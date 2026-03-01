import {
  createPrivateKey,
  createPublicKey,
  createHash,
  diffieHellman,
  sign as cryptoSign,
  verify as cryptoVerify,
  timingSafeEqual,
} from "node:crypto";
import { cpus } from "node:os";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import legacyCurve from "curve25519-js";
import { asBytes32, asBytes64, axlsign, ed25519, wasm, x25519 } from "@unknownncat/curve25519-node";

import { parseArgs, modeSummary } from "./config.js";
import { buildInputPool, copyU8, maybeCopyU8, createCycler } from "./pool.js";
import {
  createIssueManager,
  assertBytesEqual,
  assertPayloadEqual,
  assertTrue,
} from "./validators.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, "..");

const rootDistEntry = join(rootDir, "dist", "index.js");
if (!existsSync(rootDistEntry)) {
  throw new Error(
    "dist/ nao encontrado no projeto principal. Rode `npm run build` na raiz antes do benchmark."
  );
}

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const SIGN_NOTE = "sign/verify comparisons measure API throughput, not cryptographic equivalence";
const OPENMSG_NOTE =
  "legacy openMessage mutates signed input; safe-copy mode is used to avoid invalid benchmarks";
const AXL_NOTE = "axlsign comparisons are cryptographic-equivalence comparisons (same scheme)";

function debugLog(config, message) {
  if (!config.debug || config.quiet) return;
  console.log(`[debug] ${message}`);
}

function u8View(buf) {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function appendRaw32(prefix, raw32) {
  const out = Buffer.allocUnsafe(prefix.length + 32);
  out.set(prefix, 0);
  out.set(raw32, prefix.length);
  return out;
}

function derPkcs8(prefix, raw32) {
  return appendRaw32(prefix, raw32);
}

function derSpki(prefix, raw32) {
  return appendRaw32(prefix, raw32);
}

function keyFromX25519Private(raw32) {
  return createPrivateKey({
    key: derPkcs8(X25519_PKCS8_PREFIX, raw32),
    format: "der",
    type: "pkcs8",
  });
}

function keyFromX25519Public(raw32) {
  return createPublicKey({
    key: derSpki(X25519_SPKI_PREFIX, raw32),
    format: "der",
    type: "spki",
  });
}

function keyFromEd25519Private(raw32) {
  return createPrivateKey({
    key: derPkcs8(ED25519_PKCS8_PREFIX, raw32),
    format: "der",
    type: "pkcs8",
  });
}

function keyFromEd25519Public(raw32) {
  return createPublicKey({
    key: derSpki(ED25519_SPKI_PREFIX, raw32),
    format: "der",
    type: "spki",
  });
}

function rawPublicFromSpki(keyObject, prefix, label) {
  const exported = keyObject.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) {
    throw new TypeError(`${label} SPKI export must be Buffer`);
  }
  const expectedLength = prefix.length + 32;
  if (exported.byteLength !== expectedLength) {
    throw new Error(`${label} SPKI length mismatch: got ${exported.byteLength}`);
  }
  const prefixActual = exported.subarray(0, prefix.length);
  if (!timingSafeEqual(prefixActual, prefix)) {
    throw new Error(`${label} SPKI prefix mismatch`);
  }
  return asBytes32(u8View(exported).subarray(prefix.length), `${label} public key`);
}

function clampScalar(seed32) {
  const out = new Uint8Array(32);
  out.set(seed32);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return asBytes32(out, "clamped scalar");
}

function maybeGc(config) {
  if (!config.gc) return;
  if (typeof globalThis.gc === "function") {
    globalThis.gc();
  }
}

function nowNs() {
  return process.hrtime.bigint();
}

function runForDuration(task, ms, config) {
  const start = nowNs();
  const deadline = start + BigInt(Math.floor(ms * 1e6));
  let count = 0;
  let current = start;

  while (current < deadline) {
    const result = task.run();
    count += 1;

    if (config.verifyDuringBench && task.verify && count % config.verifyEvery === 0) {
      task.verify(result, count);
    }

    current = nowNs();
  }

  const elapsedSec = Number(current - start) / 1e9;
  return {
    count,
    elapsedSec,
    opsPerSec: count / elapsedSec,
  };
}

function quantile(sorted, q) {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];
  const pos = (sorted.length - 1) * q;
  const low = Math.floor(pos);
  const high = Math.ceil(pos);
  if (low === high) return sorted[low];
  const ratio = pos - low;
  return sorted[low] + (sorted[high] - sorted[low]) * ratio;
}

function summarize(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const mean = sorted.reduce((acc, v) => acc + v, 0) / n;
  const variance = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / n;
  return {
    rounds: n,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
    p50: quantile(sorted, 0.5),
    p95: quantile(sorted, 0.95),
    stdev: Math.sqrt(variance),
  };
}

function fmtOps(value) {
  return value.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

function fmtPercent(value) {
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(2)}%`;
}

function hashText(text) {
  const digest = createHash("sha256").update(text).digest();
  return digest.readUInt32LE(0);
}

function shuffleWithSeed(items, seedText) {
  const out = [...items];
  let state = hashText(seedText) || 0x9e3779b9;
  for (let i = out.length - 1; i > 0; i -= 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    const j = Math.abs(state) % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function percentDelta(current, reference) {
  if (reference === 0) return 0;
  return ((current - reference) / reference) * 100;
}

function printSuiteHeader(meta, config) {
  if (config.quiet) return;
  console.log("curve25519 benchmark suite");
  console.log(`node: ${meta.node}`);
  console.log(`openssl: ${meta.openssl}`);
  console.log(`cpu: ${meta.cpuModel} (logical cores: ${meta.logicalCores})`);
  console.log(
    `config: rounds=${config.rounds}, roundMs=${config.roundMs}, warmupMs=${config.warmupMs}, vectors=${config.vectors}, gc=${config.gc}`
  );
  console.log(
    `modes: variants=${config.variants.join(",")}, strict=${config.strict}, debug=${config.debug}, verifyDuringBench=${config.verifyDuringBench}, verifyEvery=${config.verifyEvery}`
  );
  console.log(`note: ${SIGN_NOTE}.`);
  console.log(`note: ${AXL_NOTE}.`);
}

function printPairReport(pairReport, config) {
  if (config.quiet) return;
  console.log(`\n=== ${pairReport.label} ===`);
  console.log(
    "impl".padEnd(36) +
      "mean ops/s".padStart(14) +
      "p50".padStart(12) +
      "p95".padStart(12) +
      "stdev".padStart(12) +
      "rounds".padStart(9)
  );
  console.log("-".repeat(98));

  for (const impl of pairReport.implementations) {
    const s = impl.stats;
    console.log(
      impl.name.padEnd(36) +
        fmtOps(s.mean).padStart(14) +
        fmtOps(s.p50).padStart(12) +
        fmtOps(s.p95).padStart(12) +
        fmtOps(s.stdev).padStart(12) +
        String(s.rounds).padStart(9)
    );
  }

  if (pairReport.implementations.length === 2) {
    const [a, b] = pairReport.implementations;
    const faster = a.stats.mean >= b.stats.mean ? a : b;
    const slower = faster === a ? b : a;
    const speedup = faster.stats.mean / slower.stats.mean;
    const delta = percentDelta(faster.stats.mean, slower.stats.mean);
    console.log(
      `=> ${faster.name} is ${speedup.toFixed(2)}x faster (${fmtPercent(delta)}) than ${slower.name} (mean ops/s).`
    );
  }
}

async function writeJsonOutput(output, config) {
  if (!config.json && !config.jsonFile) return;
  const json = JSON.stringify(output, null, 2);

  if (config.json) {
    console.log("\n--- JSON ---");
    console.log(json);
  }

  if (config.jsonFile) {
    const filePath = join(__dirname, config.jsonFile);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, `${json}\n`, "utf8");
    if (!config.quiet) {
      console.log(`\nJSON report written to: ${filePath}`);
    }
  }
}

function buildContext(config) {
  const pool = buildInputPool(config.vectors);
  const vectorCount = pool.vectorCount;

  const seeds32 = pool.seeds.map((seed, i) => asBytes32(seed, `seed[${i}]`));
  const modernXKeyPairs = seeds32.map((seed) => x25519.generateKeyPair(seed));
  const legacyXKeyPairs = pool.seeds.map((seed) => legacyCurve.generateKeyPair(seed));
  const modernEdKeyPairs = seeds32.map((seed) => ed25519.generateKeyPair(seed));
  const modernWasmXKeyPairs = seeds32.map((seed) => wasm.x25519.generateKeyPair(seed));
  const modernWasmEdKeyPairs = seeds32.map((seed) => wasm.ed25519.generateKeyPair(seed));
  const modernAxlKeyPairs = seeds32.map((seed) => axlsign.generateKeyPair(seed));
  const legacyAxlKeyPairs = legacyXKeyPairs;

  const modernSharedVectors = modernXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    public: modernXKeyPairs[(i + 1) % vectorCount].public,
  }));
  const legacySharedVectors = legacyXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    public: legacyXKeyPairs[(i + 1) % vectorCount].public,
  }));

  const sharedExpected = modernSharedVectors.map((v) => x25519.sharedKey(v.secret, v.public));

  const modernWasmSharedVectors = modernWasmXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    public: modernWasmXKeyPairs[(i + 1) % vectorCount].public,
  }));
  const wasmSharedExpected = modernWasmSharedVectors.map((v) => wasm.x25519.sharedKey(v.secret, v.public));

  const modernAxlSharedVectors = modernAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    public: modernAxlKeyPairs[(i + 1) % vectorCount].public,
  }));
  const legacyAxlSharedVectors = legacyAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    public: legacyAxlKeyPairs[(i + 1) % vectorCount].public,
  }));
  const axlSharedExpected = modernAxlSharedVectors.map((v) => axlsign.sharedKey(v.secret, v.public));

  const modernSign32Vectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg32[i],
    public: modernEdKeyPairs[i].public,
  }));
  const modernWasmSign32Vectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg32[i],
    public: modernWasmEdKeyPairs[i].public,
  }));
  const legacySign32Vectors = legacyXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg32[i],
    public: kp.public,
  }));

  const modernAxlSign32Vectors = modernAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg32[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));
  const legacyAxlSign32Vectors = legacyAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg32[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));

  const modernSign1024Vectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg1024[i],
    public: modernEdKeyPairs[i].public,
  }));
  const modernWasmSign1024Vectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg1024[i],
    public: modernWasmEdKeyPairs[i].public,
  }));
  const legacySign1024Vectors = legacyXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg1024[i],
    public: kp.public,
  }));

  const modernAxlSign1024Vectors = modernAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg1024[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));
  const legacyAxlSign1024Vectors = legacyAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg1024[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));

  const modernVerify32Vectors = modernSign32Vectors.map((v) => ({
    ...v,
    signature: ed25519.sign(v.seed, v.msg),
  }));
  const modernWasmVerify32Vectors = modernWasmSign32Vectors.map((v) => ({
    ...v,
    signature: wasm.ed25519.sign(v.seed, v.msg),
  }));
  const legacyVerify32Vectors = legacySign32Vectors.map((v) => ({
    ...v,
    signature: legacyCurve.sign(v.secret, v.msg),
  }));
  const modernAxlVerify32Vectors = modernAxlSign32Vectors.map((v) => ({
    ...v,
    signature: axlsign.sign(v.secret, v.msg),
    signatureRnd: axlsign.sign(v.secret, v.msg, v.rnd),
  }));
  const legacyAxlVerify32Vectors = legacyAxlSign32Vectors.map((v) => ({
    ...v,
    signature: legacyCurve.sign(v.secret, v.msg),
    signatureRnd: legacyCurve.sign(v.secret, v.msg, v.rnd),
  }));

  const modernVerify1024Vectors = modernSign1024Vectors.map((v) => ({
    ...v,
    signature: ed25519.sign(v.seed, v.msg),
  }));
  const modernWasmVerify1024Vectors = modernWasmSign1024Vectors.map((v) => ({
    ...v,
    signature: wasm.ed25519.sign(v.seed, v.msg),
  }));
  const legacyVerify1024Vectors = legacySign1024Vectors.map((v) => ({
    ...v,
    signature: legacyCurve.sign(v.secret, v.msg),
  }));
  const modernAxlVerify1024Vectors = modernAxlSign1024Vectors.map((v) => ({
    ...v,
    signature: axlsign.sign(v.secret, v.msg),
  }));
  const legacyAxlVerify1024Vectors = legacyAxlSign1024Vectors.map((v) => ({
    ...v,
    signature: legacyCurve.sign(v.secret, v.msg),
  }));

  const modernSignMessageVectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg256[i],
    public: modernEdKeyPairs[i].public,
  }));
  const modernWasmSignMessageVectors = seeds32.map((seed, i) => ({
    index: i,
    seed,
    msg: pool.msg256[i],
    public: modernWasmEdKeyPairs[i].public,
  }));
  const legacySignMessageVectors = legacyXKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg256[i],
    public: kp.public,
  }));
  const modernAxlSignMessageVectors = modernAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg256[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));
  const legacyAxlSignMessageVectors = legacyAxlKeyPairs.map((kp, i) => ({
    index: i,
    secret: kp.private,
    msg: pool.msg256[i],
    public: kp.public,
    rnd: pool.rnd64[i],
  }));

  const modernOpenMessageVectors = modernSignMessageVectors.map((v) => ({
    ...v,
    signed: ed25519.signMessage(v.seed, v.msg),
  }));
  const modernWasmOpenMessageVectors = modernWasmSignMessageVectors.map((v) => ({
    ...v,
    signed: wasm.ed25519.signMessage(v.seed, v.msg),
  }));
  const legacyOpenMessageVectors = legacySignMessageVectors.map((v) => ({
    ...v,
    signed: legacyCurve.signMessage(v.secret, v.msg),
  }));
  const modernAxlOpenMessageVectors = modernAxlSignMessageVectors.map((v) => ({
    ...v,
    signed: axlsign.signMessage(v.secret, v.msg),
    signedRnd: axlsign.signMessage(v.secret, v.msg, v.rnd),
  }));
  const legacyAxlOpenMessageVectors = legacyAxlSignMessageVectors.map((v) => ({
    ...v,
    signed: legacyCurve.signMessage(v.secret, v.msg),
    signedRnd: legacyCurve.signMessage(v.secret, v.msg, v.rnd),
  }));

  const cached = {
    x25519: {
      privateKeys: modernXKeyPairs.map((kp) => keyFromX25519Private(kp.private)),
      publicKeys: modernXKeyPairs.map((kp) => keyFromX25519Public(kp.public)),
    },
    ed25519: {
      privateKeys: seeds32.map((seed) => keyFromEd25519Private(seed)),
      publicKeys: modernEdKeyPairs.map((kp) => keyFromEd25519Public(kp.public)),
    },
    wasm: {
      x25519: {
        privateKeys: modernWasmXKeyPairs.map((kp) => wasm.x25519.createPrivateKeyObject(kp.private)),
        publicKeys: modernWasmXKeyPairs.map((kp) => wasm.x25519.createPublicKeyObject(kp.public)),
      },
      ed25519: {
        privateKeys: seeds32.map((seed) => wasm.ed25519.createPrivateKeyObject(seed)),
        publicKeys: modernWasmEdKeyPairs.map((kp) => wasm.ed25519.createPublicKeyObject(kp.public)),
      },
    },
  };

  return {
    vectorCount,
    pool,
    seeds32,
    modernXKeyPairs,
    legacyXKeyPairs,
    modernEdKeyPairs,
    modernWasmXKeyPairs,
    modernWasmEdKeyPairs,
    modernAxlKeyPairs,
    legacyAxlKeyPairs,
    modernSharedVectors,
    legacySharedVectors,
    sharedExpected,
    modernWasmSharedVectors,
    wasmSharedExpected,
    modernAxlSharedVectors,
    legacyAxlSharedVectors,
    axlSharedExpected,
    modernSign32Vectors,
    modernWasmSign32Vectors,
    legacySign32Vectors,
    modernAxlSign32Vectors,
    legacyAxlSign32Vectors,
    modernSign1024Vectors,
    modernWasmSign1024Vectors,
    legacySign1024Vectors,
    modernAxlSign1024Vectors,
    legacyAxlSign1024Vectors,
    modernVerify32Vectors,
    modernWasmVerify32Vectors,
    legacyVerify32Vectors,
    modernAxlVerify32Vectors,
    legacyAxlVerify32Vectors,
    modernVerify1024Vectors,
    modernWasmVerify1024Vectors,
    legacyVerify1024Vectors,
    modernAxlVerify1024Vectors,
    legacyAxlVerify1024Vectors,
    modernSignMessageVectors,
    modernWasmSignMessageVectors,
    legacySignMessageVectors,
    modernAxlSignMessageVectors,
    legacyAxlSignMessageVectors,
    modernOpenMessageVectors,
    modernWasmOpenMessageVectors,
    legacyOpenMessageVectors,
    modernAxlOpenMessageVectors,
    legacyAxlOpenMessageVectors,
    cached,
  };
}

function runPreflightValidation(context, issues, config) {
  debugLog(config, "running preflight correctness validation");
  const count = context.vectorCount;

  for (let i = 0; i < count; i += 1) {
    const modernX = context.modernXKeyPairs[i];
    const modernWasmX = context.modernWasmXKeyPairs[i];
    const legacyX = context.legacyXKeyPairs[i];
    const peerIndex = (i + 1) % count;

    const clamped = clampScalar(context.seeds32[i]);
    const modernPublicFromSecret = x25519.publicKey(clamped);
    assertBytesEqual(
      `x25519 publicKey modern vs legacy [${i}]`,
      modernPublicFromSecret,
      legacyX.public,
      issues
    );

    assertBytesEqual(
      `x25519 generateKeyPair public modern vs legacy [${i}]`,
      modernX.public,
      legacyX.public,
      issues
    );

    const modernShared = x25519.sharedKey(modernX.private, context.modernXKeyPairs[peerIndex].public);
    const legacyShared = legacyCurve.sharedKey(legacyX.private, context.legacyXKeyPairs[peerIndex].public);
    assertBytesEqual(`x25519 sharedKey modern vs legacy [${i}]`, modernShared, legacyShared, issues);

    assertBytesEqual(
      `wasm x25519 generateKeyPair public vs legacy [${i}]`,
      modernWasmX.public,
      legacyX.public,
      issues
    );
    assertBytesEqual(
      `wasm x25519 generateKeyPair private vs legacy [${i}]`,
      modernWasmX.private,
      legacyX.private,
      issues
    );

    const wasmPublicFromSecret = wasm.x25519.publicKey(clamped);
    assertBytesEqual(
      `wasm x25519 publicKey vs legacy [${i}]`,
      wasmPublicFromSecret,
      legacyX.public,
      issues
    );

    const wasmPrivateKeyObject = wasm.x25519.createPrivateKeyObject(modernWasmX.private);
    const wasmPeerPublicKeyObject = wasm.x25519.createPublicKeyObject(
      context.modernWasmXKeyPairs[peerIndex].public
    );
    const wasmPublicFromPrivateObject = wasm.x25519.publicKeyFromPrivateKeyObject(wasmPrivateKeyObject);
    assertBytesEqual(
      `wasm x25519 publicKeyFromPrivateKeyObject vs legacy [${i}]`,
      wasmPublicFromPrivateObject,
      legacyX.public,
      issues
    );

    const wasmShared = wasm.x25519.sharedKey(
      modernWasmX.private,
      context.modernWasmXKeyPairs[peerIndex].public
    );
    assertBytesEqual(`wasm x25519 sharedKey vs legacy [${i}]`, wasmShared, legacyShared, issues);

    const wasmSharedFromObjects = wasm.x25519.sharedKeyFromKeyObjects(
      wasmPrivateKeyObject,
      wasmPeerPublicKeyObject
    );
    assertBytesEqual(
      `wasm x25519 sharedKeyFromKeyObjects vs legacy [${i}]`,
      wasmSharedFromObjects,
      legacyShared,
      issues
    );

    const wasmSharedStrict = wasm.x25519.sharedKeyStrictFromKeyObjects(
      wasmPrivateKeyObject,
      wasmPeerPublicKeyObject
    );
    assertBytesEqual(
      `wasm x25519 sharedKeyStrictFromKeyObjects vs legacy [${i}]`,
      wasmSharedStrict,
      legacyShared,
      issues
    );
    assertTrue(`wasm x25519 isAllZero32(shared) [${i}]`, !wasm.x25519.isAllZero32(wasmShared), issues);
  }

  for (let i = 0; i < count; i += 1) {
    const modernAxl = context.modernAxlKeyPairs[i];
    const legacyAxl = context.legacyAxlKeyPairs[i];
    const peerIndex = (i + 1) % count;

    assertBytesEqual(`axlsign publicKey modern vs legacy [${i}]`, modernAxl.public, legacyAxl.public, issues);
    assertBytesEqual(`axlsign private modern vs legacy [${i}]`, modernAxl.private, legacyAxl.private, issues);

    const modernPublicFromSecret = axlsign.publicKey(modernAxl.private);
    assertBytesEqual(
      `axlsign publicKey(secret) modern vs legacy [${i}]`,
      modernPublicFromSecret,
      legacyAxl.public,
      issues
    );

    const modernShared = axlsign.sharedKey(modernAxl.private, context.modernAxlKeyPairs[peerIndex].public);
    const legacyShared = legacyCurve.sharedKey(legacyAxl.private, context.legacyAxlKeyPairs[peerIndex].public);
    assertBytesEqual(`axlsign sharedKey modern vs legacy [${i}]`, modernShared, legacyShared, issues);

    const modernVerify32 = context.modernAxlVerify32Vectors[i];
    const legacyVerify32 = context.legacyAxlVerify32Vectors[i];
    const modernVerify1024 = context.modernAxlVerify1024Vectors[i];
    const legacyVerify1024 = context.legacyAxlVerify1024Vectors[i];

    assertBytesEqual(
      `axlsign sign(msg32) modern vs legacy [${i}]`,
      modernVerify32.signature,
      legacyVerify32.signature,
      issues
    );
    assertBytesEqual(
      `axlsign sign(msg32,opt_random) modern vs legacy [${i}]`,
      modernVerify32.signatureRnd,
      legacyVerify32.signatureRnd,
      issues
    );
    assertBytesEqual(
      `axlsign sign(msg1024) modern vs legacy [${i}]`,
      modernVerify1024.signature,
      legacyVerify1024.signature,
      issues
    );

    assertTrue(
      `axlsign verify(sign(msg32)) modern [${i}]`,
      axlsign.verify(modernVerify32.public, modernVerify32.msg, modernVerify32.signature),
      issues
    );
    assertTrue(
      `axlsign verify(sign(msg32,opt_random)) modern [${i}]`,
      axlsign.verify(modernVerify32.public, modernVerify32.msg, modernVerify32.signatureRnd),
      issues
    );
    assertTrue(
      `axlsign verify(sign(msg32)) legacy [${i}]`,
      legacyCurve.verify(legacyVerify32.public, legacyVerify32.msg, legacyVerify32.signature),
      issues
    );
    assertTrue(
      `axlsign verify(sign(msg32,opt_random)) legacy [${i}]`,
      legacyCurve.verify(legacyVerify32.public, legacyVerify32.msg, legacyVerify32.signatureRnd),
      issues
    );
  }

  for (let i = 0; i < count; i += 1) {
    const modern32 = context.modernVerify32Vectors[i];
    const wasm32 = context.modernWasmVerify32Vectors[i];
    const legacy32 = context.legacyVerify32Vectors[i];
    const modern1024 = context.modernVerify1024Vectors[i];
    const wasm1024 = context.modernWasmVerify1024Vectors[i];
    const legacy1024 = context.legacyVerify1024Vectors[i];

    assertTrue(
      `ed25519 verify(sign(msg32)) [${i}]`,
      ed25519.verify(modern32.public, modern32.msg, modern32.signature),
      issues
    );
    assertTrue(
      `legacy verify(sign(msg32)) [${i}]`,
      legacyCurve.verify(legacy32.public, legacy32.msg, legacy32.signature),
      issues
    );

    assertTrue(
      `ed25519 verify(sign(msg1024)) [${i}]`,
      ed25519.verify(modern1024.public, modern1024.msg, modern1024.signature),
      issues
    );
    assertTrue(
      `wasm ed25519 verify(sign(msg32)) [${i}]`,
      wasm.ed25519.verify(wasm32.public, wasm32.msg, wasm32.signature),
      issues
    );
    const wasmPrivateKeyObject = wasm.ed25519.createPrivateKeyObject(wasm32.seed);
    const wasmPublicKeyObject = wasm.ed25519.createPublicKeyObject(wasm32.public);
    const wasmPublicFromPrivateObject = wasm.ed25519.publicKeyFromPrivateKeyObject(wasmPrivateKeyObject);
    assertBytesEqual(
      `wasm ed25519 publicKeyFromPrivateKeyObject [${i}]`,
      wasmPublicFromPrivateObject,
      wasm32.public,
      issues
    );
    const wasmSignatureFromPrivateObject = wasm.ed25519.signWithPrivateKey(
      wasmPrivateKeyObject,
      wasm32.msg
    );
    assertBytesEqual(
      `wasm ed25519 signWithPrivateKey deterministic [${i}]`,
      wasmSignatureFromPrivateObject,
      wasm32.signature,
      issues
    );
    assertTrue(
      `wasm ed25519 verifyWithPublicKey(sign(msg32)) [${i}]`,
      wasm.ed25519.verifyWithPublicKey(wasmPublicKeyObject, wasm32.msg, wasm32.signature),
      issues
    );
    assertTrue(
      `wasm ed25519 verify(sign(msg1024)) [${i}]`,
      wasm.ed25519.verify(wasm1024.public, wasm1024.msg, wasm1024.signature),
      issues
    );
    assertTrue(
      `legacy verify(sign(msg1024)) [${i}]`,
      legacyCurve.verify(legacy1024.public, legacy1024.msg, legacy1024.signature),
      issues
    );

    const modernSigned = context.modernOpenMessageVectors[i];
    const legacySigned = context.legacyOpenMessageVectors[i];

    const modernOpened = ed25519.openMessage(modernSigned.public, modernSigned.signed);
    assertPayloadEqual(`ed25519 signMessage/openMessage [${i}]`, modernOpened, modernSigned.msg, issues);

    const wasmSigned = context.modernWasmOpenMessageVectors[i];
    const wasmOpened = wasm.ed25519.openMessage(wasmSigned.public, wasmSigned.signed);
    assertPayloadEqual(`wasm ed25519 signMessage/openMessage [${i}]`, wasmOpened, wasmSigned.msg, issues);

    const legacyOpened = legacyCurve.openMessage(legacySigned.public, copyU8(legacySigned.signed));
    assertPayloadEqual(`legacy signMessage/openMessage [${i}]`, legacyOpened, legacySigned.msg, issues);

    const modernAxlSigned = context.modernAxlOpenMessageVectors[i];
    const legacyAxlSigned = context.legacyAxlOpenMessageVectors[i];

    assertBytesEqual(
      `axlsign signMessage(msg256) modern vs legacy [${i}]`,
      modernAxlSigned.signed,
      legacyAxlSigned.signed,
      issues
    );
    assertBytesEqual(
      `axlsign signMessage(msg256,opt_random) modern vs legacy [${i}]`,
      modernAxlSigned.signedRnd,
      legacyAxlSigned.signedRnd,
      issues
    );

    const modernAxlOpened = axlsign.openMessage(modernAxlSigned.public, modernAxlSigned.signed);
    assertPayloadEqual(`axlsign signMessage/openMessage [${i}]`, modernAxlOpened, modernAxlSigned.msg, issues);

    const modernAxlOpenedRnd = axlsign.openMessage(modernAxlSigned.public, modernAxlSigned.signedRnd);
    assertPayloadEqual(
      `axlsign signMessage/openMessage opt_random [${i}]`,
      modernAxlOpenedRnd,
      modernAxlSigned.msg,
      issues
    );

    const legacyAxlOpened = legacyCurve.openMessage(legacyAxlSigned.public, copyU8(legacyAxlSigned.signed));
    assertPayloadEqual(`legacy axlsign signMessage/openMessage [${i}]`, legacyAxlOpened, legacyAxlSigned.msg, issues);

    const legacyAxlOpenedRnd = legacyCurve.openMessage(
      legacyAxlSigned.public,
      copyU8(legacyAxlSigned.signedRnd)
    );
    assertPayloadEqual(
      `legacy axlsign signMessage/openMessage opt_random [${i}]`,
      legacyAxlOpenedRnd,
      legacyAxlSigned.msg,
      issues
    );
  }
}

function makeSafeOpenInput(variant, signed, forceCopyForSafety) {
  if (forceCopyForSafety) return copyU8(signed);
  if (variant === "copy") return copyU8(signed);
  if (variant === "nocopy") return signed;
  return copyU8(signed);
}

function buildModernTasksForVariant(context, variant, issues, config) {
  const n = context.vectorCount;

  const nextSeed = createCycler(context.seeds32);
  const nextShared = createCycler(context.modernSharedVectors);
  const nextSign32 = createCycler(context.modernSign32Vectors);
  const nextSign1024 = createCycler(context.modernSign1024Vectors);
  const nextVerify32 = createCycler(context.modernVerify32Vectors);
  const nextVerify1024 = createCycler(context.modernVerify1024Vectors);
  const nextSignMessage = createCycler(context.modernSignMessageVectors);
  const nextOpenMessage = createCycler(context.modernOpenMessageVectors);

  const makeModernSign = (vector, msg) => {
    if (variant === "cached") {
      const signature = cryptoSign(
        null,
        variant === "copy" ? copyU8(msg) : msg,
        context.cached.ed25519.privateKeys[vector.index]
      );
      return asBytes64(u8View(signature), "modern signature");
    }

    const seedInput = variant === "copy" ? asBytes32(copyU8(vector.seed), "seed copy") : vector.seed;
    const msgInput = maybeCopyU8(msg, variant === "copy");
    return ed25519.sign(seedInput, msgInput);
  };

  const makeModernVerify = (vector) => {
    const msgInput = maybeCopyU8(vector.msg, variant === "copy");
    const signatureInput = variant === "copy" ? asBytes64(copyU8(vector.signature), "signature copy") : vector.signature;
    const publicInput = variant === "copy" ? asBytes32(copyU8(vector.public), "public key copy") : vector.public;

    if (variant === "cached") {
      return cryptoVerify(
        null,
        msgInput,
        context.cached.ed25519.publicKeys[vector.index],
        signatureInput
      );
    }

    return ed25519.verify(publicInput, msgInput, signatureInput);
  };

  return {
    generateKeyPair: (() => {
      let last = null;
      return {
        name: "modern x25519.generateKeyPair",
        run: () => {
          const selected = nextSeed();
          last = selected;
          const seed = selected.value;
          if (variant === "cached") {
            const privateRaw = context.modernXKeyPairs[selected.index].private;
            const pub = rawPublicFromSpki(
              createPublicKey(context.cached.x25519.privateKeys[selected.index]),
              X25519_SPKI_PREFIX,
              "X25519"
            );
            return { public: pub, private: privateRaw };
          }
          const seedInput = variant === "copy" ? asBytes32(copyU8(seed), "seed copy") : seed;
          return x25519.generateKeyPair(seedInput);
        },
        verify: (result) => {
          const expected = context.modernXKeyPairs[last.index];
          assertBytesEqual("modern generateKeyPair public", result.public, expected.public, issues);
          assertBytesEqual("modern generateKeyPair private", result.private, expected.private, issues);
        },
        samples: [],
      };
    })(),
    sharedKey: (() => {
      let last = null;
      return {
        name: "modern x25519.sharedKey",
        run: () => {
          const selected = nextShared();
          last = selected;
          const input = selected.value;
          if (variant === "cached") {
            const shared = diffieHellman({
              privateKey: context.cached.x25519.privateKeys[input.index],
              publicKey: context.cached.x25519.publicKeys[(input.index + 1) % n],
            });
            return asBytes32(u8View(shared), "shared key");
          }
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
          return x25519.sharedKey(secretInput, publicInput);
        },
        verify: (result) => {
          const expected = context.sharedExpected[last.index];
          assertBytesEqual("modern sharedKey", result, expected, issues);
        },
        samples: [],
      };
    })(),
    sign32: (() => {
      let last = null;
      return {
        name: "modern ed25519.sign",
        run: () => {
          const selected = nextSign32();
          last = selected;
          return makeModernSign(selected.value, selected.value.msg);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern sign(msg32) verifies",
            ed25519.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign1024: (() => {
      let last = null;
      return {
        name: "modern ed25519.sign",
        run: () => {
          const selected = nextSign1024();
          last = selected;
          return makeModernSign(selected.value, selected.value.msg);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern sign(msg1024) verifies",
            ed25519.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    verify32: {
      name: "modern ed25519.verify",
      run: () => makeModernVerify(nextVerify32().value),
      verify: (ok) => {
        assertTrue("modern verify(msg32)", ok, issues);
      },
      samples: [],
    },
    verify1024: {
      name: "modern ed25519.verify",
      run: () => makeModernVerify(nextVerify1024().value),
      verify: (ok) => {
        assertTrue("modern verify(msg1024)", ok, issues);
      },
      samples: [],
    },
    signMessage: (() => {
      let last = null;
      return {
        name: "modern ed25519.signMessage",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const v = selected.value;

          if (variant === "cached") {
            const signature = cryptoSign(
              null,
              variant === "copy" ? copyU8(v.msg) : v.msg,
              context.cached.ed25519.privateKeys[v.index]
            );
            const out = new Uint8Array(64 + v.msg.byteLength);
            out.set(signature, 0);
            out.set(v.msg, 64);
            return out;
          }

          const seedInput = variant === "copy" ? asBytes32(copyU8(v.seed), "seed copy") : v.seed;
          const msgInput = maybeCopyU8(v.msg, variant === "copy");
          return ed25519.signMessage(seedInput, msgInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = ed25519.openMessage(input.public, signed);
          assertPayloadEqual("modern signMessage/openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessage: (() => {
      let last = null;
      return {
        name: "modern ed25519.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const signedInput = makeSafeOpenInput(variant, input.signed, variant !== "nocopy");

          if (variant === "cached") {
            const signature = asBytes64(signedInput.subarray(0, 64), "signature");
            const msg = signedInput.subarray(64);
            const verified = cryptoVerify(
              null,
              msg,
              context.cached.ed25519.publicKeys[input.index],
              signature
            );
            if (!verified) return null;
            return new Uint8Array(msg);
          }

          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public key copy") : input.public;
          return ed25519.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("modern openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
  };
}

function buildModernWasmTasksForVariant(context, variant, issues) {
  const n = context.vectorCount;

  const nextSeed = createCycler(context.seeds32);
  const nextShared = createCycler(context.modernWasmSharedVectors);
  const nextSign32 = createCycler(context.modernWasmSign32Vectors);
  const nextSign1024 = createCycler(context.modernWasmSign1024Vectors);
  const nextVerify32 = createCycler(context.modernWasmVerify32Vectors);
  const nextVerify1024 = createCycler(context.modernWasmVerify1024Vectors);
  const nextSignMessage = createCycler(context.modernWasmSignMessageVectors);
  const nextOpenMessage = createCycler(context.modernWasmOpenMessageVectors);

  const makeWasmSign = (vector, msg) => {
    if (variant === "cached") {
      const msgInput = variant === "copy" ? copyU8(msg) : msg;
      return wasm.ed25519.signWithPrivateKey(
        context.cached.wasm.ed25519.privateKeys[vector.index],
        msgInput
      );
    }

    const seedInput = variant === "copy" ? asBytes32(copyU8(vector.seed), "seed copy") : vector.seed;
    const msgInput = maybeCopyU8(msg, variant === "copy");
    return wasm.ed25519.sign(seedInput, msgInput);
  };

  const makeWasmVerify = (vector) => {
    const msgInput = maybeCopyU8(vector.msg, variant === "copy");
    const signatureInput = variant === "copy" ? asBytes64(copyU8(vector.signature), "signature copy") : vector.signature;

    if (variant === "cached") {
      return wasm.ed25519.verifyWithPublicKey(
        context.cached.wasm.ed25519.publicKeys[vector.index],
        msgInput,
        signatureInput
      );
    }

    const publicInput = variant === "copy" ? asBytes32(copyU8(vector.public), "public key copy") : vector.public;
    return wasm.ed25519.verify(publicInput, msgInput, signatureInput);
  };

  return {
    generateKeyPair: (() => {
      let last = null;
      return {
        name: "modern wasm.x25519.generateKeyPair",
        run: () => {
          const selected = nextSeed();
          last = selected;
          const seed = selected.value;
          if (variant === "cached") {
            const privateObject = context.cached.wasm.x25519.privateKeys[selected.index];
            return {
              public: wasm.x25519.publicKeyFromPrivateKeyObject(privateObject),
              private: privateObject.bytes,
            };
          }
          const seedInput = variant === "copy" ? asBytes32(copyU8(seed), "seed copy") : seed;
          return wasm.x25519.generateKeyPair(seedInput);
        },
        verify: (result) => {
          const expected = context.modernWasmXKeyPairs[last.index];
          assertBytesEqual("modern wasm generateKeyPair public", result.public, expected.public, issues);
          assertBytesEqual("modern wasm generateKeyPair private", result.private, expected.private, issues);
        },
        samples: [],
      };
    })(),
    sharedKey: (() => {
      let last = null;
      return {
        name: "modern wasm.x25519.sharedKey",
        run: () => {
          const selected = nextShared();
          last = selected;
          const input = selected.value;
          if (variant === "cached") {
            return wasm.x25519.sharedKeyFromKeyObjects(
              context.cached.wasm.x25519.privateKeys[input.index],
              context.cached.wasm.x25519.publicKeys[(input.index + 1) % n]
            );
          }
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
          return wasm.x25519.sharedKey(secretInput, publicInput);
        },
        verify: (result) => {
          const expected = context.wasmSharedExpected[last.index];
          assertBytesEqual("modern wasm sharedKey", result, expected, issues);
        },
        samples: [],
      };
    })(),
    sign32: (() => {
      let last = null;
      return {
        name: "modern wasm.ed25519.sign",
        run: () => {
          const selected = nextSign32();
          last = selected;
          return makeWasmSign(selected.value, selected.value.msg);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern wasm sign(msg32) verifies",
            wasm.ed25519.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign1024: (() => {
      let last = null;
      return {
        name: "modern wasm.ed25519.sign",
        run: () => {
          const selected = nextSign1024();
          last = selected;
          return makeWasmSign(selected.value, selected.value.msg);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern wasm sign(msg1024) verifies",
            wasm.ed25519.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    verify32: {
      name: "modern wasm.ed25519.verify",
      run: () => makeWasmVerify(nextVerify32().value),
      verify: (ok) => {
        assertTrue("modern wasm verify(msg32)", ok, issues);
      },
      samples: [],
    },
    verify1024: {
      name: "modern wasm.ed25519.verify",
      run: () => makeWasmVerify(nextVerify1024().value),
      verify: (ok) => {
        assertTrue("modern wasm verify(msg1024)", ok, issues);
      },
      samples: [],
    },
    signMessage: (() => {
      let last = null;
      return {
        name: "modern wasm.ed25519.signMessage",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const v = selected.value;

          if (variant === "cached") {
            const msgInput = variant === "copy" ? copyU8(v.msg) : v.msg;
            const signature = wasm.ed25519.signWithPrivateKey(
              context.cached.wasm.ed25519.privateKeys[v.index],
              msgInput
            );
            const out = new Uint8Array(64 + msgInput.byteLength);
            out.set(signature, 0);
            out.set(msgInput, 64);
            return out;
          }

          const seedInput = variant === "copy" ? asBytes32(copyU8(v.seed), "seed copy") : v.seed;
          const msgInput = maybeCopyU8(v.msg, variant === "copy");
          return wasm.ed25519.signMessage(seedInput, msgInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = wasm.ed25519.openMessage(input.public, signed);
          assertPayloadEqual("modern wasm signMessage/openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessage: (() => {
      let last = null;
      return {
        name: "modern wasm.ed25519.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const signedInput = makeSafeOpenInput(variant, input.signed, variant !== "nocopy");

          if (variant === "cached") {
            const signature = asBytes64(signedInput.subarray(0, 64), "signature");
            const msg = signedInput.subarray(64);
            const ok = wasm.ed25519.verifyWithPublicKey(
              context.cached.wasm.ed25519.publicKeys[input.index],
              msg,
              signature
            );
            if (!ok) return null;
            return new Uint8Array(msg);
          }

          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public key copy") : input.public;
          return wasm.ed25519.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("modern wasm openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
  };
}

function buildLegacyTasksForVariant(context, variant, issues) {
  const nextSeed = createCycler(context.pool.seeds);
  const nextShared = createCycler(context.legacySharedVectors);
  const nextSign32 = createCycler(context.legacySign32Vectors);
  const nextSign1024 = createCycler(context.legacySign1024Vectors);
  const nextVerify32 = createCycler(context.legacyVerify32Vectors);
  const nextVerify1024 = createCycler(context.legacyVerify1024Vectors);
  const nextSignMessage = createCycler(context.legacySignMessageVectors);
  const nextOpenMessage = createCycler(context.legacyOpenMessageVectors);

  return {
    generateKeyPair: (() => {
      let last = null;
      return {
        name: "legacy curve.generateKeyPair",
        run: () => {
          const selected = nextSeed();
          last = selected;
          const seedInput = maybeCopyU8(selected.value, variant === "copy");
          return legacyCurve.generateKeyPair(seedInput);
        },
        verify: (result) => {
          const expected = context.legacyXKeyPairs[last.index];
          assertBytesEqual("legacy generateKeyPair public", result.public, expected.public, issues);
          assertBytesEqual("legacy generateKeyPair private", result.private, expected.private, issues);
        },
        samples: [],
      };
    })(),
    sharedKey: (() => {
      let last = null;
      return {
        name: "legacy curve.sharedKey",
        run: () => {
          const selected = nextShared();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const publicInput = maybeCopyU8(input.public, variant === "copy");
          return legacyCurve.sharedKey(secretInput, publicInput);
        },
        verify: (result) => {
          const expected = context.sharedExpected[last.index];
          assertBytesEqual("legacy sharedKey", result, expected, issues);
        },
        samples: [],
      };
    })(),
    sign32: (() => {
      let last = null;
      return {
        name: "legacy curve.sign",
        run: () => {
          const selected = nextSign32();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "legacy sign(msg32) verifies",
            legacyCurve.verify(input.public, input.msg, signature),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign1024: (() => {
      let last = null;
      return {
        name: "legacy curve.sign",
        run: () => {
          const selected = nextSign1024();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "legacy sign(msg1024) verifies",
            legacyCurve.verify(input.public, input.msg, signature),
            issues
          );
        },
        samples: [],
      };
    })(),
    verify32: {
      name: "legacy curve.verify",
      run: () => {
        const input = nextVerify32().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = maybeCopyU8(input.signature, variant === "copy");
        const publicInput = maybeCopyU8(input.public, variant === "copy");
        return legacyCurve.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("legacy verify(msg32)", ok, issues);
      },
      samples: [],
    },
    verify1024: {
      name: "legacy curve.verify",
      run: () => {
        const input = nextVerify1024().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = maybeCopyU8(input.signature, variant === "copy");
        const publicInput = maybeCopyU8(input.public, variant === "copy");
        return legacyCurve.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("legacy verify(msg1024)", ok, issues);
      },
      samples: [],
    },
    signMessage: (() => {
      let last = null;
      return {
        name: "legacy curve.signMessage",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.signMessage(secretInput, msgInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = legacyCurve.openMessage(input.public, copyU8(signed));
          assertPayloadEqual("legacy signMessage/openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessage: (() => {
      let last = null;
      return {
        name: "legacy curve.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const publicInput = maybeCopyU8(input.public, variant === "copy");
          const signedInput = copyU8(input.signed);
          return legacyCurve.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("legacy openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
  };
}

function buildModernAxlTasksForVariant(context, variant, issues) {
  const nextSeed = createCycler(context.seeds32);
  const nextShared = createCycler(context.modernAxlSharedVectors);
  const nextSign32 = createCycler(context.modernAxlSign32Vectors);
  const nextSign1024 = createCycler(context.modernAxlSign1024Vectors);
  const nextVerify32 = createCycler(context.modernAxlVerify32Vectors);
  const nextVerify1024 = createCycler(context.modernAxlVerify1024Vectors);
  const nextSignMessage = createCycler(context.modernAxlSignMessageVectors);
  const nextOpenMessage = createCycler(context.modernAxlOpenMessageVectors);

  return {
    generateKeyPair: (() => {
      let last = null;
      return {
        name: "modern axlsign.generateKeyPair",
        run: () => {
          const selected = nextSeed();
          last = selected;
          const seedInput = variant === "copy" ? asBytes32(copyU8(selected.value), "seed copy") : selected.value;
          return axlsign.generateKeyPair(seedInput);
        },
        verify: (result) => {
          const expected = context.modernAxlKeyPairs[last.index];
          assertBytesEqual("modern axlsign generateKeyPair public", result.public, expected.public, issues);
          assertBytesEqual("modern axlsign generateKeyPair private", result.private, expected.private, issues);
        },
        samples: [],
      };
    })(),
    sharedKey: (() => {
      let last = null;
      return {
        name: "modern axlsign.sharedKey",
        run: () => {
          const selected = nextShared();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
          return axlsign.sharedKey(secretInput, publicInput);
        },
        verify: (result) => {
          const expected = context.axlSharedExpected[last.index];
          assertBytesEqual("modern axlsign sharedKey", result, expected, issues);
        },
        samples: [],
      };
    })(),
    sign32: (() => {
      let last = null;
      return {
        name: "modern axlsign.sign",
        run: () => {
          const selected = nextSign32();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return axlsign.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern axlsign sign(msg32) verifies",
            axlsign.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign32Rnd: (() => {
      let last = null;
      return {
        name: "modern axlsign.sign(opt_random)",
        run: () => {
          const selected = nextSign32();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          const rndInput = variant === "copy" ? asBytes64(copyU8(input.rnd), "rnd copy") : asBytes64(input.rnd, "rnd");
          return axlsign.sign(secretInput, msgInput, rndInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern axlsign sign(msg32,opt_random) verifies",
            axlsign.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign1024: (() => {
      let last = null;
      return {
        name: "modern axlsign.sign",
        run: () => {
          const selected = nextSign1024();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return axlsign.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "modern axlsign sign(msg1024) verifies",
            axlsign.verify(input.public, input.msg, asBytes64(signature, "signature")),
            issues
          );
        },
        samples: [],
      };
    })(),
    verify32: {
      name: "modern axlsign.verify",
      run: () => {
        const input = nextVerify32().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = variant === "copy" ? asBytes64(copyU8(input.signature), "signature copy") : input.signature;
        const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
        return axlsign.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("modern axlsign verify(msg32)", ok, issues);
      },
      samples: [],
    },
    verify32Rnd: {
      name: "modern axlsign.verify",
      run: () => {
        const input = nextVerify32().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput =
          variant === "copy" ? asBytes64(copyU8(input.signatureRnd), "signature copy") : input.signatureRnd;
        const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
        return axlsign.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("modern axlsign verify(msg32,opt_random)", ok, issues);
      },
      samples: [],
    },
    verify1024: {
      name: "modern axlsign.verify",
      run: () => {
        const input = nextVerify1024().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = variant === "copy" ? asBytes64(copyU8(input.signature), "signature copy") : input.signature;
        const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
        return axlsign.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("modern axlsign verify(msg1024)", ok, issues);
      },
      samples: [],
    },
    signMessage: (() => {
      let last = null;
      return {
        name: "modern axlsign.signMessage",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return axlsign.signMessage(secretInput, msgInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = axlsign.openMessage(input.public, signed);
          assertPayloadEqual("modern axlsign signMessage/openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    signMessageRnd: (() => {
      let last = null;
      return {
        name: "modern axlsign.signMessage(opt_random)",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const input = selected.value;
          const secretInput = variant === "copy" ? asBytes32(copyU8(input.secret), "secret copy") : input.secret;
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          const rndInput = variant === "copy" ? asBytes64(copyU8(input.rnd), "rnd copy") : asBytes64(input.rnd, "rnd");
          return axlsign.signMessage(secretInput, msgInput, rndInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = axlsign.openMessage(input.public, signed);
          assertPayloadEqual("modern axlsign signMessage/openMessage opt_random", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessage: (() => {
      let last = null;
      return {
        name: "modern axlsign.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
          const signedInput = makeSafeOpenInput(variant, input.signed, false);
          return axlsign.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("modern axlsign openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessageRnd: (() => {
      let last = null;
      return {
        name: "modern axlsign.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const publicInput = variant === "copy" ? asBytes32(copyU8(input.public), "public copy") : input.public;
          const signedInput = makeSafeOpenInput(variant, input.signedRnd, false);
          return axlsign.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("modern axlsign openMessage opt_random", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
  };
}

function buildLegacyAxlTasksForVariant(context, variant, issues) {
  const nextSeed = createCycler(context.pool.seeds);
  const nextShared = createCycler(context.legacyAxlSharedVectors);
  const nextSign32 = createCycler(context.legacyAxlSign32Vectors);
  const nextSign1024 = createCycler(context.legacyAxlSign1024Vectors);
  const nextVerify32 = createCycler(context.legacyAxlVerify32Vectors);
  const nextVerify1024 = createCycler(context.legacyAxlVerify1024Vectors);
  const nextSignMessage = createCycler(context.legacyAxlSignMessageVectors);
  const nextOpenMessage = createCycler(context.legacyAxlOpenMessageVectors);

  return {
    generateKeyPair: (() => {
      let last = null;
      return {
        name: "legacy curve.generateKeyPair",
        run: () => {
          const selected = nextSeed();
          last = selected;
          const seedInput = maybeCopyU8(selected.value, variant === "copy");
          return legacyCurve.generateKeyPair(seedInput);
        },
        verify: (result) => {
          const expected = context.legacyAxlKeyPairs[last.index];
          assertBytesEqual("legacy axlsign generateKeyPair public", result.public, expected.public, issues);
          assertBytesEqual("legacy axlsign generateKeyPair private", result.private, expected.private, issues);
        },
        samples: [],
      };
    })(),
    sharedKey: (() => {
      let last = null;
      return {
        name: "legacy curve.sharedKey",
        run: () => {
          const selected = nextShared();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const publicInput = maybeCopyU8(input.public, variant === "copy");
          return legacyCurve.sharedKey(secretInput, publicInput);
        },
        verify: (result) => {
          const expected = context.axlSharedExpected[last.index];
          assertBytesEqual("legacy axlsign sharedKey", result, expected, issues);
        },
        samples: [],
      };
    })(),
    sign32: (() => {
      let last = null;
      return {
        name: "legacy curve.sign",
        run: () => {
          const selected = nextSign32();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue("legacy axlsign sign(msg32) verifies", legacyCurve.verify(input.public, input.msg, signature), issues);
        },
        samples: [],
      };
    })(),
    sign32Rnd: (() => {
      let last = null;
      return {
        name: "legacy curve.sign(opt_random)",
        run: () => {
          const selected = nextSign32();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          const rndInput = maybeCopyU8(input.rnd, variant === "copy");
          return legacyCurve.sign(secretInput, msgInput, rndInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "legacy axlsign sign(msg32,opt_random) verifies",
            legacyCurve.verify(input.public, input.msg, signature),
            issues
          );
        },
        samples: [],
      };
    })(),
    sign1024: (() => {
      let last = null;
      return {
        name: "legacy curve.sign",
        run: () => {
          const selected = nextSign1024();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.sign(secretInput, msgInput);
        },
        verify: (signature) => {
          const input = last.value;
          assertTrue(
            "legacy axlsign sign(msg1024) verifies",
            legacyCurve.verify(input.public, input.msg, signature),
            issues
          );
        },
        samples: [],
      };
    })(),
    verify32: {
      name: "legacy curve.verify",
      run: () => {
        const input = nextVerify32().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = maybeCopyU8(input.signature, variant === "copy");
        const publicInput = maybeCopyU8(input.public, variant === "copy");
        return legacyCurve.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("legacy axlsign verify(msg32)", ok, issues);
      },
      samples: [],
    },
    verify32Rnd: {
      name: "legacy curve.verify",
      run: () => {
        const input = nextVerify32().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = maybeCopyU8(input.signatureRnd, variant === "copy");
        const publicInput = maybeCopyU8(input.public, variant === "copy");
        return legacyCurve.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("legacy axlsign verify(msg32,opt_random)", ok, issues);
      },
      samples: [],
    },
    verify1024: {
      name: "legacy curve.verify",
      run: () => {
        const input = nextVerify1024().value;
        const msgInput = maybeCopyU8(input.msg, variant === "copy");
        const signatureInput = maybeCopyU8(input.signature, variant === "copy");
        const publicInput = maybeCopyU8(input.public, variant === "copy");
        return legacyCurve.verify(publicInput, msgInput, signatureInput);
      },
      verify: (ok) => {
        assertTrue("legacy axlsign verify(msg1024)", ok, issues);
      },
      samples: [],
    },
    signMessage: (() => {
      let last = null;
      return {
        name: "legacy curve.signMessage",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          return legacyCurve.signMessage(secretInput, msgInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = legacyCurve.openMessage(input.public, copyU8(signed));
          assertPayloadEqual("legacy axlsign signMessage/openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    signMessageRnd: (() => {
      let last = null;
      return {
        name: "legacy curve.signMessage(opt_random)",
        run: () => {
          const selected = nextSignMessage();
          last = selected;
          const input = selected.value;
          const secretInput = maybeCopyU8(input.secret, variant === "copy");
          const msgInput = maybeCopyU8(input.msg, variant === "copy");
          const rndInput = maybeCopyU8(input.rnd, variant === "copy");
          return legacyCurve.signMessage(secretInput, msgInput, rndInput);
        },
        verify: (signed) => {
          const input = last.value;
          const opened = legacyCurve.openMessage(input.public, copyU8(signed));
          assertPayloadEqual("legacy axlsign signMessage/openMessage opt_random", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessage: (() => {
      let last = null;
      return {
        name: "legacy curve.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const publicInput = maybeCopyU8(input.public, variant === "copy");
          const signedInput = copyU8(input.signed);
          return legacyCurve.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("legacy axlsign openMessage", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
    openMessageRnd: (() => {
      let last = null;
      return {
        name: "legacy curve.openMessage",
        run: () => {
          const selected = nextOpenMessage();
          last = selected;
          const input = selected.value;
          const publicInput = maybeCopyU8(input.public, variant === "copy");
          const signedInput = copyU8(input.signedRnd);
          return legacyCurve.openMessage(publicInput, signedInput);
        },
        verify: (opened) => {
          const input = last.value;
          assertPayloadEqual("legacy axlsign openMessage opt_random", opened, input.msg, issues);
        },
        samples: [],
      };
    })(),
  };
}

function buildPairDescriptors(context, variant, issues, config) {
  const modernVsLegacy = (modernKey, legacyKey = modernKey) => {
    const modern = buildModernTasksForVariant(context, variant, issues, config);
    const legacy = buildLegacyTasksForVariant(context, variant, issues);
    return [modern[modernKey], legacy[legacyKey]];
  };

  const wasmVsLegacy = (wasmKey, legacyKey = wasmKey) => {
    const modernWasm = buildModernWasmTasksForVariant(context, variant, issues);
    const legacy = buildLegacyTasksForVariant(context, variant, issues);
    return [modernWasm[wasmKey], legacy[legacyKey]];
  };

  const axlsignVsLegacy = (modernKey, legacyKey = modernKey) => {
    const modernAxl = buildModernAxlTasksForVariant(context, variant, issues);
    const legacyAxl = buildLegacyAxlTasksForVariant(context, variant, issues);
    return [modernAxl[modernKey], legacyAxl[legacyKey]];
  };

  return [
    {
      id: `x25519.generateKeyPair.${variant}`,
      label: `[${variant}] X25519 generateKeyPair(seed32)`,
      tasks: modernVsLegacy("generateKeyPair"),
    },
    {
      id: `x25519.sharedKey.${variant}`,
      label: `[${variant}] X25519 sharedKey(sk, pk)`,
      tasks: modernVsLegacy("sharedKey"),
    },
    {
      id: `wasm.x25519.generateKeyPair.${variant}`,
      label: `[${variant}] WASM X25519 generateKeyPair(seed32)`,
      tasks: wasmVsLegacy("generateKeyPair"),
    },
    {
      id: `wasm.x25519.sharedKey.${variant}`,
      label: `[${variant}] WASM X25519 sharedKey(sk, pk)`,
      tasks: wasmVsLegacy("sharedKey"),
    },
    {
      id: `axlsign.generateKeyPair.${variant}`,
      label: `[${variant}] axlsign generateKeyPair(seed32)`,
      tasks: axlsignVsLegacy("generateKeyPair"),
    },
    {
      id: `axlsign.sharedKey.${variant}`,
      label: `[${variant}] axlsign sharedKey(sk, pk)`,
      tasks: axlsignVsLegacy("sharedKey"),
    },
    {
      id: `axlsign.sign.32.${variant}`,
      label: `[${variant}] axlsign sign(msg32) [equivalent schemes]`,
      tasks: axlsignVsLegacy("sign32"),
    },
    {
      id: `axlsign.sign.32.rnd.${variant}`,
      label: `[${variant}] axlsign sign(msg32,opt_random) [equivalent schemes]`,
      tasks: axlsignVsLegacy("sign32Rnd"),
    },
    {
      id: `axlsign.sign.1024.${variant}`,
      label: `[${variant}] axlsign sign(msg1024) [equivalent schemes]`,
      tasks: axlsignVsLegacy("sign1024"),
    },
    {
      id: `axlsign.verify.32.${variant}`,
      label: `[${variant}] axlsign verify(msg32) [equivalent schemes]`,
      tasks: axlsignVsLegacy("verify32"),
    },
    {
      id: `axlsign.verify.32.rnd.${variant}`,
      label: `[${variant}] axlsign verify(msg32,opt_random) [equivalent schemes]`,
      tasks: axlsignVsLegacy("verify32Rnd"),
    },
    {
      id: `axlsign.verify.1024.${variant}`,
      label: `[${variant}] axlsign verify(msg1024) [equivalent schemes]`,
      tasks: axlsignVsLegacy("verify1024"),
    },
    {
      id: `axlsign.signMessage.256.${variant}`,
      label: `[${variant}] axlsign signMessage(msg256) [equivalent schemes]`,
      tasks: axlsignVsLegacy("signMessage"),
    },
    {
      id: `axlsign.signMessage.256.rnd.${variant}`,
      label: `[${variant}] axlsign signMessage(msg256,opt_random) [equivalent schemes]`,
      tasks: axlsignVsLegacy("signMessageRnd"),
    },
    {
      id: `axlsign.openMessage.256.${variant}`,
      label: `[${variant}] axlsign openMessage(msg256) [equivalent schemes]`,
      tasks: axlsignVsLegacy("openMessage"),
    },
    {
      id: `axlsign.openMessage.256.rnd.${variant}`,
      label: `[${variant}] axlsign openMessage(msg256,opt_random) [equivalent schemes]`,
      tasks: axlsignVsLegacy("openMessageRnd"),
    },
    {
      id: `sign.32.${variant}`,
      label: `[${variant}] Signature sign(msg32) [different schemes]`,
      tasks: modernVsLegacy("sign32"),
    },
    {
      id: `wasm.sign.32.${variant}`,
      label: `[${variant}] WASM Signature sign(msg32) [different schemes]`,
      tasks: wasmVsLegacy("sign32"),
    },
    {
      id: `sign.1024.${variant}`,
      label: `[${variant}] Signature sign(msg1024) [different schemes]`,
      tasks: modernVsLegacy("sign1024"),
    },
    {
      id: `wasm.sign.1024.${variant}`,
      label: `[${variant}] WASM Signature sign(msg1024) [different schemes]`,
      tasks: wasmVsLegacy("sign1024"),
    },
    {
      id: `verify.32.${variant}`,
      label: `[${variant}] Signature verify(msg32) [different schemes]`,
      tasks: modernVsLegacy("verify32"),
    },
    {
      id: `wasm.verify.32.${variant}`,
      label: `[${variant}] WASM Signature verify(msg32) [different schemes]`,
      tasks: wasmVsLegacy("verify32"),
    },
    {
      id: `verify.1024.${variant}`,
      label: `[${variant}] Signature verify(msg1024) [different schemes]`,
      tasks: modernVsLegacy("verify1024"),
    },
    {
      id: `wasm.verify.1024.${variant}`,
      label: `[${variant}] WASM Signature verify(msg1024) [different schemes]`,
      tasks: wasmVsLegacy("verify1024"),
    },
    {
      id: `signMessage.256.${variant}`,
      label: `[${variant}] signMessage(msg256)`,
      tasks: modernVsLegacy("signMessage"),
    },
    {
      id: `wasm.signMessage.256.${variant}`,
      label: `[${variant}] WASM signMessage(msg256)`,
      tasks: wasmVsLegacy("signMessage"),
    },
    {
      id: `openMessage.256.${variant}`,
      label: `[${variant}] openMessage(msg256)`,
      tasks: modernVsLegacy("openMessage"),
    },
    {
      id: `wasm.openMessage.256.${variant}`,
      label: `[${variant}] WASM openMessage(msg256)`,
      tasks: wasmVsLegacy("openMessage"),
    },
  ];
}

function runPair(pair, config) {
  for (const task of pair.tasks) {
    runForDuration(task, config.warmupMs, {
      ...config,
      verifyDuringBench: false,
    });
    maybeGc(config);
  }

  for (let round = 0; round < config.rounds; round += 1) {
    const orderedTasks = shuffleWithSeed(pair.tasks, `${pair.id}:${round}`);
    for (const task of orderedTasks) {
      const sample = runForDuration(task, config.roundMs, config);
      task.samples.push(sample.opsPerSec);
      maybeGc(config);
    }
  }

  const implementations = pair.tasks.map((task) => ({
    name: task.name,
    stats: summarize(task.samples),
  }));

  return {
    id: pair.id,
    label: pair.label,
    implementations,
  };
}

function flattenImplementationRows(pairReports) {
  const rows = [];
  for (const pair of pairReports) {
    for (const impl of pair.implementations) {
      rows.push({
        pairId: pair.id,
        pairLabel: pair.label,
        implName: impl.name,
        stats: impl.stats,
      });
    }
  }
  return rows;
}

function readBaseline(baselinePath, config) {
  if (!baselinePath) return null;
  const fullPath = join(__dirname, baselinePath);
  if (!existsSync(fullPath)) {
    throw new Error(`baseline file not found: ${fullPath}`);
  }
  const raw = readFileSync(fullPath, "utf8");
  const parsed = JSON.parse(raw);
  debugLog(config, `baseline loaded from ${fullPath}`);
  return parsed;
}

function createBaselineMap(baseline) {
  const map = new Map();
  if (!baseline || !Array.isArray(baseline.results)) return map;

  for (const pair of baseline.results) {
    const pairId = pair?.id;
    const impls = pair?.implementations;
    if (!pairId || !Array.isArray(impls)) continue;

    for (const impl of impls) {
      if (!impl?.name || !impl?.stats || typeof impl.stats.mean !== "number") continue;
      map.set(`${pairId}|${impl.name}`, impl.stats.mean);
    }
  }
  return map;
}

function evaluateRegressions(currentReports, baseline, config, issues) {
  const findings = [];
  if (!baseline) return findings;

  const baselineMap = createBaselineMap(baseline);
  if (baselineMap.size === 0) {
    issues.failOrWarn("baseline has no comparable results[] entries");
    return findings;
  }

  for (const row of flattenImplementationRows(currentReports)) {
    const key = `${row.pairId}|${row.implName}`;
    if (!baselineMap.has(key)) continue;
    const baselineMean = baselineMap.get(key);
    const currentMean = row.stats.mean;
    const regressionPct = ((baselineMean - currentMean) / baselineMean) * 100;
    const isRegression = regressionPct > config.maxRegressionPct;

    const finding = {
      pairId: row.pairId,
      pairLabel: row.pairLabel,
      implName: row.implName,
      baselineMean,
      currentMean,
      regressionPct,
      thresholdPct: config.maxRegressionPct,
      isRegression,
    };
    findings.push(finding);

    if (isRegression) {
      const msg = `regression ${row.pairId} / ${row.implName}: ${regressionPct.toFixed(
        2
      )}% slower than baseline (threshold ${config.maxRegressionPct}%)`;
      if (config.failOnRegression || config.strict) {
        throw new Error(msg);
      }
      issues.failOrWarn(msg);
    }
  }

  return findings;
}

function printRegressionSummary(regressions, config) {
  if (config.quiet || regressions.length === 0) return;
  console.log("\n=== Regression Check ===");
  console.log(
    "pair".padEnd(42) +
      "impl".padEnd(34) +
      "baseline".padStart(12) +
      "current".padStart(12) +
      "delta".padStart(10)
  );
  console.log("-".repeat(110));
  for (const item of regressions) {
    const delta = percentDelta(item.currentMean, item.baselineMean);
    console.log(
      item.pairId.padEnd(42) +
        item.implName.padEnd(34) +
        fmtOps(item.baselineMean).padStart(12) +
        fmtOps(item.currentMean).padStart(12) +
        fmtPercent(delta).padStart(10)
    );
  }
}

function printWarnings(warnings, config) {
  if (warnings.length === 0 || config.quiet) return;
  console.log(`\nwarnings: ${warnings.length}`);
  for (const warning of warnings) {
    console.log(`- ${warning}`);
  }
}

function buildJsonResult(meta, pairReports, warnings, regressions) {
  const results = pairReports.map((pair) => {
    const entry = {
      id: pair.id,
      label: pair.label,
      implementations: pair.implementations.map((impl) => ({
        name: impl.name,
        stats: impl.stats,
      })),
    };

    if (pair.implementations.length === 2) {
      const [a, b] = pair.implementations;
      const faster = a.stats.mean >= b.stats.mean ? a : b;
      const slower = faster === a ? b : a;
      entry.relative = {
        faster: faster.name,
        slower: slower.name,
        speedup: faster.stats.mean / slower.stats.mean,
        deltaPct: percentDelta(faster.stats.mean, slower.stats.mean),
      };
    }

    return entry;
  });

  return {
    meta,
    warnings,
    regressions,
    results,
  };
}

export async function run(argv = process.argv.slice(2)) {
  const config = parseArgs(argv);
  const issues = createIssueManager(config);

  const meta = {
    timestamp: new Date().toISOString(),
    node: process.version,
    openssl: process.versions.openssl ?? "unknown",
    cpuModel: cpus()[0]?.model ?? "unknown",
    logicalCores: cpus().length,
    config: {
      rounds: config.rounds,
      roundMs: config.roundMs,
      warmupMs: config.warmupMs,
      vectors: config.vectors,
      gc: config.gc,
    },
    modes: modeSummary(config),
    notes: [SIGN_NOTE, AXL_NOTE, OPENMSG_NOTE],
  };

  printSuiteHeader(meta, config);

  const context = buildContext(config);
  if (context.vectorCount < 64) {
    throw new Error(`vector pool must be >= 64, got ${context.vectorCount}`);
  }
  debugLog(config, `vector pool ready: ${context.vectorCount}`);

  runPreflightValidation(context, issues, config);
  debugLog(config, "preflight validation finished");

  const pairReports = [];
  for (const variant of config.variants) {
    if (variant === "nocopy") {
      debugLog(config, "variant=nocopy still copies legacy openMessage input for safety");
    }
    const descriptors = buildPairDescriptors(context, variant, issues, config);
    for (const pair of descriptors) {
      const report = runPair(pair, config);
      pairReports.push(report);
      printPairReport(report, config);
    }
  }

  const baseline = readBaseline(config.baseline, config);
  const regressions = evaluateRegressions(pairReports, baseline, config, issues);
  printRegressionSummary(regressions, config);
  printWarnings(issues.warnings, config);

  const output = buildJsonResult(meta, pairReports, issues.warnings, regressions);
  await writeJsonOutput(output, config);
  return output;
}
