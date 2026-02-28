import { createHash } from "node:crypto";
import { cpus } from "node:os";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import legacyCurve from "curve25519-js";
import { asBytes32, ed25519, x25519 } from "@unknownncat/curve25519-node";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, "..");

const rootDistEntry = join(rootDir, "dist", "index.js");
if (!existsSync(rootDistEntry)) {
  throw new Error(
    "dist/ nao encontrado no projeto principal. Rode `npm run build` na raiz antes do benchmark."
  );
}

function parseArgs() {
  const defaults = {
    rounds: 12,
    roundMs: 250,
    warmupMs: 300,
  };
  const out = { ...defaults };

  for (const arg of process.argv.slice(2)) {
    if (!arg.startsWith("--")) continue;
    const [rawKey, rawValue] = arg.slice(2).split("=", 2);
    if (!rawKey || !rawValue) continue;
    const value = Number(rawValue);
    if (!Number.isFinite(value) || value <= 0) continue;
    if (rawKey === "rounds") out.rounds = Math.floor(value);
    if (rawKey === "roundMs") out.roundMs = value;
    if (rawKey === "warmupMs") out.warmupMs = value;
  }

  return out;
}

function deterministicBytes(seed, length) {
  const out = new Uint8Array(length);
  let ctr = 0;
  let offset = 0;
  while (offset < length) {
    const block = createHash("sha256").update(seed).update(String(ctr)).digest();
    const remaining = length - offset;
    const write = Math.min(remaining, block.length);
    out.set(block.subarray(0, write), offset);
    offset += write;
    ctr += 1;
  }
  return out;
}

function toHex(u8) {
  return Buffer.from(u8).toString("hex");
}

function nowNs() {
  return process.hrtime.bigint();
}

function runForDuration(fn, ms) {
  const start = nowNs();
  const deadline = start + BigInt(Math.floor(ms * 1e6));
  let count = 0;
  let current = start;
  while (current < deadline) {
    fn();
    count += 1;
    current = nowNs();
  }

  const elapsedNs = Number(current - start);
  const elapsedSec = elapsedNs / 1e9;
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
  const n = samples.length;
  const mean = samples.reduce((acc, x) => acc + x, 0) / n;
  const variance = samples.reduce((acc, x) => acc + (x - mean) ** 2, 0) / n;
  return {
    n,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
    stdev: Math.sqrt(variance),
    p50: quantile(sorted, 0.5),
    p95: quantile(sorted, 0.95),
  };
}

function fmtOps(value) {
  return value.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

function fmtNum(value, digits = 2) {
  return value.toLocaleString("en-US", { maximumFractionDigits: digits });
}

function maybeGc() {
  if (typeof globalThis.gc === "function") {
    globalThis.gc();
  }
}

function shuffle(array, roundIndex) {
  const out = [...array];
  let state = (roundIndex + 1) * 0x9e3779b1;
  for (let i = out.length - 1; i > 0; i -= 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    const j = Math.abs(state) % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function benchPair(pairName, tasks, config) {
  for (const task of tasks) {
    runForDuration(task.fn, config.warmupMs);
    maybeGc();
  }

  for (let round = 0; round < config.rounds; round += 1) {
    const roundTasks = shuffle(tasks, round);
    for (const task of roundTasks) {
      const result = runForDuration(task.fn, config.roundMs);
      task.samples.push(result.opsPerSec);
      maybeGc();
    }
  }

  const reports = tasks.map((task) => ({
    ...task,
    stats: summarize(task.samples),
  }));

  return {
    pairName,
    reports,
  };
}

function printPairReport(report) {
  console.log(`\n=== ${report.pairName} ===`);
  console.log(
    "impl".padEnd(26) +
      "mean ops/s".padStart(14) +
      "p50".padStart(12) +
      "p95".padStart(12) +
      "stdev".padStart(12) +
      "rounds".padStart(9)
  );
  console.log("-".repeat(85));

  for (const entry of report.reports) {
    const s = entry.stats;
    console.log(
      entry.name.padEnd(26) +
        fmtOps(s.mean).padStart(14) +
        fmtOps(s.p50).padStart(12) +
        fmtOps(s.p95).padStart(12) +
        fmtOps(s.stdev).padStart(12) +
        String(s.n).padStart(9)
    );
  }

  if (report.reports.length === 2) {
    const [a, b] = report.reports;
    const faster = a.stats.mean >= b.stats.mean ? a : b;
    const slower = faster === a ? b : a;
    const gain = faster.stats.mean / slower.stats.mean;
    console.log(
      `=> ${faster.name} is ${fmtNum(gain, 2)}x faster than ${slower.name} (mean ops/s).`
    );
  }
}

function main() {
  const config = parseArgs();

  const seedA = asBytes32(deterministicBytes("seed-a", 32));
  const seedB = asBytes32(deterministicBytes("seed-b", 32));
  const msgSmall = deterministicBytes("msg-small", 32);
  const msgMedium = deterministicBytes("msg-medium", 256);
  const msgLarge = deterministicBytes("msg-large", 1024);

  const modernXA = x25519.generateKeyPair(seedA);
  const modernXB = x25519.generateKeyPair(seedB);
  const modernEdA = ed25519.generateKeyPair(seedA);

  const legacyA = legacyCurve.generateKeyPair(seedA);
  const legacyB = legacyCurve.generateKeyPair(seedB);

  // Sanity checks before timing.
  const modernShared = x25519.sharedKey(modernXA.private, modernXB.public);
  const legacyShared = legacyCurve.sharedKey(legacyA.private, legacyB.public);
  if (toHex(modernShared) !== toHex(legacyShared)) {
    throw new Error("Sanity check failed: modern and legacy shared keys differ for same seeds.");
  }

  const modernSigSmall = ed25519.sign(seedA, msgSmall);
  const legacySigSmall = legacyCurve.sign(legacyA.private, msgSmall);
  if (!ed25519.verify(modernEdA.public, msgSmall, modernSigSmall)) {
    throw new Error("Sanity check failed: modern sign/verify failed.");
  }
  if (!legacyCurve.verify(legacyA.public, msgSmall, legacySigSmall)) {
    throw new Error("Sanity check failed: legacy sign/verify failed.");
  }

  const modernSignedMedium = ed25519.signMessage(seedA, msgMedium);
  const legacySignedMedium = legacyCurve.signMessage(legacyA.private, msgMedium);
  if (ed25519.openMessage(modernEdA.public, modernSignedMedium) === null) {
    throw new Error("Sanity check failed: modern openMessage failed.");
  }
  if (legacyCurve.openMessage(legacyA.public, legacySignedMedium) === null) {
    throw new Error("Sanity check failed: legacy openMessage failed.");
  }

  const modernSigLarge = ed25519.sign(seedA, msgLarge);
  const legacySigLarge = legacyCurve.sign(legacyA.private, msgLarge);
  if (!ed25519.verify(modernEdA.public, msgLarge, modernSigLarge)) {
    throw new Error("Sanity check failed: modern large sign/verify failed.");
  }
  if (!legacyCurve.verify(legacyA.public, msgLarge, legacySigLarge)) {
    throw new Error("Sanity check failed: legacy large sign/verify failed.");
  }

  const pairs = [
    {
      pairName: "X25519 generateKeyPair(seed32)",
      tasks: [
        {
          name: "modern x25519.generateKeyPair",
          fn: () => x25519.generateKeyPair(seedA),
          samples: [],
        },
        {
          name: "legacy curve.generateKeyPair",
          fn: () => legacyCurve.generateKeyPair(seedA),
          samples: [],
        },
      ],
    },
    {
      pairName: "X25519 sharedKey(sk, pk)",
      tasks: [
        {
          name: "modern x25519.sharedKey",
          fn: () => x25519.sharedKey(modernXA.private, modernXB.public),
          samples: [],
        },
        {
          name: "legacy curve.sharedKey",
          fn: () => legacyCurve.sharedKey(legacyA.private, legacyB.public),
          samples: [],
        },
      ],
    },
    {
      pairName: "Signature sign(msg32) [different schemes]",
      tasks: [
        {
          name: "modern ed25519.sign",
          fn: () => ed25519.sign(seedA, msgSmall),
          samples: [],
        },
        {
          name: "legacy curve.sign",
          fn: () => legacyCurve.sign(legacyA.private, msgSmall),
          samples: [],
        },
      ],
    },
    {
      pairName: "Signature sign(msg1024) [different schemes]",
      tasks: [
        {
          name: "modern ed25519.sign",
          fn: () => ed25519.sign(seedA, msgLarge),
          samples: [],
        },
        {
          name: "legacy curve.sign",
          fn: () => legacyCurve.sign(legacyA.private, msgLarge),
          samples: [],
        },
      ],
    },
    {
      pairName: "Signature verify(msg32) [different schemes]",
      tasks: [
        {
          name: "modern ed25519.verify",
          fn: () => ed25519.verify(modernEdA.public, msgSmall, modernSigSmall),
          samples: [],
        },
        {
          name: "legacy curve.verify",
          fn: () => legacyCurve.verify(legacyA.public, msgSmall, legacySigSmall),
          samples: [],
        },
      ],
    },
    {
      pairName: "Signature verify(msg1024) [different schemes]",
      tasks: [
        {
          name: "modern ed25519.verify",
          fn: () => ed25519.verify(modernEdA.public, msgLarge, modernSigLarge),
          samples: [],
        },
        {
          name: "legacy curve.verify",
          fn: () => legacyCurve.verify(legacyA.public, msgLarge, legacySigLarge),
          samples: [],
        },
      ],
    },
    {
      pairName: "signMessage(msg256)",
      tasks: [
        {
          name: "modern ed25519.signMessage",
          fn: () => ed25519.signMessage(seedA, msgMedium),
          samples: [],
        },
        {
          name: "legacy curve.signMessage",
          fn: () => legacyCurve.signMessage(legacyA.private, msgMedium),
          samples: [],
        },
      ],
    },
    {
      pairName: "openMessage(msg256)",
      tasks: [
        {
          name: "modern ed25519.openMessage",
          fn: () => ed25519.openMessage(modernEdA.public, new Uint8Array(modernSignedMedium)),
          samples: [],
        },
        {
          name: "legacy curve.openMessage",
          fn: () => legacyCurve.openMessage(legacyA.public, new Uint8Array(legacySignedMedium)),
          samples: [],
        },
      ],
    },
  ];

  console.log("curve25519 benchmark suite");
  console.log(`node: ${process.version}`);
  console.log(`cpu: ${cpus()[0]?.model ?? "unknown"} (logical cores: ${cpus().length})`);
  console.log(
    `config: rounds=${config.rounds}, roundMs=${config.roundMs}, warmupMs=${config.warmupMs}, gc=${typeof globalThis.gc === "function"}`
  );
  console.log(
    "note: signing/verify comparisons are throughput comparisons between APIs, not cryptographic-equivalence comparisons."
  );

  for (const pair of pairs) {
    const report = benchPair(pair.pairName, pair.tasks, config);
    printPairReport(report);
  }
}

main();
