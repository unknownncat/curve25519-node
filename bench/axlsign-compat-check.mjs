import crypto from "node:crypto";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import legacyCurve from "curve25519-js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, "..");
const nodeDistEntry = join(rootDir, "packages", "node", "dist", "index.js");

if (!existsSync(nodeDistEntry)) {
  throw new Error(
    "packages/node/dist/ nao encontrado. Rode `npm run build:node` (ou `npm run build`) na raiz antes do compat check."
  );
}

const { asBytes32, axlsign } = await import(pathToFileURL(nodeDistEntry).href);

const ALICE_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const BOB_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

function toU8Hex(hex) {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function toHex(u8) {
  return Buffer.from(u8).toString("hex");
}

function eqBytes(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  const aa = Buffer.from(a.buffer, a.byteOffset, a.byteLength);
  const bb = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  return crypto.timingSafeEqual(aa, bb);
}

function assertSame(label, a, b) {
  if (!eqBytes(a, b)) {
    throw new Error(
      `${label} mismatch\nlegacy: ${toHex(a)}\nmodern: ${toHex(b)}`
    );
  }
}

function runOriginalExampleComparison() {
  const alicePriv = toU8Hex(ALICE_PRIV);
  const bobPub = toU8Hex(BOB_PUB);

  const legacySecret = legacyCurve.sharedKey(alicePriv, bobPub);
  const modernSecret = axlsign.sharedKey(asBytes32(alicePriv), asBytes32(bobPub));

  assertSame("sharedKey(ALICE_PRIV, BOB_PUB)", legacySecret, modernSecret);

  const seed = crypto.randomBytes(32);
  const seedU8 = Uint8Array.from(seed);

  const legacyKeyPair = legacyCurve.generateKeyPair(seedU8);
  const modernKeyPair = axlsign.generateKeyPair(asBytes32(seedU8));

  assertSame("generateKeyPair(seed).private", legacyKeyPair.private, modernKeyPair.private);
  assertSame("generateKeyPair(seed).public", legacyKeyPair.public, modernKeyPair.public);

  return {
    legacy: {
      secret: toHex(legacySecret),
      private: toHex(legacyKeyPair.private),
      public: toHex(legacyKeyPair.public),
    },
    modern: {
      secret: toHex(modernSecret),
      private: toHex(modernKeyPair.private),
      public: toHex(modernKeyPair.public),
    },
    seed: toHex(seedU8),
  };
}

function runManyComparisons(iterations = 512) {
  for (let i = 0; i < iterations; i += 1) {
    const seedA = Uint8Array.from(crypto.randomBytes(32));
    const seedB = Uint8Array.from(crypto.randomBytes(32));

    const legacyA = legacyCurve.generateKeyPair(seedA);
    const legacyB = legacyCurve.generateKeyPair(seedB);

    const modernA = axlsign.generateKeyPair(asBytes32(seedA));
    const modernB = axlsign.generateKeyPair(asBytes32(seedB));

    assertSame(`iter=${i} keypair A private`, legacyA.private, modernA.private);
    assertSame(`iter=${i} keypair A public`, legacyA.public, modernA.public);
    assertSame(`iter=${i} keypair B private`, legacyB.private, modernB.private);
    assertSame(`iter=${i} keypair B public`, legacyB.public, modernB.public);

    const legacyShared1 = legacyCurve.sharedKey(legacyA.private, legacyB.public);
    const modernShared1 = axlsign.sharedKey(modernA.private, modernB.public);
    assertSame(`iter=${i} shared A->B`, legacyShared1, modernShared1);

    const legacyShared2 = legacyCurve.sharedKey(legacyB.private, legacyA.public);
    const modernShared2 = axlsign.sharedKey(modernB.private, modernA.public);
    assertSame(`iter=${i} shared B->A`, legacyShared2, modernShared2);

    assertSame(`iter=${i} DH symmetry legacy`, legacyShared1, legacyShared2);
    assertSame(`iter=${i} DH symmetry modern`, modernShared1, modernShared2);
  }
}

function parseIterations(argv) {
  const flag = argv.find((arg) => arg.startsWith("--iterations="));
  if (!flag) return 512;
  const raw = flag.slice("--iterations=".length);
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) {
    throw new Error(`invalid --iterations value: ${raw}`);
  }
  return n;
}

function main() {
  const iterations = parseIterations(process.argv.slice(2));

  const oneShot = runOriginalExampleComparison();
  runManyComparisons(iterations);

  console.log("curve25519-js compatibility check (axlsign)");
  console.log(`iterations: ${iterations}`);
  console.log(`seed:     ${oneShot.seed}`);
  console.log(`secret:   ${oneShot.legacy.secret}`);
  console.log(`private:  ${oneShot.legacy.private}`);
  console.log(`public:   ${oneShot.legacy.public}`);
  console.log("status:   OK (legacy === modern)");

  console.log("curve25519-node compatibility check (axlsign)");
  console.log(`iterations: ${iterations}`);
  console.log(`seed:     ${oneShot.seed}`);
  console.log(`secret:   ${oneShot.modern.secret}`);
  console.log(`private:  ${oneShot.modern.private}`);
  console.log(`public:   ${oneShot.modern.public}`);
  console.log("status:   OK (legacy === modern)");
}

main();
