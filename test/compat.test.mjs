import assert from "node:assert/strict";
import test from "node:test";
import {
  asBytes32,
  ed25519,
  generateKeyPair,
  generateKeyPairEd25519,
  generateKeyPairX25519,
  openMessage,
  sharedKey,
  sign,
  signMessage,
  verify,
  x25519,
} from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("top-level aliases map to namespaces", () => {
  const seedX = asBytes32(hexToBytes("01".repeat(32)));
  const seedEd = asBytes32(hexToBytes("02".repeat(32)));
  const msg = hexToBytes("deadbeef");

  const kpXNs = x25519.generateKeyPair(seedX);
  const kpXAlias = generateKeyPair(seedX);
  const kpXExplicit = generateKeyPairX25519(seedX);
  const kpEd = generateKeyPairEd25519(seedEd);

  assert.equal(bytesToHex(kpXNs.public), bytesToHex(kpXAlias.public));
  assert.equal(bytesToHex(kpXNs.public), bytesToHex(kpXExplicit.public));
  assert.equal(bytesToHex(sharedKey(kpXNs.private, kpXNs.public)), bytesToHex(x25519.sharedKey(kpXNs.private, kpXNs.public)));

  const signature = sign(seedEd, msg);
  assert.equal(verify(kpEd.public, msg, signature), true);
  assert.equal(ed25519.verify(kpEd.public, msg, signature), true);

  const signed = signMessage(seedEd, msg);
  assert.deepEqual(openMessage(kpEd.public, signed), msg);
});

test("compat sign/signMessage reject opt_random explicitly", () => {
  const seedEd = asBytes32(hexToBytes("03".repeat(32)));
  const msg = hexToBytes("010203");
  const optRandom = hexToBytes("ff".repeat(64));

  assert.throws(() => sign(seedEd, msg, optRandom), /does not support opt_random/);
  assert.throws(() => signMessage(seedEd, msg, optRandom), /does not support opt_random/);
});
