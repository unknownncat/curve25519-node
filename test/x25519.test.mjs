import assert from "node:assert/strict";
import test from "node:test";
import { asBytes32, x25519 } from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("RFC 7748 section 6.1 vectors: public keys and shared secret", () => {
  const alicePrivate = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const alicePublic = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const bobPrivate = asBytes32(
    hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
  );
  const bobPublic = asBytes32(
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );
  const expectedShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  assert.equal(bytesToHex(x25519.publicKey(alicePrivate)), bytesToHex(alicePublic));
  assert.equal(bytesToHex(x25519.publicKey(bobPrivate)), bytesToHex(bobPublic));
  assert.equal(bytesToHex(x25519.sharedKey(alicePrivate, bobPublic)), expectedShared);
  assert.equal(bytesToHex(x25519.sharedKey(bobPrivate, alicePublic)), expectedShared);
});

test("RFC 7748 section 5.2 vectors: scalar/u-coordinate multiplication", () => {
  const scalar1 = asBytes32(
    hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
  );
  const u1 = asBytes32(
    hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
  );
  const out1 = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

  const scalar2 = asBytes32(
    hexToBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
  );
  const u2 = asBytes32(
    hexToBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
  );
  const out2 = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

  assert.equal(bytesToHex(x25519.sharedKey(scalar1, u1)), out1);
  assert.equal(bytesToHex(x25519.sharedKey(scalar2, u2)), out2);
});

test("generateKeyPair clamps private key and does not mutate seed", () => {
  const seed = asBytes32(hexToBytes("ff".repeat(32)));
  const snapshot = bytesToHex(seed);
  const pair = x25519.generateKeyPair(seed);

  assert.equal(bytesToHex(seed), snapshot);
  assert.equal(pair.private.length, 32);
  assert.equal(pair.public.length, 32);
  assert.equal(pair.private[0] & 0b111, 0);
  assert.equal(pair.private[31] & 0b1000_0000, 0);
  assert.equal(pair.private[31] & 0b0100_0000, 0b0100_0000);
});

test("runtime validation rejects invalid key sizes", () => {
  assert.throws(() => x25519.publicKey(hexToBytes("11".repeat(31))), /32 bytes/);
  assert.throws(
    () => x25519.sharedKey(hexToBytes("22".repeat(31)), asBytes32(hexToBytes("33".repeat(32)))),
    /32 bytes/,
  );
  assert.throws(
    () => x25519.sharedKey(asBytes32(hexToBytes("44".repeat(32))), hexToBytes("55".repeat(31))),
    /32 bytes/,
  );
});
