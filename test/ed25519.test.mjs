import assert from "node:assert/strict";
import test from "node:test";
import { asBytes32, asBytes64, ed25519 } from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("RFC 8032 test vector 1: empty message", () => {
  const seed = asBytes32(
    hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
  );
  const expectedPublic = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const expectedSignature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

  const msg = new Uint8Array(0);
  const publicKey32 = ed25519.publicKey(seed);
  const signature64 = ed25519.sign(seed, msg);

  assert.equal(bytesToHex(publicKey32), expectedPublic);
  assert.equal(bytesToHex(signature64), expectedSignature);
  assert.equal(
    ed25519.verify(
      asBytes32(hexToBytes(expectedPublic)),
      msg,
      asBytes64(hexToBytes(expectedSignature)),
    ),
    true,
  );
});

test("RFC 8032 test vector 2: one-byte message", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const expectedPublic = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
  const expectedSignature =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

  const msg = hexToBytes("72");
  const publicKey32 = ed25519.publicKey(seed);
  const signature64 = ed25519.sign(seed, msg);

  assert.equal(bytesToHex(publicKey32), expectedPublic);
  assert.equal(bytesToHex(signature64), expectedSignature);
  assert.equal(ed25519.verify(publicKey32, msg, signature64), true);
});

test("signMessage returns signature || message and openMessage recovers payload", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const publicKey32 = ed25519.publicKey(seed);
  const msg = hexToBytes("48656c6c6f2c2065643235353139");

  const signature = ed25519.sign(seed, msg);
  const signedMsg = ed25519.signMessage(seed, msg);
  const opened = ed25519.openMessage(publicKey32, signedMsg);

  assert.equal(signedMsg.length, 64 + msg.length);
  assert.equal(bytesToHex(signedMsg.subarray(0, 64)), bytesToHex(signature));
  assert.equal(bytesToHex(signedMsg.subarray(64)), bytesToHex(msg));
  assert.deepEqual(opened, msg);
});

test("openMessage returns null on invalid signature", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const publicKey32 = ed25519.publicKey(seed);
  const msg = hexToBytes("001122334455");
  const signedMsg = ed25519.signMessage(seed, msg);

  signedMsg[10] ^= 0xff;
  assert.equal(ed25519.openMessage(publicKey32, signedMsg), null);
});

test("runtime validation rejects wrong input sizes", () => {
  const seed31 = hexToBytes("aa".repeat(31));
  const pub31 = hexToBytes("bb".repeat(31));
  const sig63 = hexToBytes("cc".repeat(63));
  const msg = new Uint8Array([1, 2, 3]);

  assert.throws(() => ed25519.publicKey(seed31), /32 bytes/);
  assert.throws(() => ed25519.sign(seed31, msg), /32 bytes/);
  assert.throws(
    () => ed25519.verify(asBytes32(hexToBytes("11".repeat(32))), msg, sig63),
    /64 bytes/,
  );
  assert.throws(
    () => ed25519.verify(pub31, msg, asBytes64(hexToBytes("22".repeat(64)))),
    /32 bytes/,
  );
});
