import assert from "node:assert/strict";
import test from "node:test";
import { asBytes32, asBytes64, ed25519, wasm, x25519 } from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("wasm.x25519 covers full parity API and RFC 7748 vectors", () => {
  const alicePrivate = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const bobPublic = asBytes32(
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );
  const expectedPublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const expectedShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  const privateKeyObject = wasm.x25519.createPrivateKeyObject(alicePrivate);
  const publicKeyObject = wasm.x25519.createPublicKeyObject(bobPublic);

  assert.equal(bytesToHex(wasm.x25519.publicKey(alicePrivate)), expectedPublic);
  assert.equal(
    bytesToHex(wasm.x25519.publicKeyFromPrivateKeyObject(privateKeyObject)),
    expectedPublic,
  );

  assert.equal(bytesToHex(wasm.x25519.sharedKey(alicePrivate, bobPublic)), expectedShared);
  assert.equal(
    bytesToHex(wasm.x25519.sharedKeyFromKeyObjects(privateKeyObject, publicKeyObject)),
    expectedShared,
  );
  assert.equal(bytesToHex(wasm.x25519.sharedKeyStrict(alicePrivate, bobPublic)), expectedShared);
  assert.equal(
    bytesToHex(wasm.x25519.sharedKeyStrictFromKeyObjects(privateKeyObject, publicKeyObject)),
    expectedShared,
  );

  assert.equal(wasm.x25519.isAllZero32(asBytes32(new Uint8Array(32))), true);
  assert.equal(wasm.x25519.isAllZero32(asBytes32(hexToBytes("01".repeat(32)))), false);
});

test("wasm.x25519 generateKeyPair is deterministic and clamped", () => {
  const seed = asBytes32(hexToBytes("ff".repeat(32)));
  const pair = wasm.x25519.generateKeyPair(seed);

  assert.equal(pair.private[0] & 0b111, 0);
  assert.equal(pair.private[31] & 0b1000_0000, 0);
  assert.equal(pair.private[31] & 0b0100_0000, 0b0100_0000);
  assert.equal(bytesToHex(pair.public), bytesToHex(wasm.x25519.publicKey(pair.private)));
});

test("wasm.ed25519 covers full parity API and RFC 8032 vector", () => {
  const seed = asBytes32(
    hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
  );
  const expectedPublic = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const expectedSignature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
  const msg = new Uint8Array(0);

  const privateKeyObject = wasm.ed25519.createPrivateKeyObject(seed);
  const publicKeyObject = wasm.ed25519.createPublicKeyObject(asBytes32(hexToBytes(expectedPublic)));

  const publicKey32 = wasm.ed25519.publicKey(seed);
  const signature64 = wasm.ed25519.sign(seed, msg);
  const signatureFromObject = wasm.ed25519.signWithPrivateKey(privateKeyObject, msg);

  assert.equal(bytesToHex(publicKey32), expectedPublic);
  assert.equal(
    bytesToHex(wasm.ed25519.publicKeyFromPrivateKeyObject(privateKeyObject)),
    expectedPublic,
  );
  assert.equal(bytesToHex(signature64), expectedSignature);
  assert.equal(bytesToHex(signatureFromObject), expectedSignature);

  const expectedPublic32 = asBytes32(hexToBytes(expectedPublic));
  const expectedSignature64 = asBytes64(hexToBytes(expectedSignature));
  assert.equal(wasm.ed25519.verify(expectedPublic32, msg, expectedSignature64), true);
  assert.equal(wasm.ed25519.verifyWithPublicKey(publicKeyObject, msg, expectedSignature64), true);
});

test("wasm.ed25519 signMessage/openMessage roundtrip", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const publicKey32 = wasm.ed25519.publicKey(seed);
  const msg = hexToBytes("68656c6c6f2d7761736d");

  const signed = wasm.ed25519.signMessage(seed, msg);
  assert.deepEqual(wasm.ed25519.openMessage(publicKey32, signed), msg);

  signed[0] ^= 0xff;
  assert.equal(wasm.ed25519.openMessage(publicKey32, signed), null);
});

test("wasm modern API matches node:crypto API outputs", () => {
  const seedX = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const seedEd = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const msg = hexToBytes("00112233445566778899");

  assert.equal(bytesToHex(wasm.x25519.publicKey(seedX)), bytesToHex(x25519.publicKey(seedX)));
  assert.equal(bytesToHex(wasm.ed25519.publicKey(seedEd)), bytesToHex(ed25519.publicKey(seedEd)));
  assert.equal(bytesToHex(wasm.ed25519.sign(seedEd, msg)), bytesToHex(ed25519.sign(seedEd, msg)));

  const wasmX = wasm.x25519.generateKeyPair(seedX);
  const nodeX = x25519.generateKeyPair(seedX);
  assert.equal(bytesToHex(wasmX.public), bytesToHex(nodeX.public));

  const wasmEd = wasm.ed25519.generateKeyPair(seedEd);
  const nodeEd = ed25519.generateKeyPair(seedEd);
  assert.equal(bytesToHex(wasmEd.public), bytesToHex(nodeEd.public));
});

test("wasm runtime validation rejects wrong sizes and invalid key objects", () => {
  const msg = hexToBytes("deadbeef");
  const sk31 = hexToBytes("aa".repeat(31));
  const pk31 = hexToBytes("bb".repeat(31));
  const sig63 = hexToBytes("cc".repeat(63));

  assert.throws(() => wasm.x25519.publicKey(sk31), /32 bytes/);
  assert.throws(
    () => wasm.x25519.sharedKey(asBytes32(hexToBytes("11".repeat(32))), pk31),
    /32 bytes/,
  );
  assert.throws(() => wasm.ed25519.sign(sk31, msg), /32 bytes/);
  assert.throws(
    () => wasm.ed25519.verify(asBytes32(hexToBytes("22".repeat(32))), msg, sig63),
    /64 bytes/,
  );

  assert.throws(
    () =>
      wasm.x25519.sharedKeyFromKeyObjects({ type: "x25519-private" }, { type: "x25519-public" }),
    /key object/,
  );
  assert.throws(
    () => wasm.ed25519.signWithPrivateKey({ type: "ed25519-private" }, msg),
    /key object/,
  );
});
