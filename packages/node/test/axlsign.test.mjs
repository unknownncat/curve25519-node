import assert from "node:assert/strict";
import test from "node:test";
import { asBytes32, axlsign } from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("axlsign publicKey/sharedKey match known vectors", () => {
  const aliceSeed = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const expectedAlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const bobPublic = asBytes32(
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );
  const expectedShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  const derivedPublic = axlsign.publicKey(aliceSeed);
  const shared = axlsign.sharedKey(aliceSeed, bobPublic);

  assert.equal(bytesToHex(derivedPublic), expectedAlicePublic);
  assert.equal(bytesToHex(shared), expectedShared);
});

test("axlsign generateKeyPair returns clamped private key", () => {
  const seed = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );

  const pair = axlsign.generateKeyPair(seed);

  assert.equal(
    bytesToHex(pair.private),
    "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a",
  );
  assert.equal(
    bytesToHex(pair.public),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
});

test("axlsign deterministic sign/verify matches known signature", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("68656c6c6f20776f726c64");
  const expectedSignature =
    "e51caa3a3b5a361b87884b4bf5683bfc2ffc5a3f854b4e1778bae08ab9253cd1" +
    "744b1022e407deeff9a23e86d7c6af82ba72e27a736f5425e9212c3d479b7985";

  const signature = axlsign.sign(secret, msg);

  assert.equal(bytesToHex(signature), expectedSignature);
  assert.equal(axlsign.verify(publicKey32, msg, signature), true);
});

test("axlsign randomized sign(opt_random) matches known signature", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("68656c6c6f20776f726c64");
  const rnd = hexToBytes("11".repeat(64));
  const expectedSignature =
    "1a2aec15fc319f2d4af503b68d2841e746907235b2fe285e068bd16b734a1ab5" +
    "d433310ef6c649f63dc549f01e49e8dffc8bf3695873352290ea39f416bfb180";

  const signature = axlsign.sign(secret, msg, rnd);

  assert.equal(bytesToHex(signature), expectedSignature);
  assert.equal(axlsign.verify(publicKey32, msg, signature), true);
});

test("axlsign signMessage/openMessage roundtrip and invalid signature handling", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("001122334455");

  const signed = axlsign.signMessage(secret, msg);
  const opened = axlsign.openMessage(publicKey32, signed);

  assert.deepEqual(opened, msg);

  signed[5] ^= 0xff;
  assert.equal(axlsign.openMessage(publicKey32, signed), null);
});

test("axlsign runtime validation rejects wrong input sizes", () => {
  const sk31 = hexToBytes("aa".repeat(31));
  const pk31 = hexToBytes("bb".repeat(31));
  const msg = hexToBytes("deadbeef");

  assert.throws(() => axlsign.publicKey(sk31), /32 bytes/);
  assert.throws(() => axlsign.sharedKey(asBytes32(hexToBytes("11".repeat(32))), pk31), /32 bytes/);
  assert.throws(
    () => axlsign.sign(asBytes32(hexToBytes("22".repeat(32))), msg, hexToBytes("33".repeat(63))),
    /64 bytes/,
  );
  assert.throws(
    () => axlsign.verify(asBytes32(hexToBytes("44".repeat(32))), msg, hexToBytes("55".repeat(63))),
    /64 bytes/,
  );
});
