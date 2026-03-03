import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { asBytes32, axlsign, ed25519, napi, x25519 } from "../dist/index.js";

const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");
const here = dirname(fileURLToPath(import.meta.url));

test("napi addon is stored under platform/arch directory", () => {
  const expectedAddonPath = join(
    here,
    "..",
    "dist",
    "internal",
    "napi",
    `${process.platform}-${process.arch}`,
    "curve25519_node_napi.node",
  );
  const legacyAddonPath = join(here, "..", "dist", "internal", "napi", "curve25519_node_napi.node");

  assert.equal(existsSync(expectedAddonPath), true);
  assert.equal(existsSync(legacyAddonPath), false);
});

test("napi addon is available after build", () => {
  assert.equal(napi.isAvailable(), true);
});

test("napi.x25519 matches RFC 7748 vector and node:crypto output", () => {
  const alicePrivate = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const bobPublic = asBytes32(
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );

  const napiPublic = napi.x25519.publicKey(alicePrivate);
  const napiShared = napi.x25519.sharedKey(alicePrivate, bobPublic);

  assert.equal(bytesToHex(napiPublic), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  assert.equal(bytesToHex(napiShared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  assert.equal(bytesToHex(napiPublic), bytesToHex(x25519.publicKey(alicePrivate)));
  assert.equal(bytesToHex(napiShared), bytesToHex(x25519.sharedKey(alicePrivate, bobPublic)));
});

test("napi.ed25519 sign/verify matches node:crypto outputs", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const msg = hexToBytes("00112233445566778899");

  const napiPublic = napi.ed25519.publicKey(seed);
  const napiSig = napi.ed25519.sign(seed, msg);

  assert.equal(bytesToHex(napiPublic), bytesToHex(ed25519.publicKey(seed)));
  assert.equal(bytesToHex(napiSig), bytesToHex(ed25519.sign(seed, msg)));
  assert.equal(napi.ed25519.verify(napiPublic, msg, napiSig), true);
});

test("napi.axlsign matches wasm axlsign signatures", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("68656c6c6f20776f726c64");
  const rnd = hexToBytes("11".repeat(64));

  const napiSig = napi.axlsign.sign(secret, msg, rnd);
  const wasmSig = axlsign.sign(secret, msg, rnd);

  assert.equal(bytesToHex(napiSig), bytesToHex(wasmSig));
  assert.equal(napi.axlsign.verify(publicKey32, msg, napiSig), true);
});
