import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as browser from "../../browser/dist/index.js";
import {
  asBytes32,
  axlsign as nodeAxlsign,
  ed25519 as nodeEd25519,
  x25519 as nodeX25519,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

await browser.initWasm({
  axlsign: await readFile(
    join(here, "..", "..", "browser", "dist", "internal", "axlsign-wasm", "axlsign_wasm_bg.wasm"),
  ),
  curve25519: await readFile(
    join(
      here,
      "..",
      "..",
      "browser",
      "dist",
      "internal",
      "curve25519-wasm",
      "curve25519_wasm_bg.wasm",
    ),
  ),
});

test("node axlsign sign -> browser verify, and browser sign -> node verify", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("68656c6c6f20776f726c64");
  const rnd = hexToBytes("11".repeat(64));

  const nodeSig = nodeAxlsign.sign(secret, msg, rnd);
  assert.equal(browser.axlsign.verify(publicKey32, msg, nodeSig), true);

  const browserSig = browser.axlsign.sign(secret, msg, rnd);
  assert.equal(nodeAxlsign.verify(publicKey32, msg, browserSig), true);
  assert.equal(bytesToHex(browserSig), bytesToHex(nodeSig));
});

test("node ed25519 sign -> browser verify, and browser sign -> node verify", () => {
  const seed = asBytes32(
    hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
  );
  const publicKey32 = nodeEd25519.publicKey(seed);
  const msg = hexToBytes("00112233445566778899");

  const nodeSig = nodeEd25519.sign(seed, msg);
  assert.equal(browser.ed25519.verify(publicKey32, msg, nodeSig), true);

  const browserSig = browser.ed25519.sign(seed, msg);
  assert.equal(nodeEd25519.verify(publicKey32, msg, browserSig), true);
  assert.equal(bytesToHex(browserSig), bytesToHex(nodeSig));
});

test("node and browser x25519 sharedKey outputs are identical", () => {
  const seedA = asBytes32(hexToBytes("01".repeat(32)));
  const seedB = asBytes32(hexToBytes("02".repeat(32)));

  const nodeA = nodeX25519.generateKeyPair(seedA);
  const browserB = browser.x25519.generateKeyPair(seedB);

  const sharedNode = nodeX25519.sharedKey(nodeA.private, browserB.public);
  const sharedBrowser = browser.x25519.sharedKey(nodeA.private, browserB.public);

  assert.equal(bytesToHex(sharedNode), bytesToHex(sharedBrowser));
});
