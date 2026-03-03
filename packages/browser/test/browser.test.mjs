import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  asBytes32,
  asBytes64,
  axlsign,
  ed25519,
  initWasm,
  isWasmInitialized,
  x25519,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const hexToBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

test("initWasm allows retry after a failed first attempt", () => {
  const code = `
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const runtimePath = join(process.cwd(), "dist", "internal", "wasm-runtime.js");
const runtime = await import(pathToFileURL(runtimePath).href);

let failed = false;
try {
  await runtime.initWasm({
    axlsign: new Uint8Array([1]),
    curve25519: new Uint8Array([1]),
  });
} catch {
  failed = true;
}

if (!failed) {
  throw new Error("Expected first initWasm call to fail with invalid module bytes");
}

const axlsignWasm = await readFile(
  join(process.cwd(), "dist", "internal", "axlsign-wasm", "axlsign_wasm_bg.wasm"),
);
const curveWasm = await readFile(
  join(process.cwd(), "dist", "internal", "curve25519-wasm", "curve25519_wasm_bg.wasm"),
);

await runtime.initWasm({ axlsign: axlsignWasm, curve25519: curveWasm });
if (!runtime.isWasmInitialized()) {
  throw new Error("WASM runtime should be initialized after retry");
}
`;

  const result = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    cwd: join(here, ".."),
    encoding: "utf8",
  });

  assert.equal(
    result.status,
    0,
    `retry scenario failed\\nstdout:\\n${result.stdout}\\nstderr:\\n${result.stderr}`,
  );
});

await initWasm({
  axlsign: await readFile(
    join(here, "..", "dist", "internal", "axlsign-wasm", "axlsign_wasm_bg.wasm"),
  ),
  curve25519: await readFile(
    join(here, "..", "dist", "internal", "curve25519-wasm", "curve25519_wasm_bg.wasm"),
  ),
});

test("initWasm initializes browser runtime", () => {
  assert.equal(isWasmInitialized(), true);
});

test("browser x25519 matches RFC 7748 vector", () => {
  const alicePrivate = asBytes32(
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  );
  const bobPublic = asBytes32(
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );

  assert.equal(
    bytesToHex(x25519.publicKey(alicePrivate)),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
  assert.equal(
    bytesToHex(x25519.sharedKey(alicePrivate, bobPublic)),
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  );
});

test("browser ed25519 signs/verifies RFC 8032 vector", () => {
  const seed = asBytes32(
    hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
  );
  const msg = new Uint8Array(0);

  const publicKey32 = ed25519.publicKey(seed);
  const signature64 = ed25519.sign(seed, msg);

  assert.equal(
    bytesToHex(publicKey32),
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  );
  assert.equal(
    bytesToHex(signature64),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  );

  assert.equal(ed25519.verify(publicKey32, msg, signature64), true);
});

test("browser axlsign deterministic verify", () => {
  const secret = asBytes32(
    hexToBytes("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a"),
  );
  const publicKey32 = asBytes32(
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  const msg = hexToBytes("68656c6c6f20776f726c64");
  const expectedSignature = asBytes64(
    hexToBytes(
      "e51caa3a3b5a361b87884b4bf5683bfc2ffc5a3f854b4e1778bae08ab9253cd1" +
        "744b1022e407deeff9a23e86d7c6af82ba72e27a736f5425e9212c3d479b7985",
    ),
  );

  const signature = axlsign.sign(secret, msg);

  assert.equal(bytesToHex(signature), bytesToHex(expectedSignature));
  assert.equal(axlsign.verify(publicKey32, msg, signature), true);
});
