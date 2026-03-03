import { spawnSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { optimizeWasmBinary } from "./optimize-wasm.mjs";

const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(packageDir, "src", "internal", "axlsign-wasm");
const crateDir = join(packageDir, "..", "..", "rust", "crates", "axlsign-wasm");

await mkdir(outDir, { recursive: true });

const args = [
  "build",
  crateDir,
  "--target",
  "web",
  "--release",
  "--out-dir",
  outDir,
  "--out-name",
  "axlsign_wasm",
];

const result = spawnSync("wasm-pack", args, {
  cwd: packageDir,
  stdio: "inherit",
});

if (result.error) {
  throw new Error(
    `failed to execute wasm-pack: ${result.error.message}. ` +
      "Install Rust + wasm-pack and retry (https://rustwasm.github.io/wasm-pack/installer/).",
  );
}

if (result.status !== 0) {
  throw new Error(`wasm-pack build failed with exit code ${result.status ?? "unknown"}`);
}

const wasmFile = join(outDir, "axlsign_wasm_bg.wasm");
optimizeWasmBinary(wasmFile, {
  required: process.env.CURVE25519_REQUIRE_WASM_OPT === "1",
});
