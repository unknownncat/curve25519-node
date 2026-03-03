import { spawnSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(rootDir, "src", "internal", "curve25519-wasm");
const crateDir = join(rootDir, "..", "..", "rust", "crates", "curve-wasm");

await mkdir(outDir, { recursive: true });

const args = [
  "build",
  crateDir,
  "--target",
  "nodejs",
  "--release",
  "--out-dir",
  outDir,
  "--out-name",
  "curve25519_wasm",
];

const result = spawnSync("wasm-pack", args, {
  cwd: rootDir,
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
