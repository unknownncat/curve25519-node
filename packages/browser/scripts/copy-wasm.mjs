import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();

const wasmPackages = [
  {
    sourceDir: join(root, "src", "internal", "axlsign-wasm"),
    distDir: join(root, "dist", "internal", "axlsign-wasm"),
  },
  {
    sourceDir: join(root, "src", "internal", "curve25519-wasm"),
    distDir: join(root, "dist", "internal", "curve25519-wasm"),
  },
];

for (const { sourceDir, distDir } of wasmPackages) {
  await mkdir(distDir, { recursive: true });
  await cp(sourceDir, distDir, { recursive: true });
  await rm(join(distDir, ".gitignore"), { force: true });
}
