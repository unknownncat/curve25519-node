import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();

const wasmPackages = [
  {
    sourceDir: join(root, "src", "internal", "axlsign-wasm"),
    distEsmDir: join(root, "dist", "internal", "axlsign-wasm"),
    distCjsDir: join(root, "dist", "cjs", "internal", "axlsign-wasm"),
  },
  {
    sourceDir: join(root, "src", "internal", "curve25519-wasm"),
    distEsmDir: join(root, "dist", "internal", "curve25519-wasm"),
    distCjsDir: join(root, "dist", "cjs", "internal", "curve25519-wasm"),
  },
  {
    sourceDir: join(root, "src", "internal", "napi"),
    distEsmDir: join(root, "dist", "internal", "napi"),
    distCjsDir: join(root, "dist", "cjs", "internal", "napi"),
  },
];

for (const { sourceDir, distEsmDir, distCjsDir } of wasmPackages) {
  await mkdir(distEsmDir, { recursive: true });
  await mkdir(distCjsDir, { recursive: true });

  await cp(sourceDir, distEsmDir, { recursive: true });
  await cp(sourceDir, distCjsDir, { recursive: true });

  // Avoid nested ignore rules excluding wasm assets from npm tarballs.
  await rm(join(distEsmDir, ".gitignore"), { force: true });
  await rm(join(distCjsDir, ".gitignore"), { force: true });
}
