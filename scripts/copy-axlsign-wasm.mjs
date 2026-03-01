import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const sourceDir = join(root, "src", "internal", "axlsign-wasm");
const distEsmDir = join(root, "dist", "internal", "axlsign-wasm");
const distCjsDir = join(root, "dist", "cjs", "internal", "axlsign-wasm");

await mkdir(distEsmDir, { recursive: true });
await mkdir(distCjsDir, { recursive: true });

await cp(sourceDir, distEsmDir, { recursive: true });
await cp(sourceDir, distCjsDir, { recursive: true });

// Avoid nested ignore rules excluding wasm assets from npm tarballs.
await rm(join(distEsmDir, ".gitignore"), { force: true });
await rm(join(distCjsDir, ".gitignore"), { force: true });
