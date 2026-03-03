import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const sourceDir = join(root, "src", "internal", "axlsign-wasm");
const distTargets = [
  join(root, "dist", "internal", "axlsign-wasm"),
  join(root, "dist", "cjs", "internal", "axlsign-wasm"),
];

for (const distDir of distTargets) {
  await mkdir(distDir, { recursive: true });
  await cp(sourceDir, distDir, { recursive: true });
  await rm(join(distDir, ".gitignore"), { force: true });
}
