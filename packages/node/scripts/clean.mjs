import { rm } from "node:fs/promises";
import { join } from "node:path";

const distDir = join(process.cwd(), "dist");
const generatedInternalDirs = [
  join(process.cwd(), "src", "internal", "axlsign-wasm"),
  join(process.cwd(), "src", "internal", "curve25519-wasm"),
];

await rm(distDir, { recursive: true, force: true });
for (const dir of generatedInternalDirs) {
  await rm(dir, { recursive: true, force: true });
}
