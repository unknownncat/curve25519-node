import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const cjsDir = join(process.cwd(), "dist", "cjs");
const packageJsonPath = join(cjsDir, "package.json");

const packageJson = {
  type: "commonjs",
};

await mkdir(cjsDir, { recursive: true });
await writeFile(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, "utf8");
