import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

function resolveWasmOptBinary() {
  const direct = spawnSync("wasm-opt", ["--version"], { stdio: "ignore" });
  if (!direct.error && direct.status === 0) {
    return "wasm-opt";
  }

  const cacheRoot = join(homedir(), ".wasm-pack");
  if (!existsSync(cacheRoot)) {
    return undefined;
  }

  const cacheDirs = readdirSync(cacheRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("wasm-opt-"))
    .map((entry) => entry.name)
    .sort()
    .reverse();

  const executable = process.platform === "win32" ? "wasm-opt.exe" : "wasm-opt";

  for (const dirName of cacheDirs) {
    const candidate = join(cacheRoot, dirName, "bin", executable);
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return undefined;
}

export function optimizeWasmBinary(wasmFile, options = {}) {
  const { required = false } = options;
  const wasmOpt = resolveWasmOptBinary();
  if (wasmOpt === undefined) {
    if (required) {
      throw new Error(
        "wasm-opt is required for strict release builds but was not found in PATH or ~/.wasm-pack.",
      );
    }
    console.warn("[warn] wasm-opt not available for extra optimization.");
    return;
  }

  const optimize = spawnSync(wasmOpt, ["-O4", "--enable-bulk-memory", "-o", wasmFile, wasmFile], {
    stdio: "inherit",
  });

  if (optimize.error || optimize.status !== 0) {
    if (required) {
      throw new Error("wasm-opt optimization failed during strict release build.");
    }
    console.warn("[warn] wasm-opt optimization failed; keeping wasm-pack release output.");
  }
}
