#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");

const defaultWorkspaces = ["@unknownncat/curve25519-node", "@unknownncat/curve25519-browser"];

function parseArgs(argv) {
  const options = {
    json: false,
    workspaces: [],
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") {
      options.json = true;
      continue;
    }
    if (arg === "--workspace" || arg === "-w") {
      const value = argv[i + 1];
      if (!value) {
        throw new Error(`Missing value for ${arg}`);
      }
      options.workspaces.push(value);
      i += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h" || arg === "/?") {
      printHelp();
      process.exit(0);
    }
    throw new Error(`Unsupported argument '${arg}'. Run with --help for usage.`);
  }

  if (options.workspaces.length === 0) {
    options.workspaces = [...defaultWorkspaces];
  }

  return options;
}

function printHelp() {
  console.log("Usage: node scripts/pack-size.mjs [options]");
  console.log("");
  console.log("Options:");
  console.log("  --workspace, -w <name>   Workspace package name (repeatable)");
  console.log("  --json                   Output as JSON");
  console.log("  --help                   Show this help");
}

function resolveCommand(file, args) {
  if (process.platform === "win32" && file === "npm") {
    return {
      file: process.env.ComSpec || "cmd.exe",
      args: ["/d", "/s", "/c", "npm", ...args],
    };
  }
  return { file, args };
}

function captureCommand(file, args) {
  const resolved = resolveCommand(file, args);
  const result = spawnSync(resolved.file, resolved.args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error) {
    throw result.error;
  }
  if ((result.status ?? 0) !== 0) {
    throw new Error((result.stderr ?? "").trim() || `Command failed: ${file} ${args.join(" ")}`);
  }
  return result.stdout ?? "";
}

function byteSummaryFromFiles(files) {
  let js = 0;
  let wasm = 0;
  let dts = 0;
  let sourceMaps = 0;

  for (const file of files) {
    const filePath = String(file.path ?? "");
    const size = Number(file.size ?? 0);
    if (filePath.endsWith(".js")) {
      js += size;
    } else if (filePath.endsWith(".wasm")) {
      wasm += size;
    } else if (filePath.endsWith(".d.ts")) {
      dts += size;
    } else if (filePath.endsWith(".map")) {
      sourceMaps += size;
    }
  }

  return { js, wasm, dts, sourceMaps };
}

function formatKB(bytes) {
  if (!Number.isFinite(bytes)) {
    return "-";
  }
  if (bytes < 1000) {
    return `${bytes} B`;
  }
  if (bytes < 1_000_000) {
    return `${(bytes / 1000).toFixed(1)} kB`;
  }
  return `${(bytes / 1_000_000).toFixed(2)} MB`;
}

function getPackageReport(workspaceName) {
  const output = captureCommand("npm", [
    "pack",
    "--dry-run",
    "--json",
    "--ignore-scripts",
    "-w",
    workspaceName,
  ]);

  let payload;
  try {
    payload = JSON.parse(output);
  } catch {
    throw new Error(`Could not parse npm pack JSON output for workspace '${workspaceName}'.`);
  }

  if (!Array.isArray(payload) || payload.length < 1 || !payload[0]) {
    throw new Error(`Unexpected npm pack payload for workspace '${workspaceName}'.`);
  }

  const packInfo = payload[0];
  const files = Array.isArray(packInfo.files) ? packInfo.files : [];
  const breakdown = byteSummaryFromFiles(files);
  const largestFiles = [...files].sort((a, b) => Number(b.size ?? 0) - Number(a.size ?? 0)).slice(0, 5);

  return {
    workspace: workspaceName,
    packageName: String(packInfo.name ?? workspaceName),
    version: String(packInfo.version ?? ""),
    packedSize: Number(packInfo.size ?? 0),
    unpackedSize: Number(packInfo.unpackedSize ?? 0),
    entryCount: Number(packInfo.entryCount ?? files.length),
    breakdown,
    largestFiles: largestFiles.map((file) => ({
      path: String(file.path ?? ""),
      size: Number(file.size ?? 0),
    })),
  };
}

function printReport(reports) {
  console.log("Local package size report via npm pack --dry-run:");
  console.log("");

  for (const report of reports) {
    console.log(`${report.packageName}@${report.version}`);
    console.log(
      `  packed: ${formatKB(report.packedSize)} | unpacked: ${formatKB(report.unpackedSize)} | files: ${report.entryCount}`,
    );
    console.log(
      `  js: ${formatKB(report.breakdown.js)} | wasm: ${formatKB(report.breakdown.wasm)} | d.ts: ${formatKB(report.breakdown.dts)} | maps: ${formatKB(report.breakdown.sourceMaps)}`,
    );
    console.log("  largest files:");
    for (const file of report.largestFiles) {
      console.log(`    - ${file.path} (${formatKB(file.size)})`);
    }
    console.log("");
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const reports = options.workspaces.map((workspaceName) => getPackageReport(workspaceName));

  if (options.json) {
    console.log(JSON.stringify(reports, null, 2));
    return;
  }

  printReport(reports);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
}
