#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");

const packageFiles = ["packages/node/package.json", "packages/browser/package.json"];
const publishOrder = ["@unknownncat/curve25519-node", "@unknownncat/curve25519-browser"];
const validBumps = new Set(["patch", "minor", "major", "none"]);

function printHelp() {
  console.log("Usage: node scripts/release.mjs [options]");
  console.log("");
  console.log("Options:");
  console.log("  --bump <patch|minor|major|none>   Version bump level (default: patch)");
  console.log("  --publish                          Publish workspaces in release order");
  console.log("  --commit                           Commit package version files");
  console.log("  --tag                              Create git tag v<version>");
  console.log("  --skip-checks                      Skip release:check");
  console.log("  --skip-bench                       Skip benchmark during release checks");
  console.log("  --allow-dirty                      Allow dirty git working tree");
  console.log("");
  console.log("PowerShell-compatible aliases are also supported:");
  console.log("  -Bump, -Publish, -Commit, -Tag, -SkipChecks, -SkipBench, -AllowDirty");
}

function parseArgs(argv) {
  const options = {
    bump: "patch",
    publish: false,
    commit: false,
    tag: false,
    skipChecks: false,
    skipBench: false,
    allowDirty: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    switch (arg) {
      case "--bump":
      case "-Bump": {
        const value = argv[i + 1];
        if (!value) {
          throw new Error(`Missing value for ${arg}`);
        }
        options.bump = value.toLowerCase();
        i += 1;
        break;
      }
      case "--publish":
      case "-Publish":
        options.publish = true;
        break;
      case "--commit":
      case "-Commit":
        options.commit = true;
        break;
      case "--tag":
      case "-Tag":
        options.tag = true;
        break;
      case "--skip-checks":
      case "-SkipChecks":
        options.skipChecks = true;
        break;
      case "--skip-bench":
      case "-SkipBench":
        options.skipBench = true;
        break;
      case "--allow-dirty":
      case "-AllowDirty":
        options.allowDirty = true;
        break;
      case "--help":
      case "-h":
      case "/?":
        printHelp();
        process.exit(0);
      default:
        throw new Error(`Unsupported argument '${arg}'. Run with --help for usage.`);
    }
  }

  if (!validBumps.has(options.bump)) {
    throw new Error(
      `Unsupported bump level '${options.bump}'. Expected one of: patch, minor, major, none`,
    );
  }

  return options;
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

function invokeCheckedCommand(file, args, extra = {}) {
  console.log(`==> ${file} ${args.join(" ")}`);
  const resolved = resolveCommand(file, args);
  const result = spawnSync(resolved.file, resolved.args, {
    cwd: repoRoot,
    stdio: "inherit",
    ...extra,
  });

  if (result.error) {
    throw new Error(`Failed to execute '${file}': ${result.error.message}`);
  }
  if ((result.status ?? 0) !== 0) {
    throw new Error(`Command failed with exit code ${result.status}: ${file} ${args.join(" ")}`);
  }
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

function getNextVersion(current, level) {
  if (level === "none") {
    return current;
  }

  const match = /^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$/.exec(current);
  if (!match?.groups) {
    throw new Error(
      `Unsupported version format '${current}'. Expected plain semver like 2.1.1`,
    );
  }

  let major = Number.parseInt(match.groups.major, 10);
  let minor = Number.parseInt(match.groups.minor, 10);
  let patch = Number.parseInt(match.groups.patch, 10);

  if (level === "patch") {
    patch += 1;
  } else if (level === "minor") {
    minor += 1;
    patch = 0;
  } else if (level === "major") {
    major += 1;
    minor = 0;
    patch = 0;
  }

  return `${major}.${minor}.${patch}`;
}

function readPackageJson(relativePath) {
  const fullPath = path.resolve(repoRoot, relativePath);
  return JSON.parse(fs.readFileSync(fullPath, "utf8"));
}

function writePackageJson(relativePath, data) {
  const fullPath = path.resolve(repoRoot, relativePath);
  fs.writeFileSync(fullPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

function ensureCleanWorkingTree(allowDirty) {
  if (allowDirty) {
    return;
  }

  let statusOutput;
  try {
    statusOutput = captureCommand("git", ["status", "--porcelain"]).trim();
  } catch {
    throw new Error("Could not read git status. Ensure git is installed and repository is initialized.");
  }

  if (statusOutput.length > 0) {
    throw new Error("Working tree is not clean. Commit or stash changes first, or rerun with --allow-dirty.");
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  ensureCleanWorkingTree(options.allowDirty);

  const packages = packageFiles.map((file) => ({ path: file, json: readPackageJson(file) }));
  const versions = [...new Set(packages.map((entry) => String(entry.json.version)))];

  if (versions.length !== 1) {
    throw new Error(`Package versions are not aligned: ${versions.join(", ")}`);
  }

  const currentVersion = versions[0];
  const nextVersion = getNextVersion(currentVersion, options.bump);

  console.log(`Current version: ${currentVersion}`);
  console.log(`Target version:  ${nextVersion}`);

  if (options.bump !== "none") {
    for (const entry of packages) {
      entry.json.version = nextVersion;
    }

    for (const entry of packages) {
      writePackageJson(entry.path, entry.json);
      console.log(`Updated ${entry.path} -> ${nextVersion}`);
    }

    invokeCheckedCommand("npm", ["install", "--package-lock-only"]);
    invokeCheckedCommand("npm", ["exec", "--", "prettier", "--write", ...packageFiles]);
  }

  if (!options.skipChecks) {
    const hadRequireWasmOpt = Object.prototype.hasOwnProperty.call(
      process.env,
      "CURVE25519_REQUIRE_WASM_OPT",
    );
    const previousRequireWasmOpt = process.env.CURVE25519_REQUIRE_WASM_OPT;
    process.env.CURVE25519_REQUIRE_WASM_OPT = "1";
    try {
      const checkScript = options.skipBench ? "release:check:nobench" : "release:check";
      invokeCheckedCommand("npm", ["run", checkScript]);
    } finally {
      if (hadRequireWasmOpt) {
        process.env.CURVE25519_REQUIRE_WASM_OPT = previousRequireWasmOpt;
      } else {
        delete process.env.CURVE25519_REQUIRE_WASM_OPT;
      }
    }
  }

  if (options.publish) {
    for (const packageName of publishOrder) {
      invokeCheckedCommand("npm", ["publish", "--access", "public", "-w", packageName]);
    }
  }

  if (options.commit) {
    invokeCheckedCommand("git", ["add", "package-lock.json", ...packageFiles]);
    invokeCheckedCommand("git", ["commit", "-m", `chore(release): v${nextVersion}`]);
  }

  if (options.tag) {
    invokeCheckedCommand("git", ["tag", `v${nextVersion}`]);
  }

  console.log("");
  console.log("Release automation finished.");
  console.log(`Version: ${nextVersion}`);
  if (options.tag) {
    console.log(`Tag created: v${nextVersion}`);
  }
  console.log("If you created commit/tag, push manually with:");
  console.log("  git push origin HEAD");
  if (options.tag) {
    console.log(`  git push origin v${nextVersion}`);
  }
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
}
