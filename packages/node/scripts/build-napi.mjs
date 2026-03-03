import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const packageDir = process.cwd();
const rustWorkspaceDir = join(packageDir, "..", "..", "rust");
const napiOutDir = join(
  packageDir,
  "src",
  "internal",
  "napi",
  `${process.platform}-${process.arch}`,
);

const result = spawnSync("cargo", ["build", "-p", "curve25519-node-napi", "--release"], {
  cwd: rustWorkspaceDir,
  stdio: "inherit",
});

if (result.error) {
  throw new Error(
    `failed to execute cargo: ${result.error.message}. Install Rust toolchain and retry.`,
  );
}

if (result.status !== 0) {
  throw new Error(`cargo build failed with exit code ${result.status ?? "unknown"}`);
}

const artifactNameByPlatform = {
  win32: "curve25519_node_napi.dll",
  linux: "libcurve25519_node_napi.so",
  darwin: "libcurve25519_node_napi.dylib",
};

const artifactName = artifactNameByPlatform[process.platform];
if (artifactName === undefined) {
  throw new Error(`unsupported platform for napi artifact copy: ${process.platform}`);
}

const sourceArtifact = join(rustWorkspaceDir, "target", "release", artifactName);
const destArtifact = join(napiOutDir, "curve25519_node_napi.node");
const legacyDestArtifact = join(packageDir, "src", "internal", "napi", "curve25519_node_napi.node");

await mkdir(napiOutDir, { recursive: true });
await rm(legacyDestArtifact, { force: true });
await cp(sourceArtifact, destArtifact);
