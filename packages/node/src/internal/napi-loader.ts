import { existsSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { createRequire } from "node:module";

const SELF_PACKAGE_NAME = "@unknownncat/curve25519-node";

const requireBase =
  typeof __filename === "string"
    ? __filename
    : typeof process.argv[1] === "string" && isAbsolute(process.argv[1])
      ? process.argv[1]
      : join(process.cwd(), "package.json");

const nodeRequire = createRequire(requireBase);
const NAPI_ARTIFACT_NAME = "curve25519_node_napi.node";
const NAPI_PLATFORM_DIR = `${process.platform}-${process.arch}`;

interface NapiBindings {
  x25519PublicKey(secretKey: Uint8Array): Uint8Array;
  x25519SharedKey(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  ed25519PublicKey(secretSeed: Uint8Array): Uint8Array;
  ed25519Sign(secretSeed: Uint8Array, msg: Uint8Array): Uint8Array;
  ed25519Verify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean;
  axlsignPublicKey(secretKey: Uint8Array): Uint8Array;
  axlsignSharedKey(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  axlsignSign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array;
  axlsignSignRnd(secretKey: Uint8Array, msg: Uint8Array, rnd: Uint8Array): Uint8Array;
  axlsignVerify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean;
}

let napiModulePath: string | undefined;
let napiBindings: NapiBindings | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function hasFn(value: Record<string, unknown>, name: keyof NapiBindings): boolean {
  return typeof value[name] === "function";
}

function isNapiBindings(value: unknown): value is NapiBindings {
  if (!isRecord(value)) {
    return false;
  }

  return (
    hasFn(value, "x25519PublicKey") &&
    hasFn(value, "x25519SharedKey") &&
    hasFn(value, "ed25519PublicKey") &&
    hasFn(value, "ed25519Sign") &&
    hasFn(value, "ed25519Verify") &&
    hasFn(value, "axlsignPublicKey") &&
    hasFn(value, "axlsignSharedKey") &&
    hasFn(value, "axlsignSign") &&
    hasFn(value, "axlsignSignRnd") &&
    hasFn(value, "axlsignVerify")
  );
}

function resolveNapiModulePath(): string {
  const candidates: string[] = [];

  const addInternalNapiCandidates = (rootDir: string): void => {
    candidates.push(join(rootDir, "internal", "napi", NAPI_PLATFORM_DIR, NAPI_ARTIFACT_NAME));
    // Backward-compatibility path for older local builds.
    candidates.push(join(rootDir, "internal", "napi", NAPI_ARTIFACT_NAME));
  };

  try {
    const packageJsonPath = nodeRequire.resolve(`${SELF_PACKAGE_NAME}/package.json`);
    addInternalNapiCandidates(join(dirname(packageJsonPath), "dist"));
  } catch {
    // Fall back to local development paths below.
  }

  if (typeof __dirname === "string") {
    candidates.push(join(__dirname, "napi", NAPI_PLATFORM_DIR, NAPI_ARTIFACT_NAME));
    candidates.push(join(__dirname, "napi", NAPI_ARTIFACT_NAME));
  }

  addInternalNapiCandidates(join(process.cwd(), "dist"));
  addInternalNapiCandidates(join(process.cwd(), "src"));

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    "Unable to locate napi-rs native addon. Run `npm run build` before using napi namespace in local dev.",
  );
}

function loadNapiBindings(): NapiBindings {
  if (napiBindings !== undefined) {
    return napiBindings;
  }

  if (napiModulePath === undefined) {
    napiModulePath = resolveNapiModulePath();
  }

  let loaded: unknown;
  try {
    loaded = nodeRequire(napiModulePath);
  } catch (error) {
    const reason =
      error instanceof Error
        ? error
        : new Error(`Unknown N-API load failure: ${String(error)}`);
    throw reason;
  }

  if (!isNapiBindings(loaded)) {
    throw new Error("Loaded N-API addon has an unexpected export shape.");
  }

  napiBindings = loaded;
  return napiBindings;
}

export function isNapiAvailable(): boolean {
  try {
    loadNapiBindings();
    return true;
  } catch {
    return false;
  }
}

export function getNapiBindings(): NapiBindings {
  try {
    return loadNapiBindings();
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Unable to load napi-rs native addon: ${error.message}`);
    }
    throw new Error(`Unable to load napi-rs native addon: ${String(error)}`);
  }
}
