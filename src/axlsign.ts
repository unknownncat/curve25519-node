import { existsSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { createRequire } from "node:module";
import {
  asBytes32,
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertUint8Array,
} from "./internal/assert.js";
import type { Bytes32, Bytes64, KeyPair32 } from "./types.js";
import type * as WasmAxlModule from "./internal/axlsign-wasm/axlsign_wasm.js";

const SELF_PACKAGE_NAME = "@unknownncat/curve25519-node";

const requireBase =
  typeof __filename === "string"
    ? __filename
    : typeof process.argv[1] === "string" && isAbsolute(process.argv[1])
      ? process.argv[1]
      : join(process.cwd(), "package.json");

const nodeRequire = createRequire(requireBase);

let wasmModulePath: string | undefined;

let wasmAxl: typeof WasmAxlModule | undefined;

function resolveWasmModulePath(): string {
  const candidates: string[] = [];

  try {
    const packageJsonPath = nodeRequire.resolve(`${SELF_PACKAGE_NAME}/package.json`);
    candidates.push(
      join(dirname(packageJsonPath), "dist", "internal", "axlsign-wasm", "axlsign_wasm.js"),
    );
  } catch {
    // Fall back to local development paths below.
  }

  if (typeof __dirname === "string") {
    candidates.push(join(__dirname, "internal", "axlsign-wasm", "axlsign_wasm.js"));
  }

  candidates.push(join(process.cwd(), "dist", "internal", "axlsign-wasm", "axlsign_wasm.js"));
  candidates.push(join(process.cwd(), "src", "internal", "axlsign-wasm", "axlsign_wasm.js"));

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    "Unable to locate axlsign WASM module. Run `npm run build` before using axlsign in local dev.",
  );
}

function getWasmAxl(): typeof WasmAxlModule {
  if (wasmAxl !== undefined) {
    return wasmAxl;
  }

  if (wasmModulePath === undefined) {
    wasmModulePath = resolveWasmModulePath();
  }

  // Lazy-load WASM bindings to keep modern-only imports lightweight.
  wasmAxl = nodeRequire(wasmModulePath) as typeof WasmAxlModule;
  return wasmAxl;
}

function clampScalar(seed32: Bytes32): Bytes32 {
  const out = new Uint8Array(32);
  out.set(seed32);
  out[0] = (out[0] ?? 0) & 248;
  const last = out[31] ?? 0;
  out[31] = (last & 127) | 64;
  return asBytes32(out, "clamped scalar");
}

function assertOptionalRandom64(value: Uint8Array | undefined, fnName: string): void {
  if (value === undefined) return;
  assertBytes64(value, `${fnName} opt_random`);
}

/**
 * Derives an axlsign-compatible public key (Montgomery/X25519 format).
 */
export function publicKey(secretKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  const out = getWasmAxl().axlsignPublicKey(secretKey32);
  return asBytes32(out, "axlsign public key");
}

/**
 * Computes an axlsign-compatible X25519 shared key.
 */
export function sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  assertBytes32(publicKey32, "publicKey32");
  const out = getWasmAxl().axlsignSharedKey(secretKey32, publicKey32);
  return asBytes32(out, "axlsign shared key");
}

/**
 * Generates an axlsign-compatible key pair from a 32-byte seed.
 */
export function generateKeyPair(seed32: Bytes32): KeyPair32 {
  assertBytes32(seed32, "seed32");
  const privateKey = clampScalar(seed32);
  const publicKey32 = publicKey(privateKey);
  return {
    public: publicKey32,
    private: privateKey,
  };
}

/**
 * Detached axlsign signature using X25519-format secret key.
 * opt_random (64 bytes) enables randomized signing as in curve25519-js.
 */
export function sign(secretKey32: Bytes32, msg: Uint8Array, opt_random?: Uint8Array): Bytes64 {
  assertBytes32(secretKey32, "secretKey32");
  assertUint8Array(msg, "msg");
  assertOptionalRandom64(opt_random, "sign");

  const signature =
    opt_random === undefined
      ? getWasmAxl().axlsignSign(secretKey32, msg)
      : getWasmAxl().axlsignSignRnd(secretKey32, msg, opt_random);
  return asBytes64(signature, "axlsign signature");
}

/**
 * Verifies detached axlsign signature.
 */
export function verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return getWasmAxl().axlsignVerify(publicKey32, msg, signature64);
}

/**
 * Returns signature || message (axlsign mode).
 */
export function signMessage(
  secretKey32: Bytes32,
  msg: Uint8Array,
  opt_random?: Uint8Array,
): Uint8Array {
  assertBytes32(secretKey32, "secretKey32");
  assertUint8Array(msg, "msg");
  assertOptionalRandom64(opt_random, "signMessage");

  const signature = sign(secretKey32, msg, opt_random);
  const out = new Uint8Array(64 + msg.byteLength);
  out.set(signature, 0);
  out.set(msg, 64);
  return out;
}

/**
 * Verifies signature || message and returns original message on success.
 */
export function openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(signedMsg, "signedMsg");

  if (signedMsg.byteLength < 64) {
    return null;
  }

  const signature64 = asBytes64(signedMsg.subarray(0, 64), "signedMsg signature");
  const msg = signedMsg.subarray(64);
  if (!verify(publicKey32, msg, signature64)) {
    return null;
  }

  return new Uint8Array(msg);
}
