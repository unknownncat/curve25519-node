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

const SELF_PACKAGE_NAME = "@unknownncat/curve25519-node";

const requireBase =
  typeof __filename === "string"
    ? __filename
    : typeof process.argv[1] === "string" && isAbsolute(process.argv[1])
      ? process.argv[1]
      : join(process.cwd(), "package.json");

const nodeRequire = createRequire(requireBase);

interface WasmBindings {
  x25519PublicKey(secretKey: Uint8Array): Uint8Array;
  x25519SharedKey(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  ed25519PublicKey(secretSeed: Uint8Array): Uint8Array;
  ed25519Sign(secretSeed: Uint8Array, msg: Uint8Array): Uint8Array;
  ed25519Verify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean;
}

export interface WasmX25519PrivateKeyObject {
  readonly type: "x25519-private";
  readonly bytes: Bytes32;
}

export interface WasmX25519PublicKeyObject {
  readonly type: "x25519-public";
  readonly bytes: Bytes32;
}

export interface WasmEd25519PrivateKeyObject {
  readonly type: "ed25519-private";
  readonly bytes: Bytes32;
}

export interface WasmEd25519PublicKeyObject {
  readonly type: "ed25519-public";
  readonly bytes: Bytes32;
}

let wasmModulePath: string | undefined;
let wasmBindings: WasmBindings | undefined;

function resolveWasmModulePath(): string {
  const candidates: string[] = [];

  try {
    const packageJsonPath = nodeRequire.resolve(`${SELF_PACKAGE_NAME}/package.json`);
    candidates.push(
      join(dirname(packageJsonPath), "dist", "internal", "curve25519-wasm", "curve25519_wasm.js"),
    );
  } catch {
    // Fall back to local development paths below.
  }

  if (typeof __dirname === "string") {
    candidates.push(join(__dirname, "internal", "curve25519-wasm", "curve25519_wasm.js"));
  }

  candidates.push(join(process.cwd(), "dist", "internal", "curve25519-wasm", "curve25519_wasm.js"));
  candidates.push(join(process.cwd(), "src", "internal", "curve25519-wasm", "curve25519_wasm.js"));

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    "Unable to locate modern curve25519 WASM module. Run `npm run build` before using wasm API in local dev.",
  );
}

function getWasmBindings(): WasmBindings {
  if (wasmBindings !== undefined) {
    return wasmBindings;
  }

  if (wasmModulePath === undefined) {
    wasmModulePath = resolveWasmModulePath();
  }

  // Lazy-load WASM bindings so node:crypto users avoid startup overhead.
  wasmBindings = nodeRequire(wasmModulePath) as WasmBindings;
  return wasmBindings;
}

function copyBytes32(bytes32: Bytes32, label: string): Bytes32 {
  const out = new Uint8Array(32);
  out.set(bytes32);
  return asBytes32(out, label);
}

function clampScalar(seed32: Bytes32): Bytes32 {
  const out = new Uint8Array(32);
  out.set(seed32);
  out[0] = (out[0] ?? 0) & 248;
  const last = out[31] ?? 0;
  out[31] = (last & 127) | 64;
  return asBytes32(out, "clamped scalar");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function assertWasmKeyObject(
  value: unknown,
  expectedType: "x25519-private" | "x25519-public" | "ed25519-private" | "ed25519-public",
  label: string,
): asserts value is { readonly type: typeof expectedType; readonly bytes: Bytes32 } {
  if (!isRecord(value) || value.type !== expectedType || !(value.bytes instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a ${expectedType} key object`);
  }
  assertBytes32(value.bytes, `${label}.bytes`);
}

export function isAllZero32(bytes32: Bytes32): boolean {
  assertBytes32(bytes32, "bytes32");
  let acc = 0;
  for (let i = 0; i < 32; i += 1) {
    acc |= bytes32[i] ?? 0;
  }
  return acc === 0;
}

export function x25519CreatePrivateKeyObject(secretKey32: Bytes32): WasmX25519PrivateKeyObject {
  assertBytes32(secretKey32, "secretKey32");
  return Object.freeze({
    type: "x25519-private",
    bytes: copyBytes32(secretKey32, "x25519 private key object bytes"),
  });
}

export function x25519CreatePublicKeyObject(publicKey32: Bytes32): WasmX25519PublicKeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return Object.freeze({
    type: "x25519-public",
    bytes: copyBytes32(publicKey32, "x25519 public key object bytes"),
  });
}

export function x25519PublicKeyFromPrivateKeyObject(
  privateKey: WasmX25519PrivateKeyObject,
): Bytes32 {
  assertWasmKeyObject(privateKey, "x25519-private", "privateKey");
  return asBytes32(getWasmBindings().x25519PublicKey(privateKey.bytes), "x25519 public key");
}

export function x25519PublicKey(secretKey32: Bytes32): Bytes32 {
  return x25519PublicKeyFromPrivateKeyObject(x25519CreatePrivateKeyObject(secretKey32));
}

export function x25519SharedKeyFromKeyObjects(
  privateKey: WasmX25519PrivateKeyObject,
  publicKey: WasmX25519PublicKeyObject,
): Bytes32 {
  assertWasmKeyObject(privateKey, "x25519-private", "privateKey");
  assertWasmKeyObject(publicKey, "x25519-public", "publicKey");
  return asBytes32(
    getWasmBindings().x25519SharedKey(privateKey.bytes, publicKey.bytes),
    "x25519 shared key",
  );
}

export function x25519SharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  const privateKey = x25519CreatePrivateKeyObject(secretKey32);
  const publicKey = x25519CreatePublicKeyObject(publicKey32);
  return x25519SharedKeyFromKeyObjects(privateKey, publicKey);
}

export function x25519SharedKeyStrictFromKeyObjects(
  privateKey: WasmX25519PrivateKeyObject,
  publicKey: WasmX25519PublicKeyObject,
): Bytes32 {
  const shared = x25519SharedKeyFromKeyObjects(privateKey, publicKey);
  if (isAllZero32(shared)) {
    throw new Error(
      "X25519 shared secret is all-zero; reject low-order/invalid peer public key in protocol flow.",
    );
  }
  return shared;
}

export function x25519SharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  const privateKey = x25519CreatePrivateKeyObject(secretKey32);
  const publicKey = x25519CreatePublicKeyObject(publicKey32);
  return x25519SharedKeyStrictFromKeyObjects(privateKey, publicKey);
}

export function x25519GenerateKeyPair(seed32: Bytes32): KeyPair32 {
  assertBytes32(seed32, "seed32");
  const privateKey = clampScalar(seed32);
  const publicKey32 = x25519PublicKey(privateKey);
  return {
    public: publicKey32,
    private: privateKey,
  };
}

export function ed25519CreatePrivateKeyObject(secretSeed32: Bytes32): WasmEd25519PrivateKeyObject {
  assertBytes32(secretSeed32, "secretSeed32");
  return Object.freeze({
    type: "ed25519-private",
    bytes: copyBytes32(secretSeed32, "ed25519 private key object bytes"),
  });
}

export function ed25519CreatePublicKeyObject(publicKey32: Bytes32): WasmEd25519PublicKeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return Object.freeze({
    type: "ed25519-public",
    bytes: copyBytes32(publicKey32, "ed25519 public key object bytes"),
  });
}

export function ed25519PublicKeyFromPrivateKeyObject(
  privateKey: WasmEd25519PrivateKeyObject,
): Bytes32 {
  assertWasmKeyObject(privateKey, "ed25519-private", "privateKey");
  return asBytes32(getWasmBindings().ed25519PublicKey(privateKey.bytes), "ed25519 public key");
}

export function ed25519PublicKey(secretSeed32: Bytes32): Bytes32 {
  return ed25519PublicKeyFromPrivateKeyObject(ed25519CreatePrivateKeyObject(secretSeed32));
}

export function ed25519GenerateKeyPair(seed32: Bytes32): KeyPair32 {
  assertBytes32(seed32, "seed32");
  return {
    public: ed25519PublicKey(seed32),
    private: seed32,
  };
}

export function ed25519SignWithPrivateKey(
  privateKey: WasmEd25519PrivateKeyObject,
  msg: Uint8Array,
): Bytes64 {
  assertWasmKeyObject(privateKey, "ed25519-private", "privateKey");
  assertUint8Array(msg, "msg");
  return asBytes64(getWasmBindings().ed25519Sign(privateKey.bytes, msg), "ed25519 signature");
}

export function ed25519Sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64 {
  return ed25519SignWithPrivateKey(ed25519CreatePrivateKeyObject(secretSeed32), msg);
}

export function ed25519VerifyWithPublicKey(
  publicKey: WasmEd25519PublicKeyObject,
  msg: Uint8Array,
  signature64: Bytes64,
): boolean {
  assertWasmKeyObject(publicKey, "ed25519-public", "publicKey");
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return getWasmBindings().ed25519Verify(publicKey.bytes, msg, signature64);
}

export function ed25519Verify(
  publicKey32: Bytes32,
  msg: Uint8Array,
  signature64: Bytes64,
): boolean {
  return ed25519VerifyWithPublicKey(ed25519CreatePublicKeyObject(publicKey32), msg, signature64);
}

export function ed25519SignMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array {
  assertBytes32(secretSeed32, "secretSeed32");
  assertUint8Array(msg, "msg");

  const signature64 = ed25519Sign(secretSeed32, msg);
  const signed = new Uint8Array(64 + msg.byteLength);
  signed.set(signature64, 0);
  signed.set(msg, 64);
  return signed;
}

export function ed25519OpenMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(signedMsg, "signedMsg");

  if (signedMsg.byteLength < 64) {
    return null;
  }

  const signature64 = asBytes64(signedMsg.subarray(0, 64), "signedMsg signature");
  const msg = signedMsg.subarray(64);
  if (!ed25519Verify(publicKey32, msg, signature64)) {
    return null;
  }
  return new Uint8Array(msg);
}

export const x25519 = {
  createPrivateKeyObject: x25519CreatePrivateKeyObject,
  createPublicKeyObject: x25519CreatePublicKeyObject,
  publicKeyFromPrivateKeyObject: x25519PublicKeyFromPrivateKeyObject,
  publicKey: x25519PublicKey,
  sharedKey: x25519SharedKey,
  sharedKeyFromKeyObjects: x25519SharedKeyFromKeyObjects,
  sharedKeyStrict: x25519SharedKeyStrict,
  sharedKeyStrictFromKeyObjects: x25519SharedKeyStrictFromKeyObjects,
  isAllZero32,
  generateKeyPair: x25519GenerateKeyPair,
} as const;

export const ed25519 = {
  createPrivateKeyObject: ed25519CreatePrivateKeyObject,
  createPublicKeyObject: ed25519CreatePublicKeyObject,
  publicKeyFromPrivateKeyObject: ed25519PublicKeyFromPrivateKeyObject,
  publicKey: ed25519PublicKey,
  generateKeyPair: ed25519GenerateKeyPair,
  sign: ed25519Sign,
  signWithPrivateKey: ed25519SignWithPrivateKey,
  verify: ed25519Verify,
  verifyWithPublicKey: ed25519VerifyWithPublicKey,
  signMessage: ed25519SignMessage,
  openMessage: ed25519OpenMessage,
} as const;

const api = {
  x25519,
  ed25519,
} as const;

export default api;
