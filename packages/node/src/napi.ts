import {
  asBytes32,
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertUint8Array,
} from "./internal/assert.js";
import { getNapiBindings, isNapiAvailable } from "./internal/napi-loader.js";
import type { Bytes32, Bytes64, KeyPair32 } from "./types.js";

export interface NapiX25519PrivateKeyObject {
  readonly type: "x25519-private";
  readonly bytes: Bytes32;
}

export interface NapiX25519PublicKeyObject {
  readonly type: "x25519-public";
  readonly bytes: Bytes32;
}

export interface NapiEd25519PrivateKeyObject {
  readonly type: "ed25519-private";
  readonly bytes: Bytes32;
}

export interface NapiEd25519PublicKeyObject {
  readonly type: "ed25519-public";
  readonly bytes: Bytes32;
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

function assertNapiKeyObject(
  value: unknown,
  expectedType: "x25519-private" | "x25519-public" | "ed25519-private" | "ed25519-public",
  label: string,
): asserts value is { readonly type: typeof expectedType; readonly bytes: Bytes32 } {
  if (!isRecord(value) || value.type !== expectedType || !(value.bytes instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a ${expectedType} key object`);
  }
  assertBytes32(value.bytes, `${label}.bytes`);
}

function assertOptionalRandom64(value: Uint8Array | undefined, fnName: string): void {
  if (value === undefined) return;
  assertBytes64(value, `${fnName} opt_random`);
}

export function isAllZero32(bytes32: Bytes32): boolean {
  assertBytes32(bytes32, "bytes32");
  let acc = 0;
  for (let i = 0; i < 32; i += 1) {
    acc |= bytes32[i] ?? 0;
  }
  return acc === 0;
}

export function x25519CreatePrivateKeyObject(secretKey32: Bytes32): NapiX25519PrivateKeyObject {
  assertBytes32(secretKey32, "secretKey32");
  return Object.freeze({
    type: "x25519-private",
    bytes: copyBytes32(secretKey32, "x25519 private key object bytes"),
  });
}

export function x25519CreatePublicKeyObject(publicKey32: Bytes32): NapiX25519PublicKeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return Object.freeze({
    type: "x25519-public",
    bytes: copyBytes32(publicKey32, "x25519 public key object bytes"),
  });
}

export function x25519PublicKeyFromPrivateKeyObject(
  privateKey: NapiX25519PrivateKeyObject,
): Bytes32 {
  assertNapiKeyObject(privateKey, "x25519-private", "privateKey");
  return asBytes32(getNapiBindings().x25519PublicKey(privateKey.bytes), "x25519 public key");
}

export function x25519PublicKey(secretKey32: Bytes32): Bytes32 {
  return x25519PublicKeyFromPrivateKeyObject(x25519CreatePrivateKeyObject(secretKey32));
}

export function x25519SharedKeyFromKeyObjects(
  privateKey: NapiX25519PrivateKeyObject,
  publicKey: NapiX25519PublicKeyObject,
): Bytes32 {
  assertNapiKeyObject(privateKey, "x25519-private", "privateKey");
  assertNapiKeyObject(publicKey, "x25519-public", "publicKey");
  return asBytes32(
    getNapiBindings().x25519SharedKey(privateKey.bytes, publicKey.bytes),
    "x25519 shared key",
  );
}

export function x25519SharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  const privateKey = x25519CreatePrivateKeyObject(secretKey32);
  const publicKey = x25519CreatePublicKeyObject(publicKey32);
  return x25519SharedKeyFromKeyObjects(privateKey, publicKey);
}

export function x25519SharedKeyStrictFromKeyObjects(
  privateKey: NapiX25519PrivateKeyObject,
  publicKey: NapiX25519PublicKeyObject,
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

export function ed25519CreatePrivateKeyObject(secretSeed32: Bytes32): NapiEd25519PrivateKeyObject {
  assertBytes32(secretSeed32, "secretSeed32");
  return Object.freeze({
    type: "ed25519-private",
    bytes: copyBytes32(secretSeed32, "ed25519 private key object bytes"),
  });
}

export function ed25519CreatePublicKeyObject(publicKey32: Bytes32): NapiEd25519PublicKeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return Object.freeze({
    type: "ed25519-public",
    bytes: copyBytes32(publicKey32, "ed25519 public key object bytes"),
  });
}

export function ed25519PublicKeyFromPrivateKeyObject(
  privateKey: NapiEd25519PrivateKeyObject,
): Bytes32 {
  assertNapiKeyObject(privateKey, "ed25519-private", "privateKey");
  return asBytes32(getNapiBindings().ed25519PublicKey(privateKey.bytes), "ed25519 public key");
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
  privateKey: NapiEd25519PrivateKeyObject,
  msg: Uint8Array,
): Bytes64 {
  assertNapiKeyObject(privateKey, "ed25519-private", "privateKey");
  assertUint8Array(msg, "msg");
  return asBytes64(getNapiBindings().ed25519Sign(privateKey.bytes, msg), "ed25519 signature");
}

export function ed25519Sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64 {
  return ed25519SignWithPrivateKey(ed25519CreatePrivateKeyObject(secretSeed32), msg);
}

export function ed25519VerifyWithPublicKey(
  publicKey: NapiEd25519PublicKeyObject,
  msg: Uint8Array,
  signature64: Bytes64,
): boolean {
  assertNapiKeyObject(publicKey, "ed25519-public", "publicKey");
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return getNapiBindings().ed25519Verify(publicKey.bytes, msg, signature64);
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

export function axlsignPublicKey(secretKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  return asBytes32(getNapiBindings().axlsignPublicKey(secretKey32), "axlsign public key");
}

export function axlsignSharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  assertBytes32(publicKey32, "publicKey32");
  return asBytes32(
    getNapiBindings().axlsignSharedKey(secretKey32, publicKey32),
    "axlsign shared key",
  );
}

export function axlsignGenerateKeyPair(seed32: Bytes32): KeyPair32 {
  assertBytes32(seed32, "seed32");
  const privateKey = clampScalar(seed32);
  const publicKey32 = axlsignPublicKey(privateKey);
  return {
    public: publicKey32,
    private: privateKey,
  };
}

export function axlsignSign(
  secretKey32: Bytes32,
  msg: Uint8Array,
  opt_random?: Uint8Array,
): Bytes64 {
  assertBytes32(secretKey32, "secretKey32");
  assertUint8Array(msg, "msg");
  assertOptionalRandom64(opt_random, "axlsignSign");

  const signature =
    opt_random === undefined
      ? getNapiBindings().axlsignSign(secretKey32, msg)
      : getNapiBindings().axlsignSignRnd(secretKey32, msg, opt_random);
  return asBytes64(signature, "axlsign signature");
}

export function axlsignVerify(
  publicKey32: Bytes32,
  msg: Uint8Array,
  signature64: Bytes64,
): boolean {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return getNapiBindings().axlsignVerify(publicKey32, msg, signature64);
}

export function axlsignSignMessage(
  secretKey32: Bytes32,
  msg: Uint8Array,
  opt_random?: Uint8Array,
): Uint8Array {
  assertBytes32(secretKey32, "secretKey32");
  assertUint8Array(msg, "msg");
  assertOptionalRandom64(opt_random, "axlsignSignMessage");

  const signature = axlsignSign(secretKey32, msg, opt_random);
  const out = new Uint8Array(64 + msg.byteLength);
  out.set(signature, 0);
  out.set(msg, 64);
  return out;
}

export function axlsignOpenMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(signedMsg, "signedMsg");

  if (signedMsg.byteLength < 64) {
    return null;
  }

  const signature64 = asBytes64(signedMsg.subarray(0, 64), "signedMsg signature");
  const msg = signedMsg.subarray(64);
  if (!axlsignVerify(publicKey32, msg, signature64)) {
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

export const axlsign = {
  publicKey: axlsignPublicKey,
  sharedKey: axlsignSharedKey,
  generateKeyPair: axlsignGenerateKeyPair,
  sign: axlsignSign,
  verify: axlsignVerify,
  signMessage: axlsignSignMessage,
  openMessage: axlsignOpenMessage,
} as const;

const api = {
  isAvailable: isNapiAvailable,
  x25519,
  ed25519,
  axlsign,
} as const;

export { isNapiAvailable };
export default api;
