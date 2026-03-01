import { createPublicKey, diffieHellman, type KeyObject } from "node:crypto";
import { asBytes32, assertBytes32 } from "./internal/assert.js";
import {
  keyFromX25519Private,
  keyFromX25519Public,
  rawPublicFromX25519Spki,
} from "./internal/der.js";
import type { Bytes32, KeyPair32 } from "./types.js";

function clampScalar(seed32: Bytes32): Bytes32 {
  const clamped = new Uint8Array(32);
  clamped.set(seed32);
  clamped[0] = (clamped[0] ?? 0) & 248;
  const last = clamped[31] ?? 0;
  clamped[31] = (last & 127) | 64;
  return asBytes32(clamped, "clamped scalar");
}

function normalizeSharedSecret(shared: Buffer): Bytes32 {
  if (shared.byteLength !== 32) {
    throw new Error(`X25519 shared secret must be 32 bytes, received ${shared.byteLength}`);
  }
  return asBytes32(
    new Uint8Array(shared.buffer, shared.byteOffset, shared.byteLength),
    "sharedKey",
  );
}

/**
 * Constant-time style 32-byte zero check for shared-secret hardening.
 */
export function isAllZero32(bytes32: Bytes32): boolean {
  assertBytes32(bytes32, "bytes32");
  let acc = 0;
  for (let i = 0; i < 32; i += 1) {
    acc |= bytes32[i] ?? 0;
  }
  return acc === 0;
}

/**
 * Builds a reusable X25519 private KeyObject from a raw 32-byte secret scalar.
 */
export function createPrivateKeyObject(secretKey32: Bytes32): KeyObject {
  assertBytes32(secretKey32, "secretKey32");
  return keyFromX25519Private(secretKey32);
}

/**
 * Builds a reusable X25519 public KeyObject from a raw 32-byte public key.
 */
export function createPublicKeyObject(publicKey32: Bytes32): KeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return keyFromX25519Public(publicKey32);
}

/**
 * Derives raw 32-byte X25519 public key from a private KeyObject.
 */
export function publicKeyFromPrivateKeyObject(privateKey: KeyObject): Bytes32 {
  return rawPublicFromX25519Spki(createPublicKey(privateKey));
}

/**
 * Derives an X25519 public key from a raw 32-byte secret scalar.
 */
export function publicKey(secretKey32: Bytes32): Bytes32 {
  return publicKeyFromPrivateKeyObject(createPrivateKeyObject(secretKey32));
}

/**
 * Computes X25519 ECDH shared secret (raw 32 bytes) from reusable KeyObjects.
 */
export function sharedKeyFromKeyObjects(privateKey: KeyObject, publicKey: KeyObject): Bytes32 {
  return normalizeSharedSecret(diffieHellman({ privateKey, publicKey }));
}

/**
 * Computes X25519 ECDH shared secret (raw 32 bytes).
 */
export function sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  const privateKey = createPrivateKeyObject(secretKey32);
  const publicKey = createPublicKeyObject(publicKey32);
  return sharedKeyFromKeyObjects(privateKey, publicKey);
}

/**
 * Strict X25519 ECDH: rejects all-zero shared secret.
 */
export function sharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  const shared = sharedKey(secretKey32, publicKey32);
  if (isAllZero32(shared)) {
    throw new Error(
      "X25519 shared secret is all-zero; reject low-order/invalid peer public key in protocol flow.",
    );
  }
  return shared;
}

/**
 * Strict X25519 ECDH from reusable KeyObjects: rejects all-zero shared secret.
 */
export function sharedKeyStrictFromKeyObjects(
  privateKey: KeyObject,
  publicKey: KeyObject,
): Bytes32 {
  const shared = sharedKeyFromKeyObjects(privateKey, publicKey);
  if (isAllZero32(shared)) {
    throw new Error(
      "X25519 shared secret is all-zero; reject low-order/invalid peer public key in protocol flow.",
    );
  }
  return shared;
}

/**
 * Deterministically creates an X25519 key pair from a 32-byte seed.
 * The returned private key is explicitly clamped for stable output.
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
