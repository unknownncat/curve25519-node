import {
  createPublicKey,
  sign as cryptoSign,
  type KeyObject,
  verify as cryptoVerify,
} from "node:crypto";
import {
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertUint8Array,
  toBufferView,
} from "./internal/assert.js";
import {
  keyFromEd25519Private,
  keyFromEd25519Public,
  rawPublicFromEd25519Spki,
} from "./internal/der.js";
import type { Bytes32, Bytes64, KeyPair32 } from "./types.js";

function normalizeSignature(signature: Buffer): Bytes64 {
  if (signature.byteLength !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes, received ${signature.byteLength}`);
  }
  return asBytes64(
    new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength),
    "signature",
  );
}

/**
 * Builds a reusable Ed25519 private KeyObject from a raw 32-byte seed.
 */
export function createPrivateKeyObject(secretSeed32: Bytes32): KeyObject {
  assertBytes32(secretSeed32, "secretSeed32");
  return keyFromEd25519Private(secretSeed32);
}

/**
 * Builds a reusable Ed25519 public KeyObject from a raw 32-byte public key.
 */
export function createPublicKeyObject(publicKey32: Bytes32): KeyObject {
  assertBytes32(publicKey32, "publicKey32");
  return keyFromEd25519Public(publicKey32);
}

/**
 * Derives raw 32-byte Ed25519 public key from a private KeyObject.
 */
export function publicKeyFromPrivateKeyObject(privateKey: KeyObject): Bytes32 {
  return rawPublicFromEd25519Spki(createPublicKey(privateKey));
}

/**
 * Derives an Ed25519 public key from a raw 32-byte seed.
 */
export function publicKey(secretSeed32: Bytes32): Bytes32 {
  return publicKeyFromPrivateKeyObject(createPrivateKeyObject(secretSeed32));
}

/**
 * Deterministically creates an Ed25519 key pair from a 32-byte seed.
 * The private key returned is the original 32-byte seed.
 */
export function generateKeyPair(seed32: Bytes32): KeyPair32 {
  assertBytes32(seed32, "seed32");
  return {
    public: publicKey(seed32),
    private: seed32,
  };
}

/**
 * Signs a message with Ed25519 and returns the 64-byte detached signature.
 */
export function sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64 {
  return signWithPrivateKey(createPrivateKeyObject(secretSeed32), msg);
}

/**
 * Signs a message with Ed25519 using a reusable private KeyObject.
 */
export function signWithPrivateKey(privateKey: KeyObject, msg: Uint8Array): Bytes64 {
  assertUint8Array(msg, "msg");
  return normalizeSignature(cryptoSign(null, toBufferView(msg), privateKey));
}

/**
 * Verifies a detached Ed25519 signature.
 */
export function verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean {
  return verifyWithPublicKey(createPublicKeyObject(publicKey32), msg, signature64);
}

/**
 * Verifies a detached Ed25519 signature using a reusable public KeyObject.
 */
export function verifyWithPublicKey(
  publicKey: KeyObject,
  msg: Uint8Array,
  signature64: Bytes64,
): boolean {
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return cryptoVerify(null, toBufferView(msg), publicKey, toBufferView(signature64));
}

/**
 * Returns signature || message.
 */
export function signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array {
  assertBytes32(secretSeed32, "secretSeed32");
  assertUint8Array(msg, "msg");

  const signature = sign(secretSeed32, msg);
  const signed = new Uint8Array(64 + msg.byteLength);
  signed.set(signature, 0);
  signed.set(msg, 64);
  return signed;
}

/**
 * Verifies signature || message and returns a copy of the message if valid, else null.
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

  // Return a detached message copy to avoid retaining oversized parent buffers.
  return new Uint8Array(msg);
}
