import { createPublicKey, diffieHellman } from "node:crypto";
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

/**
 * Derives an X25519 public key from a raw 32-byte secret scalar.
 */
export function publicKey(secretKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  const privateKey = keyFromX25519Private(secretKey32);
  return rawPublicFromX25519Spki(createPublicKey(privateKey));
}

/**
 * Computes X25519 ECDH shared secret (raw 32 bytes).
 */
export function sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  assertBytes32(publicKey32, "publicKey32");

  const shared = diffieHellman({
    privateKey: keyFromX25519Private(secretKey32),
    publicKey: keyFromX25519Public(publicKey32),
  });

  if (shared.byteLength !== 32) {
    throw new Error(`X25519 shared secret must be 32 bytes, received ${shared.byteLength}`);
  }
  return asBytes32(new Uint8Array(shared.buffer, shared.byteOffset, shared.byteLength), "sharedKey");
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
