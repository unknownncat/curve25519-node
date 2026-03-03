import {
  asBytes32,
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertUint8Array,
} from "./internal/assert.js";
import * as legacyAxlsign from "./internal/curve25519-legacy.js";
import type { Bytes32, Bytes64, KeyPair32 } from "./types.js";

interface LegacyCurve25519KeyPair {
  public: Uint8Array;
  private: Uint8Array;
}

interface LegacyCurve25519 {
  generateKeyPair(secret: Uint8Array): LegacyCurve25519KeyPair;
  sharedKey(secret: Uint8Array, publicKey: Uint8Array): Uint8Array;
  sign(secret: Uint8Array, msg: Uint8Array, optRandom?: Uint8Array): Uint8Array;
  verify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean;
  signMessage(secret: Uint8Array, msg: Uint8Array, optRandom?: Uint8Array): Uint8Array;
  openMessage(publicKey: Uint8Array, signedMsg: Uint8Array): Uint8Array | null;
}
const legacy = legacyAxlsign as LegacyCurve25519;

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
 * Derives an axlsign-compatible public key (Montgomery/X25519 format) in Node runtime.
 */
export function publicKey(secretKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  const out = legacy.generateKeyPair(secretKey32).public;
  return asBytes32(out, "axlsign public key");
}

/**
 * Computes an axlsign-compatible X25519 shared key.
 */
export function sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32 {
  assertBytes32(secretKey32, "secretKey32");
  assertBytes32(publicKey32, "publicKey32");
  const out = legacy.sharedKey(secretKey32, publicKey32);
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
      ? legacy.sign(secretKey32, msg)
      : legacy.sign(secretKey32, msg, opt_random);
  return asBytes64(signature, "axlsign signature");
}

/**
 * Verifies detached axlsign signature.
 */
export function verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean {
  assertBytes32(publicKey32, "publicKey32");
  assertUint8Array(msg, "msg");
  assertBytes64(signature64, "signature64");
  return legacy.verify(publicKey32, msg, signature64);
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

  // curve25519-js mutates input; keep API immutable by passing a defensive copy.
  const opened = legacy.openMessage(publicKey32, new Uint8Array(signedMsg));
  if (opened === null) {
    return null;
  }
  assertUint8Array(opened, "opened message");
  return new Uint8Array(opened);
}
