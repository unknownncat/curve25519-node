import { assertNoOptRandom, assertUint8Array } from "./internal/assert.js";
import * as axlsignApi from "./axlsign.js";
import * as wasmApi from "./wasm.js";
import * as ed25519Api from "./ed25519.js";
import * as x25519Api from "./x25519.js";
import type { Bytes32, Bytes64 } from "./types.js";

export { asBytes32, asBytes64, assertBytes32, assertBytes64 } from "./internal/assert.js";
export type { Bytes32, Bytes64, KeyPair32 } from "./types.js";

/**
 * Standard X25519 namespace.
 */
export const x25519 = {
  createPrivateKeyObject: x25519Api.createPrivateKeyObject,
  createPublicKeyObject: x25519Api.createPublicKeyObject,
  publicKeyFromPrivateKeyObject: x25519Api.publicKeyFromPrivateKeyObject,
  publicKey: x25519Api.publicKey,
  sharedKey: x25519Api.sharedKey,
  sharedKeyFromKeyObjects: x25519Api.sharedKeyFromKeyObjects,
  sharedKeyStrict: x25519Api.sharedKeyStrict,
  sharedKeyStrictFromKeyObjects: x25519Api.sharedKeyStrictFromKeyObjects,
  isAllZero32: x25519Api.isAllZero32,
  generateKeyPair: x25519Api.generateKeyPair,
} as const;

/**
 * Standard Ed25519 namespace.
 */
export const ed25519 = {
  createPrivateKeyObject: ed25519Api.createPrivateKeyObject,
  createPublicKeyObject: ed25519Api.createPublicKeyObject,
  publicKeyFromPrivateKeyObject: ed25519Api.publicKeyFromPrivateKeyObject,
  publicKey: ed25519Api.publicKey,
  generateKeyPair: ed25519Api.generateKeyPair,
  sign: ed25519Api.sign,
  signWithPrivateKey: ed25519Api.signWithPrivateKey,
  verify: ed25519Api.verify,
  verifyWithPublicKey: ed25519Api.verifyWithPublicKey,
  signMessage: ed25519Api.signMessage,
  openMessage: ed25519Api.openMessage,
} as const;

/**
 * Optional legacy-compatible axlsign namespace implemented with WASM.
 */
export const axlsign = {
  publicKey: axlsignApi.publicKey,
  sharedKey: axlsignApi.sharedKey,
  generateKeyPair: axlsignApi.generateKeyPair,
  sign: axlsignApi.sign,
  verify: axlsignApi.verify,
  signMessage: axlsignApi.signMessage,
  openMessage: axlsignApi.openMessage,
} as const;

/**
 * Optional modern WASM namespace with X25519 + Ed25519 parity methods.
 */
export const wasm = {
  x25519: wasmApi.x25519,
  ed25519: wasmApi.ed25519,
} as const;

/**
 * Top-level compatibility alias for X25519 shared secret.
 */
export const sharedKey = x25519.sharedKey;

/**
 * Top-level strict X25519 shared secret helper that rejects all-zero results.
 */
export const sharedKeyStrict = x25519.sharedKeyStrict;

/**
 * Top-level compatibility alias for X25519 deterministic key generation.
 */
export const generateKeyPair = x25519.generateKeyPair;

/**
 * Explicit X25519 key generation helper.
 */
export const generateKeyPairX25519 = x25519.generateKeyPair;

/**
 * Explicit Ed25519 key generation helper.
 */
export const generateKeyPairEd25519 = ed25519.generateKeyPair;

/**
 * Compatibility wrapper for Ed25519 detached signing.
 * opt_random from legacy curve25519-js/axlsign is intentionally unsupported.
 */
export function sign(secretSeed32: Bytes32, msg: Uint8Array, opt_random?: Uint8Array): Bytes64 {
  assertUint8Array(msg, "msg");
  assertNoOptRandom(opt_random, "sign");
  return ed25519.sign(secretSeed32, msg);
}

/**
 * Compatibility wrapper for Ed25519 signed-message mode.
 * opt_random from legacy curve25519-js/axlsign is intentionally unsupported.
 */
export function signMessage(
  secretSeed32: Bytes32,
  msg: Uint8Array,
  opt_random?: Uint8Array,
): Uint8Array {
  assertUint8Array(msg, "msg");
  assertNoOptRandom(opt_random, "signMessage");
  return ed25519.signMessage(secretSeed32, msg);
}

/**
 * Top-level compatibility alias for signed-message verification/open.
 */
export const openMessage = ed25519.openMessage;

/**
 * Top-level compatibility alias for detached signature verification.
 */
export const verify = ed25519.verify;

const api = {
  x25519,
  ed25519,
  axlsign,
  wasm,
  sharedKey,
  sharedKeyStrict,
  generateKeyPair,
  generateKeyPairX25519,
  generateKeyPairEd25519,
  sign,
  signMessage,
  openMessage,
  verify,
} as const;

export default api;
