import { assertNoOptRandom, assertUint8Array } from "./internal/assert.js";
import * as axlsignApi from "./axlsign.js";
import * as wasmApi from "./wasm.js";
import { initWasm, isWasmInitialized } from "./internal/wasm-runtime.js";
import type { Bytes32, Bytes64 } from "./types.js";

export { asBytes32, asBytes64, assertBytes32, assertBytes64 } from "./internal/assert.js";
export type { Bytes32, Bytes64, KeyPair32 } from "./types.js";
export type { WasmInitOptions } from "./internal/wasm-runtime.js";
export { initWasm, isWasmInitialized };

export const x25519 = wasmApi.x25519;

export const ed25519 = wasmApi.ed25519;

export const axlsign = {
  publicKey: axlsignApi.publicKey,
  sharedKey: axlsignApi.sharedKey,
  generateKeyPair: axlsignApi.generateKeyPair,
  sign: axlsignApi.sign,
  verify: axlsignApi.verify,
  signMessage: axlsignApi.signMessage,
  openMessage: axlsignApi.openMessage,
} as const;

export const wasm = {
  x25519: wasmApi.x25519,
  ed25519: wasmApi.ed25519,
} as const;

export const sharedKey = x25519.sharedKey;
export const sharedKeyStrict = x25519.sharedKeyStrict;
export const generateKeyPair = x25519.generateKeyPair;
export const generateKeyPairX25519 = x25519.generateKeyPair;
export const generateKeyPairEd25519 = ed25519.generateKeyPair;

export function sign(secretSeed32: Bytes32, msg: Uint8Array, opt_random?: Uint8Array): Bytes64 {
  assertUint8Array(msg, "msg");
  assertNoOptRandom(opt_random, "sign");
  return ed25519.sign(secretSeed32, msg);
}

export function signMessage(
  secretSeed32: Bytes32,
  msg: Uint8Array,
  opt_random?: Uint8Array,
): Uint8Array {
  assertUint8Array(msg, "msg");
  assertNoOptRandom(opt_random, "signMessage");
  return ed25519.signMessage(secretSeed32, msg);
}

export const openMessage = ed25519.openMessage;
export const verify = ed25519.verify;

const api = {
  initWasm,
  isWasmInitialized,
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
