import { createPrivateKey, createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import type { Bytes32 } from "../types.js";
import { asBytes32, assertBytes32 } from "./assert.js";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function appendRaw32(prefix: Buffer, raw32: Uint8Array, inputName: string): Buffer {
  assertBytes32(raw32, inputName);
  const out = Buffer.allocUnsafe(prefix.length + 32);
  out.set(prefix, 0);
  out.set(raw32, prefix.length);
  return out;
}

export function derPkcs8(prefix: Buffer, raw32: Uint8Array): Buffer {
  return appendRaw32(prefix, raw32, "raw private key");
}

export function derSpki(prefix: Buffer, raw32: Uint8Array): Buffer {
  return appendRaw32(prefix, raw32, "raw public key");
}

export function keyFromX25519Private(raw32: Bytes32): KeyObject {
  return createPrivateKey({
    key: derPkcs8(X25519_PKCS8_PREFIX, raw32),
    format: "der",
    type: "pkcs8",
  });
}

export function keyFromX25519Public(raw32: Bytes32): KeyObject {
  return createPublicKey({
    key: derSpki(X25519_SPKI_PREFIX, raw32),
    format: "der",
    type: "spki",
  });
}

export function keyFromEd25519Private(seed32: Bytes32): KeyObject {
  return createPrivateKey({
    key: derPkcs8(ED25519_PKCS8_PREFIX, seed32),
    format: "der",
    type: "pkcs8",
  });
}

export function keyFromEd25519Public(raw32: Bytes32): KeyObject {
  return createPublicKey({
    key: derSpki(ED25519_SPKI_PREFIX, raw32),
    format: "der",
    type: "spki",
  });
}

function rawPublicFromSpki(keyObject: KeyObject, prefix: Buffer, label: string): Bytes32 {
  const der = keyObject.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(der)) {
    throw new TypeError(`${label} SPKI export must be a Buffer`);
  }
  if (der.byteLength !== prefix.length + 32) {
    throw new Error(`${label} SPKI DER length mismatch`);
  }

  const exportedPrefix = der.subarray(0, prefix.length);
  if (!timingSafeEqual(exportedPrefix, prefix)) {
    throw new Error(`${label} SPKI DER prefix mismatch`);
  }

  const raw = new Uint8Array(der.buffer, der.byteOffset + prefix.length, 32);
  return asBytes32(raw, `${label} public key`);
}

export function rawPublicFromX25519Spki(keyObject: KeyObject): Bytes32 {
  return rawPublicFromSpki(keyObject, X25519_SPKI_PREFIX, "X25519");
}

export function rawPublicFromEd25519Spki(keyObject: KeyObject): Bytes32 {
  return rawPublicFromSpki(keyObject, ED25519_SPKI_PREFIX, "Ed25519");
}
