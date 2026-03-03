import type { Bytes32, Bytes64 } from "../types.js";

export function assertUint8Array(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    const actual = value === null ? "null" : typeof value;
    throw new TypeError(`${name} must be a Uint8Array, received ${actual}`);
  }
}

function assertLength(value: Uint8Array, expected: number, name: string): void {
  if (value.byteLength !== expected) {
    throw new RangeError(`${name} must be ${expected} bytes, received ${value.byteLength}`);
  }
}

export function assertBytes32(value: Uint8Array, name = "value"): asserts value is Bytes32 {
  assertUint8Array(value, name);
  assertLength(value, 32, name);
}

export function assertBytes64(value: Uint8Array, name = "value"): asserts value is Bytes64 {
  assertUint8Array(value, name);
  assertLength(value, 64, name);
}

export function asBytes32(value: Uint8Array, name = "value"): Bytes32 {
  assertBytes32(value, name);
  return value;
}

export function asBytes64(value: Uint8Array, name = "value"): Bytes64 {
  assertBytes64(value, name);
  return value;
}

export function assertNoOptRandom(optRandom: unknown, fnName: string): void {
  if (optRandom !== undefined) {
    throw new Error(
      `${fnName} does not support opt_random with Ed25519. ` +
        "Remove the third argument and use deterministic Ed25519 signing.",
    );
  }
}
