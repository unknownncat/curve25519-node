import assert from "node:assert/strict";
import test from "node:test";
import {
  asBytes32,
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertNoOptRandom,
  assertUint8Array,
} from "../dist/index.js";

test("assertUint8Array and byte-length guards validate inputs", () => {
  const bytes32 = new Uint8Array(32);
  const bytes64 = new Uint8Array(64);

  assert.doesNotThrow(() => assertUint8Array(bytes32, "bytes32"));
  assert.doesNotThrow(() => assertBytes32(bytes32, "bytes32"));
  assert.doesNotThrow(() => assertBytes64(bytes64, "bytes64"));

  assert.throws(() => assertUint8Array("not-bytes", "value"), /Uint8Array/);
  assert.throws(() => assertBytes32(new Uint8Array(31), "bytes32"), /32 bytes/);
  assert.throws(() => assertBytes64(new Uint8Array(63), "bytes64"), /64 bytes/);
});

test("asBytes helpers keep reference and assertNoOptRandom enforces deterministic mode", () => {
  const bytes32 = new Uint8Array(32);
  const bytes64 = new Uint8Array(64);

  assert.strictEqual(asBytes32(bytes32), bytes32);
  assert.strictEqual(asBytes64(bytes64), bytes64);

  assert.doesNotThrow(() => assertNoOptRandom(undefined, "sign"));
  assert.throws(() => assertNoOptRandom(new Uint8Array(64), "sign"), /does not support opt_random/);
});
