export {
  asBytes32,
  asBytes64,
  assertBytes32,
  assertBytes64,
  assertNoOptRandom,
  assertUint8Array,
} from "@unknownncat/curve25519-core";

export function toBufferView(value: Uint8Array): Buffer {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}
