import { createHash } from "node:crypto";

export function deterministicBytes(seed, length) {
  const out = new Uint8Array(length);
  let ctr = 0;
  let offset = 0;
  while (offset < length) {
    const block = createHash("sha256").update(seed).update(String(ctr)).digest();
    const write = Math.min(block.length, length - offset);
    out.set(block.subarray(0, write), offset);
    offset += write;
    ctr += 1;
  }
  return out;
}

export function buildInputPool(count) {
  const vectorCount = Math.max(64, Math.floor(count));
  const seeds = [];
  const msg32 = [];
  const msg256 = [];
  const msg1024 = [];
  const rnd64 = [];

  for (let i = 0; i < vectorCount; i += 1) {
    seeds.push(deterministicBytes(`seed-${i}`, 32));
    msg32.push(deterministicBytes(`msg32-${i}`, 32));
    msg256.push(deterministicBytes(`msg256-${i}`, 256));
    msg1024.push(deterministicBytes(`msg1024-${i}`, 1024));
    rnd64.push(deterministicBytes(`rnd64-${i}`, 64));
  }

  return {
    vectorCount,
    seeds,
    msg32,
    msg256,
    msg1024,
    rnd64,
  };
}

export function createCycler(items) {
  let index = 0;
  return () => {
    const position = index;
    const value = items[position];
    index = (index + 1) % items.length;
    return {
      value,
      index: position,
    };
  };
}

export function copyU8(value) {
  return new Uint8Array(value);
}

export function maybeCopyU8(value, shouldCopy) {
  return shouldCopy ? copyU8(value) : value;
}
