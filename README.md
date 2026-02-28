# @unknownncat/curve25519-node

Modern zero-dependency X25519 + Ed25519 for Node.js using OpenSSL via `node:crypto`.

[![npm](https://img.shields.io/npm/v/@unknownncat/curve25519-node)](https://www.npmjs.com/package/@unknownncat/curve25519-node)
[![node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![types](https://img.shields.io/badge/types-included-blue)](./dist/index.d.ts)
![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![esm+cjs](https://img.shields.io/badge/ESM%20%2B%20CJS-compatible-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

- Node: `>= 20`
- Runtime deps: `0`
- TypeScript: strict
- Module format: ESM + CJS

---

## Install

```bash
npm i @unknownncat/curve25519-node
```

---

## Quick Usage

```ts
import { randomBytes } from "node:crypto";
import { asBytes32, x25519, ed25519 } from "@unknownncat/curve25519-node";

const aliceSeed = asBytes32(randomBytes(32));
const bobSeed = asBytes32(randomBytes(32));

const aliceX = x25519.generateKeyPair(aliceSeed);
const bobX = x25519.generateKeyPair(bobSeed);

const secret1 = x25519.sharedKey(aliceX.private, bobX.public);
const secret2 = x25519.sharedKey(bobX.private, aliceX.public);
// secret1 === secret2

const signerSeed = asBytes32(randomBytes(32));
const signer = ed25519.generateKeyPair(signerSeed);
const msg = new TextEncoder().encode("hello");

const sig = ed25519.sign(signerSeed, msg);
const ok = ed25519.verify(signer.public, msg, sig);
```

CommonJS:

```js
const { x25519, ed25519, asBytes32 } = require("@unknownncat/curve25519-node");
```

---

## API

### `x25519`

- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`

### `ed25519`

- `publicKey(secretSeed32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array` (`signature || message`)
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### Top-level compat aliases

- `sharedKey = x25519.sharedKey`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (Ed25519 semantics)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

---

## Compatibility Notes

This package does **not** implement `axlsign` from `curve25519-js`.

It follows standard split usage:

- key agreement: **X25519**
- signatures: **Ed25519**

| Feature                   | curve25519-js | curve25519-node    |
| ------------------------- | ------------- | ------------------ |
| Signing scheme            | axlsign       | Ed25519 (standard) |
| Key agreement             | X25519        | X25519             |
| Same key for sign + ECDH  | sim           | não                |
| `opt_random` in sign APIs | sim           | não                |
| OpenSSL backend           | não           | sim                |

Important:

- X25519 public keys and Ed25519 public keys are different.
- `node:crypto` does not expose X25519 public key ↔ Ed25519 public key conversion APIs.
- `sign`/`signMessage` keep a 3rd optional argument only for call-shape compatibility, but throw if provided (`opt_random` unsupported).
- Ed25519 signatures here are deterministic (OpenSSL default).

---

## Why This Exists

`curve25519-js` is a good project, but it uses manual finite-field arithmetic in JS (`Float64Array`, TweetNaCl-style internals).

This package targets modern Node with OpenSSL primitives:

- safer default implementation path
- faster operations in Node >= 20
- smaller, explicit API surface
- strict typing and zero runtime dependencies

---

## Branded Types

- `Bytes32`
- `Bytes64`

Helpers (validation without copy):

- `asBytes32(u8)`
- `asBytes64(u8)`

---

## RFC Coverage

Test vectors included for:

- **RFC 7748** (X25519)
- **RFC 8032** (Ed25519)

Run:

```bash
npm test
```

---

## Technical Details (RFC 8410 DER)

Raw 32-byte keys are imported/exported via DER with fixed prefixes:

- X25519 PKCS#8: `302e020100300506032b656e04220420`
- X25519 SPKI: `302a300506032b656e032100`
- Ed25519 PKCS#8: `302e020100300506032b657004220420`
- Ed25519 SPKI: `302a300506032b6570032100`

Implementation notes:

- preallocated buffers + `.set`
- zero-copy `Uint8Array` views where safe
- no `Buffer.concat` in hot paths

---

## Performance Notes

- Avoids unnecessary byte copies in critical paths.
- `signMessage` builds `signature || message` using one preallocated `Uint8Array`.
- For high-throughput loops, caching `KeyObject` in application code can reduce ASN.1 parse overhead.

---

## Security Notes

- strict type/length validation on public APIs
- no secret logging
- `timingSafeEqual` used where fixed-byte comparisons are needed internally

---

## Benchmarks

Benchmark suite is isolated in `bench/` (separate subproject) and compares against `curve25519-js`.

```bash
npm run build
cd bench
npm install
npm run bench
```

---

## License

MIT

---

## Credits

- [curve25519-js](https://github.com/harveyconnor/curve25519-js)
- TweetNaCl
- OpenSSL
- RFC 7748 / RFC 8032
