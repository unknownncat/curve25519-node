# @unknownncat/curve25519-node

> 🇧🇷 Versão em português (principal): [README.md](./README.md)

Zero-runtime-dependency implementation of:

- X25519 + Ed25519 (modern mode via OpenSSL in `node:crypto`)
- legacy axlsign (optional WASM mode, compatible with `curve25519-js`)

[![npm](https://img.shields.io/npm/v/@unknownncat/curve25519-node)](https://www.npmjs.com/package/@unknownncat/curve25519-node)
[![node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![types](https://img.shields.io/badge/types-included-blue)](./dist/index.d.ts)
![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![esm+cjs](https://img.shields.io/badge/ESM%20%2B%20CJS-compatible-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

- Node: `>= 20`
- Runtime dependencies: `0`
- TypeScript: `strict`
- Module formats: ESM + CJS

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

Legacy axlsign via WASM:

```ts
import { asBytes32, axlsign } from "@unknownncat/curve25519-node";

const seed = asBytes32(new Uint8Array(32));
const kp = axlsign.generateKeyPair(seed); // curve25519-js-compatible X25519 keypair
const sig = axlsign.sign(kp.private, new TextEncoder().encode("hello"), new Uint8Array(64));
const ok = axlsign.verify(kp.public, new TextEncoder().encode("hello"), sig);
```

---

## API

### `x25519`

- `createPrivateKeyObject(secretKey32: Bytes32): KeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): KeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: KeyObject): Bytes32`
- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKeyFromKeyObjects(privateKey: KeyObject, publicKey: KeyObject): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `sharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32` (rejects all-zero shared secret)
- `sharedKeyStrictFromKeyObjects(privateKey: KeyObject, publicKey: KeyObject): Bytes32` (rejects all-zero shared secret)
- `isAllZero32(bytes32: Bytes32): boolean`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`

### `ed25519`

- `createPrivateKeyObject(secretSeed32: Bytes32): KeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): KeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: KeyObject): Bytes32`
- `publicKey(secretSeed32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64`
- `signWithPrivateKey(privateKey: KeyObject, msg: Uint8Array): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `verifyWithPublicKey(publicKey: KeyObject, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array` (`signature || message`)
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### `axlsign` (legacy compatibility via WASM)

- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretKey32: Bytes32, msg: Uint8Array, opt_random?: Bytes64): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretKey32: Bytes32, msg: Uint8Array, opt_random?: Bytes64): Uint8Array`
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### Top-level compatibility aliases

- `sharedKey = x25519.sharedKey`
- `sharedKeyStrict = x25519.sharedKeyStrict`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (Ed25519 semantics)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

---

## Compatibility Notes

This package provides two modes:

- **modern (recommended):** `x25519` + `ed25519` via `node:crypto`
- **legacy:** `axlsign` via WASM for `curve25519-js` compatibility

| Feature                      | `curve25519-js` | `curve25519-node`                           |
| ---------------------------- | --------------- | ------------------------------------------- |
| Signature scheme (modern)    | axlsign         | Ed25519 (standard)                          |
| Signature scheme (legacy)    | axlsign         | axlsign (namespace `axlsign`)               |
| Key agreement                | X25519          | X25519                                      |
| Same key for signing + ECDH  | yes             | only in `axlsign` namespace                 |
| `opt_random` in signing APIs | yes             | yes in `axlsign`, no in top-level/`ed25519` |
| OpenSSL backend              | no              | yes                                         |

Important:

- X25519 public keys and Ed25519 public keys are different.
- For stricter protocol flows (Signal-like), prefer `sharedKeyStrict` to reject all-zero shared secrets.
- `node:crypto` does not expose an API to convert X25519 public keys to/from Ed25519 public keys.
- Top-level `sign`/`signMessage` and `ed25519` keep Ed25519 semantics and reject `opt_random`.
- For `curve25519-js` compatibility (including `opt_random`), use namespace `axlsign`.
- Ed25519 signatures here are deterministic (OpenSSL default behavior).
- The `axlsign` WASM module is lazy-loaded on first call (importing only `x25519`/`ed25519` does not initialize WASM).

---

## Why This Exists

`curve25519-js` is an important project, but it relies on manual finite-field arithmetic in JS (`Float64Array`, TweetNaCl style internals).

This package targets modern Node using OpenSSL primitives:

- safer implementation path by default
- better performance on Node >= 20
- smaller, explicit API surface
- strong typing with zero runtime dependencies

In addition, the WASM `axlsign` namespace enables progressive migration of legacy code without reintroducing manual curve arithmetic in JavaScript.

---

## Branded Types

- `Bytes32`
- `Bytes64`

Validation helpers (no copy):

- `asBytes32(u8)`
- `asBytes64(u8)`

---

## RFC Map (what this project uses)

| RFC                               | Sections used                                                                                                | How it is used                                                                                      | Where in code           |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- | ----------------------- |
| RFC 7748 (X25519)                 | Section 5 (`The X25519 and X448 Functions`)                                                                  | Scalar decoding/clamping and X25519 behavior (clear low 3 bits, clear top bit, set second-top bit). | `src/x25519.ts`         |
| RFC 7748 (X25519)                 | Section 5.2 (`Test Vectors`), Section 6.1 (`Diffie-Hellman / Curve25519`)                                    | Official vectors for interoperability and correctness checks.                                       | `test/x25519.test.mjs`  |
| RFC 8032 (Ed25519)                | Section 5.1.5 (`Key Generation`), 5.1.6 (`Sign`), 5.1.7 (`Verify`)                                           | Ed25519 keygen/sign/verify semantics (performed by OpenSSL via `node:crypto`).                      | `src/ed25519.ts`        |
| RFC 8032 (Ed25519)                | Section 7.1 (`Test Vectors for Ed25519`)                                                                     | Deterministic vector checks for public key and signature correctness.                               | `test/ed25519.test.mjs` |
| RFC 8410 (X25519/Ed25519 in PKIX) | Section 3 (algorithm identifiers), Section 4 (`Subject Public Key Fields`), Section 7 (`Private Key Format`) | DER layout for raw 32-byte key import/export to SPKI/PKCS#8 with X25519/Ed25519 OIDs.               | `src/internal/der.ts`   |

Indirect references via RFC 8410 structures:

- RFC 5958 (OneAsymmetricKey / PKCS#8 family)
- RFC 5280 Section 4.1.2.7 (`Subject Public Key Info`)

Notes:

- This project does not reimplement curve arithmetic in JS; cryptographic operations are delegated to OpenSSL via `node:crypto`.
- Tests include official vectors from RFC 7748 and RFC 8032.

Run tests:

```bash
npm test
```

---

## Technical Details (DER / RFC 8410)

Raw 32-byte keys are imported/exported using fixed DER prefixes:

- X25519 PKCS#8: `302e020100300506032b656e04220420`
- X25519 SPKI: `302a300506032b656e032100`
- Ed25519 PKCS#8: `302e020100300506032b657004220420`
- Ed25519 SPKI: `302a300506032b6570032100`

Implementation notes:

- preallocated buffers + `.set`
- zero-copy `Uint8Array` views when safe
- no `Buffer.concat` in hot paths

---

## Performance Notes

- Avoids unnecessary byte copies in critical paths.
- `signMessage` builds `signature || message` with a single preallocated `Uint8Array`.
- For high-throughput loops, use `KeyObject` helpers (`create*KeyObject`, `*FromKeyObjects`) to reduce ASN.1 parse overhead.

---

## Security Notes

- strict type/length validation on public APIs
- no secret logging
- `timingSafeEqual` for internal fixed-size comparisons where needed

---

## Benchmarks

Benchmark suite is isolated in `bench/` (separate subproject) and compares against `curve25519-js`.

```bash
npm run build
cd bench
npm install
npm run bench
```

### Real benchmark snapshot (`npm run bench:ci`) on GitHub Codespaces

Command:

```bash
node --expose-gc bench.mjs --rounds=16 --roundMs=350 --warmupMs=500 --vectors=64 --variants=raw,cached --strict --verifyEvery=64 --jsonFile=results/bench-results.json
```

Environment:

- Node: `v24.11.1`
- OpenSSL: `3.5.4`
- CPU: `AMD EPYC 7763 64-Core Processor`
- Logical cores: `4`
- Vectors: `64`

### Table 1 - Modern API (`x25519` + `ed25519`)

`sign`/`verify` rows below compare API throughput, not cryptographic equivalence (Ed25519 vs legacy axlsign).

| Operation                      | Modern raw | Legacy raw (`curve25519-js`) | Raw speedup | Modern cached | Legacy cached (`curve25519-js`) | Cached speedup |
| ------------------------------ | ---------: | ---------------------------: | ----------: | ------------: | ------------------------------: | -------------: |
| `x25519.generateKeyPair`       |     14,378 |                        1,591 |       9.04x |        41,120 |                           1,478 |         27.83x |
| `x25519.sharedKey`             |      9,970 |                        1,591 |       6.27x |        23,995 |                           1,554 |         15.44x |
| `ed25519.sign (msg32)`         |     11,273 |                          143 |      78.95x |        23,696 |                             133 |        178.10x |
| `ed25519.sign (msg1024)`       |     10,800 |                          138 |      78.07x |        22,502 |                             147 |        152.92x |
| `ed25519.verify (msg32)`       |      7,280 |                          136 |      53.36x |         8,271 |                             155 |         53.37x |
| `ed25519.verify (msg1024)`     |      7,160 |                          132 |      54.33x |         8,159 |                             154 |         52.90x |
| `ed25519.signMessage (msg256)` |     10,624 |                          131 |      81.09x |        23,304 |                             148 |        156.97x |
| `ed25519.openMessage (msg256)` |      6,574 |                          124 |      52.93x |         8,129 |                             154 |         52.64x |

### Table 2 - `axlsign` compatibility mode (equivalent to `curve25519-js`)

This table compares the same cryptographic scheme (equivalence + throughput).

| Operation                                 | Modern raw | Legacy raw (`curve25519-js`) | Raw speedup | Modern cached | Legacy cached (`curve25519-js`) | Cached speedup |
| ----------------------------------------- | ---------: | ---------------------------: | ----------: | ------------: | ------------------------------: | -------------: |
| `axlsign.generateKeyPair`                 |      8,429 |                        1,583 |       5.33x |         8,384 |                           1,585 |          5.29x |
| `axlsign.sharedKey`                       |      8,452 |                        1,583 |       5.34x |         8,396 |                           1,570 |          5.35x |
| `axlsign.sign (msg32)`                    |      3,973 |                          144 |      27.61x |         3,952 |                             140 |         28.28x |
| `axlsign.sign (msg32,opt_random)`         |      3,969 |                          147 |      27.03x |         3,984 |                             139 |         28.58x |
| `axlsign.sign (msg1024)`                  |      3,881 |                          143 |      27.16x |         3,864 |                             139 |         27.72x |
| `axlsign.verify (msg32)`                  |      6,527 |                          146 |      44.70x |         6,534 |                             143 |         45.72x |
| `axlsign.verify (msg32,opt_random)`       |      6,506 |                          144 |      45.07x |         6,469 |                             141 |         45.80x |
| `axlsign.verify (msg1024)`                |      6,361 |                          141 |      45.03x |         6,337 |                             135 |         46.92x |
| `axlsign.signMessage (msg256)`            |      3,902 |                          140 |      27.79x |         3,935 |                             141 |         27.98x |
| `axlsign.signMessage (msg256,opt_random)` |      3,885 |                          142 |      27.40x |         3,864 |                             145 |         26.60x |
| `axlsign.openMessage (msg256)`            |      6,441 |                          138 |      46.57x |         6,300 |                             131 |         47.93x |
| `axlsign.openMessage (msg256,opt_random)` |      6,362 |                          141 |      45.24x |         6,285 |                             130 |         48.22x |

Notes:

- `raw` includes end-to-end API cost.
- `cached` reduces setup overhead to better expose cryptographic throughput.
- Numbers are sourced from the `bench:ci` JSON output (`results/bench-results.json`).

---

## Building `axlsign`

In the npm package, WASM artifacts are already prebuilt under `dist/`.

To build from source, you need:

- Rust toolchain
- `wasm-pack` installed

Then `npm run build` runs:

1. `wasm-pack build` (`wasm/axlsign`)
2. TypeScript ESM + CJS build
3. copy of WASM artifacts to `dist/internal/axlsign-wasm`

---

## Contributing

- Guide: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Code of conduct: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](./SECURITY.md)

Full local validation:

```bash
npm run ci
```

---

## License

MIT

---

## Credits

- [curve25519-js](https://github.com/harveyconnor/curve25519-js) (Harvey Connor, Dmitry Chestnykh)
- [TweetNaCl.js](https://tweetnacl.js.org/)
- Trevor Perrin, Curve25519 signatures idea: <https://moderncrypto.org/mail-archive/curves/2014/000205.html>
- [Node.js `crypto` docs](https://nodejs.org/api/crypto.html)
- [OpenSSL](https://www.openssl.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)
- [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
