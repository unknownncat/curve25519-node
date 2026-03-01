# @unknownncat/curve25519-node

> 🇧🇷 Versão em português (principal): [README.md](./README.md)

Zero-runtime-dependency implementation of:

- X25519 + Ed25519 (modern mode via OpenSSL in `node:crypto`)
- X25519 + Ed25519 (optional modern mode via WASM)
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

Modern WASM mode (`wasm`):

```ts
import { asBytes32, wasm } from "@unknownncat/curve25519-node";

const seed = asBytes32(new Uint8Array(32));
const kp = wasm.x25519.generateKeyPair(seed);
const shared = wasm.x25519.sharedKey(kp.private, kp.public);

const msg = new TextEncoder().encode("hello");
const sig = wasm.ed25519.sign(seed, msg);
const ok = wasm.ed25519.verify(wasm.ed25519.publicKey(seed), msg, sig);
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

### `wasm` (optional modern mode via WASM)

`wasm.x25519`:

- `createPrivateKeyObject(secretKey32: Bytes32): WasmX25519PrivateKeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): WasmX25519PublicKeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: WasmX25519PrivateKeyObject): Bytes32`
- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKeyFromKeyObjects(privateKey: WasmX25519PrivateKeyObject, publicKey: WasmX25519PublicKeyObject): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `sharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `sharedKeyStrictFromKeyObjects(privateKey: WasmX25519PrivateKeyObject, publicKey: WasmX25519PublicKeyObject): Bytes32`
- `isAllZero32(bytes32: Bytes32): boolean`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`

`wasm.ed25519`:

- `createPrivateKeyObject(secretSeed32: Bytes32): WasmEd25519PrivateKeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): WasmEd25519PublicKeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: WasmEd25519PrivateKeyObject): Bytes32`
- `publicKey(secretSeed32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64`
- `signWithPrivateKey(privateKey: WasmEd25519PrivateKeyObject, msg: Uint8Array): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `verifyWithPublicKey(publicKey: WasmEd25519PublicKeyObject, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array`
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### Top-level compatibility aliases

- `sharedKey = x25519.sharedKey`
- `sharedKeyStrict = x25519.sharedKeyStrict`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (Ed25519 semantics)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

---

## Compatibility Notes

This package provides three modes:

- **modern native (recommended):** `x25519` + `ed25519` via `node:crypto`
- **modern WASM (optional):** `wasm` namespace (`wasm.x25519` + `wasm.ed25519`)
- **legacy:** `axlsign` via WASM for `curve25519-js` compatibility

| Feature                          | `curve25519-js` | `curve25519-node`                           |
| -------------------------------- | --------------- | ------------------------------------------- |
| Signature scheme (modern)        | axlsign         | Ed25519 (standard)                          |
| Alternative modern scheme        | no              | Ed25519 via WASM (`wasm.ed25519`)           |
| Signature scheme (legacy)        | axlsign         | axlsign (namespace `axlsign`)               |
| Key agreement                    | X25519          | X25519                                      |
| Alternative modern key agreement | no              | X25519 via WASM (`wasm.x25519`)             |
| Same key for signing + ECDH      | yes             | only in `axlsign` namespace                 |
| `opt_random` in signing APIs     | yes             | yes in `axlsign`, no in top-level/`ed25519` |
| OpenSSL backend                  | no              | yes                                         |

Important:

- X25519 public keys and Ed25519 public keys are different.
- For stricter protocol flows (Signal-like), prefer `sharedKeyStrict` to reject all-zero shared secrets.
- `node:crypto` does not expose an API to convert X25519 public keys to/from Ed25519 public keys.
- Top-level `sign`/`signMessage` and `ed25519` keep Ed25519 semantics and reject `opt_random`.
- For `curve25519-js` compatibility (including `opt_random`), use namespace `axlsign`.
- Ed25519 signatures here are deterministic (OpenSSL default behavior).
- WASM modules (`axlsign` and `wasm`) are lazy-loaded on first call (importing only `x25519`/`ed25519` does not initialize WASM).

---

## Why This Exists

`curve25519-js` is an important project, but it relies on manual finite-field arithmetic in JS (`Float64Array`, TweetNaCl style internals).

This package targets modern Node using OpenSSL primitives:

- safer implementation path by default
- better performance on Node >= 20
- smaller, explicit API surface
- strong typing with zero runtime dependencies

In addition:

- WASM `axlsign` enables progressive migration of legacy code.
- WASM `wasm` provides a modern backend option without relying on `node:crypto` in the crypto execution path.

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

### Table 1 - Modern API (native + WASM)

`sign`/`verify` rows below compare API throughput, not cryptographic equivalence (Ed25519 vs legacy axlsign).

| Operation                           | Modern raw | Legacy raw (`curve25519-js`) | Raw speedup | Modern cached | Legacy cached (`curve25519-js`) | Cached speedup |
| ----------------------------------- | ---------: | ---------------------------: | ----------: | ------------: | ------------------------------: | -------------: |
| `x25519.generateKeyPair`            |     14,082 |                        1,579 |       8.92x |        49,035 |                           1,576 |         31.12x |
| `x25519.sharedKey`                  |     10,134 |                        1,568 |       6.46x |        25,423 |                           1,578 |         16.11x |
| `wasm.x25519.generateKeyPair`       |      8,415 |                        1,571 |       5.36x |         8,385 |                           1,574 |          5.33x |
| `wasm.x25519.sharedKey`             |      8,333 |                        1,577 |       5.28x |         8,350 |                           1,583 |          5.28x |
| `ed25519.sign (msg32)`              |     11,273 |                          142 |      79.56x |        23,886 |                             137 |        174.75x |
| `wasm.ed25519.sign (msg32)`         |      3,945 |                          142 |      27.80x |         3,956 |                             140 |         28.27x |
| `ed25519.sign (msg1024)`            |     10,759 |                          136 |      79.31x |        22,335 |                             138 |        162.38x |
| `wasm.ed25519.sign (msg1024)`       |      3,872 |                          137 |      28.27x |         3,873 |                             137 |         28.37x |
| `ed25519.verify (msg32)`            |      7,333 |                          142 |      51.65x |         8,186 |                             141 |         58.01x |
| `wasm.ed25519.verify (msg32)`       |      7,747 |                          141 |      54.84x |         7,629 |                             143 |         53.26x |
| `ed25519.verify (msg1024)`          |      7,241 |                          134 |      54.20x |         8,081 |                             136 |         59.35x |
| `wasm.ed25519.verify (msg1024)`     |      7,505 |                          135 |      55.76x |         7,480 |                             134 |         55.66x |
| `ed25519.signMessage (msg256)`      |     10,859 |                          140 |      77.67x |        23,607 |                             132 |        178.57x |
| `wasm.ed25519.signMessage (msg256)` |      3,888 |                          139 |      27.99x |         3,867 |                             137 |         28.23x |
| `ed25519.openMessage (msg256)`      |      7,113 |                          145 |      49.03x |         8,012 |                             141 |         56.96x |
| `wasm.ed25519.openMessage (msg256)` |      7,428 |                          137 |      54.26x |         7,476 |                             137 |         54.74x |

### Table 2 - `axlsign` compatibility mode (equivalent to `curve25519-js`)

This table compares the same cryptographic scheme (equivalence + throughput).

| Operation                                 | Modern raw | Legacy raw (`curve25519-js`) | Raw speedup | Modern cached | Legacy cached (`curve25519-js`) | Cached speedup |
| ----------------------------------------- | ---------: | ---------------------------: | ----------: | ------------: | ------------------------------: | -------------: |
| `axlsign.generateKeyPair`                 |      8,382 |                        1,571 |       5.34x |         8,357 |                           1,579 |          5.29x |
| `axlsign.sharedKey`                       |      8,361 |                        1,583 |       5.28x |         8,422 |                           1,564 |          5.39x |
| `axlsign.sign (msg32)`                    |      4,010 |                          140 |      28.59x |         3,970 |                             141 |         28.10x |
| `axlsign.sign (msg32,opt_random)`         |      4,000 |                          142 |      28.07x |         3,965 |                             136 |         29.08x |
| `axlsign.sign (msg1024)`                  |      3,883 |                          138 |      28.17x |         3,878 |                             138 |         28.03x |
| `axlsign.verify (msg32)`                  |      6,604 |                          144 |      45.83x |         6,585 |                             143 |         46.17x |
| `axlsign.verify (msg32,opt_random)`       |      6,531 |                          143 |      45.69x |         6,527 |                             142 |         46.08x |
| `axlsign.verify (msg1024)`                |      6,428 |                          138 |      46.47x |         6,377 |                             136 |         46.82x |
| `axlsign.signMessage (msg256)`            |      3,913 |                          140 |      27.85x |         3,935 |                             136 |         28.92x |
| `axlsign.signMessage (msg256,opt_random)` |      3,941 |                          139 |      28.39x |         3,878 |                             139 |         27.93x |
| `axlsign.openMessage (msg256)`            |      6,440 |                          138 |      46.78x |         6,407 |                             136 |         47.18x |
| `axlsign.openMessage (msg256,opt_random)` |      6,513 |                          134 |      48.53x |         6,431 |                             133 |         48.19x |

Notes:

- `raw` includes end-to-end API cost.
- `cached` reduces setup overhead to better expose cryptographic throughput.
- Numbers are sourced from the `bench:ci` JSON output (`results/bench-results.json`).

---

## Building WASM namespaces (`axlsign` and `wasm`)

In the npm package, WASM artifacts are already prebuilt under `dist/`.

To build from source, you need:

- Rust toolchain
- `wasm-pack` installed

Then `npm run build` runs:

1. `wasm-pack build` (`wasm/axlsign`)
2. `wasm-pack build` (`wasm/curve25519-wasm`)
3. TypeScript ESM + CJS build
4. copy of WASM artifacts to `dist/internal/axlsign-wasm` and `dist/internal/curve25519-wasm`

Rust crates reference: [wasm/README.md](./wasm/README.md)

---

## Contributing

- Guide: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Code of conduct: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](./SECURITY.md)

Full local validation:

```bash
npm run ci
```

Extra robustness/supply-chain checks:

```bash
npm run audit
npm run audit:prod
npm run release:check
```

---

## License

MIT

Additional compliance/security documents:

- [NOTICE.md](./NOTICE.md) (canonical third-party notice)
- [THIRD_PARTY_NOTICE.md](./THIRD_PARTY_NOTICE.md) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) (compatibility aliases)
- [SECURITY.md](./SECURITY.md) (security policy and vulnerability reporting)

---

## Credits

- [curve25519-js](https://github.com/harveyconnor/curve25519-js) (Harvey Connor, Dmitry Chestnykh)
- [TweetNaCl.js](https://tweetnacl.js.org/)
- Trevor Perrin, Curve25519 signatures idea: <https://moderncrypto.org/mail-archive/curves/2014/000205.html>
- [Node.js `crypto` docs](https://nodejs.org/api/crypto.html)
- [OpenSSL](https://www.openssl.org/)
- [RustCrypto](https://github.com/RustCrypto)
- [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen)
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
- [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek)
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)
- [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
