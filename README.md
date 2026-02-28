# @unknownncat/curve25519-node

[![npm](https://img.shields.io/npm/v/@unknownncat/curve25519-node)](https://www.npmjs.com/package/@unknownncat/curve25519-node)
[![downloads](https://img.shields.io/badge/downloads-new%20package-lightgrey)](https://www.npmjs.com/package/@unknownncat/curve25519-node)
[![types](https://img.shields.io/badge/types-included-blue)](./dist/index.d.ts)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![esm+cjs](https://img.shields.io/badge/ESM%20%2B%20CJS-compatible-blue)

Modern **zero-dependency** X25519 + Ed25519 for Node.js using OpenSSL via `node:crypto`.

- **Node:** `>= 20`
- **Runtime deps:** `0`
- **TypeScript:** `strict`, **ESM-first**
- **Compat:** ESM + CJS (`import` e `require`)

---

## Why

O projeto original ([curve25519-js](https://github.com/harveyconnor/curve25519-js)) fazia aritmética de campo manual (loops extensos BigInt/Float64) para Curve25519/Ed25519.

Este pacote troca isso por primitivas nativas do OpenSSL (via `node:crypto`), com foco em:

- **segurança** por implementação consolidada
- **performance** melhor em Node moderno
- **API pequena** e **bem tipada**

---

## Compatibility notes (importante)

Este pacote **não replica o esquema `axlsign`** do `curve25519-js`.

Aqui a API é **padrão moderna**:

- acordo de chave: **X25519**
- assinatura: **Ed25519**

Consequências:

- Chaves de X25519 e Ed25519 são **diferentes** (public keys diferentes).
- `sign`/`verify` usam chaves **Ed25519**.
- Conversão X25519 public key ↔ Ed25519 public key **não é exposta** por `node:crypto`.
- `opt_random` (64 bytes) do legado **não é suportado** em Ed25519 com `node:crypto`.
  - O compat layer aceita um 3º argumento apenas por compatibilidade de chamada, mas **sempre lança erro** se ele for fornecido.

---

## Install

```bash
npm i @unknownncat/curve25519-node
```

---

## Usage

### ESM (TypeScript / Node moderno)

```ts
import {
  asBytes32,
  x25519,
  ed25519,
  sign, // compat top-level (Ed25519)
  verify, // compat top-level (Ed25519)
} from "@unknownncat/curve25519-node";

const aliceSeed = asBytes32(crypto.getRandomValues(new Uint8Array(32)));
const bobSeed = asBytes32(crypto.getRandomValues(new Uint8Array(32)));

const aliceX = x25519.generateKeyPair(aliceSeed);
const bobX = x25519.generateKeyPair(bobSeed);

const s1 = x25519.sharedKey(aliceX.private, bobX.public);
const s2 = x25519.sharedKey(bobX.private, aliceX.public);
// s1 e s2 devem ser iguais

const signerSeed = asBytes32(crypto.getRandomValues(new Uint8Array(32)));
const ed = ed25519.generateKeyPair(signerSeed);

const msg = new TextEncoder().encode("hello");

const sig = ed25519.sign(signerSeed, msg);
const ok = verify(ed.public, msg, sig);

const signedMsg = ed25519.signMessage(signerSeed, msg);
const opened = ed25519.openMessage(ed.public, signedMsg);
```

### CommonJS

```js
const { x25519, ed25519, asBytes32 } = require("@unknownncat/curve25519-node");

const seed = asBytes32(new Uint8Array(32));
const kp = x25519.generateKeyPair(seed);

const sig = ed25519.sign(seed, Buffer.from("hello"));
```

### Subpath imports (opcional)

```ts
import { x25519 } from "@unknownncat/curve25519-node/x25519";
import { ed25519 } from "@unknownncat/curve25519-node/ed25519";
import { asBytes32, asBytes64 } from "@unknownncat/curve25519-node/types";
```

---

## API

### Namespace `x25519`

- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`

### Namespace `ed25519`

- `publicKey(secretSeed32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretSeed32: Bytes32, msg: Uint8Array): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array`
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### Top-level compat layer

- `sharedKey = x25519.sharedKey`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (**Ed25519**)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

> `sign` e `signMessage` aceitam um terceiro argumento opcional **apenas para compatibilidade de chamada**, mas **sempre lançam erro** se ele for fornecido (`opt_random` legado não suportado).

---

## Branded types

- `Bytes32`
- `Bytes64`

Helpers:

- `asBytes32(u8)`
- `asBytes64(u8)`

✅ Os helpers validam tamanho e retornam o **mesmo objeto** (sem cópia).

---

## Technical details (RFC 8410 DER)

Prefixos usados para importar/exportar RAW(32) ↔ `KeyObject` via DER prealocado:

- X25519 PKCS#8 prefix: `302e020100300506032b656e04220420`
- X25519 SPKI prefix: `302a300506032b656e032100`
- Ed25519 PKCS#8 prefix: `302e020100300506032b657004220420`
- Ed25519 SPKI prefix: `302a300506032b6570032100`

As operações usam buffers DER prealocados + `.set`, sem loops byte-a-byte.

---

## Performance notes

- Sem `Buffer.concat` no hot path; buffers montados por prealloc + `.set`.
- `Uint8Array` → `Buffer` usa view zero-copy:
  - `Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength)`

- `signMessage` monta `signature || msg` com `Uint8Array` prealocado e `.set`.
- Para throughput máximo em loops longos, considere cachear `KeyObject` no nível da aplicação (evita parse ASN.1 repetido).

---

## Security

- Validação de tipo/tamanho em todas as entradas públicas.
- Sem logs de segredo.
- Comparações internas de DER prefix usam `timingSafeEqual`.

---

## Tests

```bash
npm test
```

Cobertura inclui vetores RFC:

- X25519: RFC 7748
- Ed25519: RFC 8032

---

## License

MIT © unknownncat — veja [LICENSE](./LICENSE)

---

## Thanks

❤️ [curve25519-js](https://github.com/harveyconnor/curve25519-js)
