# unknownncat-curve25519-node

Reimplementacao moderna de [curve25519-js](https://github.com/harveyconnor/curve25519-js) usando somente `node:crypto` (OpenSSL), sem dependencias de runtime.

- Node: `>= 20`
- Runtime deps: `0`
- Linguagem: TypeScript strict, ESM-first
- Compat: ESM + CJS (`import` e `require`)

## Motivacao

O projeto original fazia aritmetica de campo manual (BigInt/Float64 loops extensos) para Curve25519/Ed25519.
Este pacote troca isso por primitivas nativas do OpenSSL via `node:crypto`, com foco em:

- seguranca por implementacao consolidada
- performance melhor em Node moderno
- API pequena e tipada

## Compat Notes

Este pacote **nao replica o esquema axlsign** do [curve25519-js](https://github.com/harveyconnor/curve25519-js).

- Original: usava chaves Curve25519/X25519 para assinar via conversoes Montgomery <-> Edwards e bit de sinal.
- Aqui: API **padrao moderna**:
  - acordo de chave: **X25519**
  - assinatura: **Ed25519**

Consequencias importantes:

- Chaves de X25519 e Ed25519 sao diferentes (public keys diferentes).
- `sign`/`verify` usam chaves **Ed25519**.
- Conversao X25519 public key <-> Ed25519 public key nao e exposta por `node:crypto`.
- `opt_random` (64 bytes) do legado nao e suportado em Ed25519 com `node:crypto`; o compat layer lanca erro explicito.

## Instalacao

```bash
npm install
npm run build
```

## Uso

```ts
import {
  asBytes32,
  x25519,
  ed25519,
  sign, // compat top-level (Ed25519)
  verify, // compat top-level (Ed25519)
} from "unknownncat-curve25519-node";

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

### Uso em CommonJS

```js
const { x25519, ed25519, asBytes32 } = require("unknownncat-curve25519-node");

const seed = asBytes32(new Uint8Array(32));
const kp = x25519.generateKeyPair(seed);
const sig = ed25519.sign(seed, Buffer.from("hello"));
```

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
- `sign`, `verify`, `signMessage`, `openMessage` (Ed25519)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

`sign` e `signMessage` aceitam um terceiro argumento opcional apenas para compatibilidade de chamada, mas **sempre** lancam erro se ele for fornecido (`opt_random` legado nao suportado).

## Tipos branded

- `Bytes32`
- `Bytes64`
- helpers:
  - `asBytes32(u8)`
  - `asBytes64(u8)`

Os helpers validam tamanho e retornam o mesmo objeto (sem copia).

## Detalhes Tecnicos (RFC 8410 DER)

- X25519 PKCS#8 prefix: `302e020100300506032b656e04220420`
- X25519 SPKI prefix: `302a300506032b656e032100`
- Ed25519 PKCS#8 prefix: `302e020100300506032b657004220420`
- Ed25519 SPKI prefix: `302a300506032b6570032100`

As operacoes de import/export RAW(32) <-> `KeyObject` usam DER prealocado + `set`, sem loops byte-a-byte.

## Performance

- Sem `Buffer.concat` em hot path; buffers DER sao montados por prealloc + `.set`.
- `Uint8Array` -> `Buffer` usa view zero-copy (`Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength)`).
- `signMessage` monta `signature || msg` com `Uint8Array` prealocado e `set`.
- Para throughput maximo em loops longos, considere cachear `KeyObject` no nivel da aplicacao (evita parse ASN.1 repetido).

## Seguranca

- Validacao de tipo/tamanho em todas as entradas publicas.
- Sem logs de segredo.
- Comparacoes internas de DER prefix usam `timingSafeEqual`.

## Testes

```bash
npm test
```

Cobertura inclui vetores RFC:

- X25519: RFC 7748
- Ed25519: RFC 8032

# Tanks

❤️[curve25519-js](https://github.com/harveyconnor/curve25519-js)
