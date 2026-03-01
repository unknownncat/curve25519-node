# @unknownncat/curve25519-node

> 🇺🇸 English version: [README.en.md](./README.en.md)

Implementação sem dependências de runtime de:

- X25519 + Ed25519 (modo moderno via OpenSSL em `node:crypto`)
- axlsign legado (modo opcional via WASM, compatível com `curve25519-js`)

[![npm](https://img.shields.io/npm/v/@unknownncat/curve25519-node)](https://www.npmjs.com/package/@unknownncat/curve25519-node)
[![node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![types](https://img.shields.io/badge/types-included-blue)](./dist/index.d.ts)
![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![esm+cjs](https://img.shields.io/badge/ESM%20%2B%20CJS-compatible-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

- Node: `>= 20`
- Dependências de runtime: `0`
- TypeScript: `strict`
- Formatos de módulo: ESM + CJS

---

## Instalação

```bash
npm i @unknownncat/curve25519-node
```

---

## Uso Rápido

```ts
import { randomBytes } from "node:crypto";
import { asBytes32, x25519, ed25519 } from "@unknownncat/curve25519-node";

const aliceSeed = asBytes32(randomBytes(32));
const bobSeed = asBytes32(randomBytes(32));

const aliceX = x25519.generateKeyPair(aliceSeed);
const bobX = x25519.generateKeyPair(bobSeed);

const segredo1 = x25519.sharedKey(aliceX.private, bobX.public);
const segredo2 = x25519.sharedKey(bobX.private, aliceX.public);
// segredo1 === segredo2

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

Legado axlsign via WASM:

```ts
import { asBytes32, axlsign } from "@unknownncat/curve25519-node";

const seed = asBytes32(new Uint8Array(32));
const kp = axlsign.generateKeyPair(seed); // X25519 keypair compatível com curve25519-js
const sig = axlsign.sign(kp.private, new TextEncoder().encode("hello"), new Uint8Array(64));
const ok = axlsign.verify(kp.public, new TextEncoder().encode("hello"), sig);
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
- `signMessage(secretSeed32: Bytes32, msg: Uint8Array): Uint8Array` (`assinatura || mensagem`)
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### `axlsign` (compatibilidade legado, via WASM)

- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `generateKeyPair(seed32: Bytes32): { public: Bytes32; private: Bytes32 }`
- `sign(secretKey32: Bytes32, msg: Uint8Array, opt_random?: Bytes64): Bytes64`
- `verify(publicKey32: Bytes32, msg: Uint8Array, signature64: Bytes64): boolean`
- `signMessage(secretKey32: Bytes32, msg: Uint8Array, opt_random?: Bytes64): Uint8Array`
- `openMessage(publicKey32: Bytes32, signedMsg: Uint8Array): Uint8Array | null`

### Aliases de compatibilidade (top-level)

- `sharedKey = x25519.sharedKey`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (semântica Ed25519)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

---

## Notas de Compatibilidade

Este pacote suporta dois modos:

- **moderno (recomendado):** `x25519` + `ed25519` via `node:crypto`
- **legado:** `axlsign` via WASM para compatibilidade com `curve25519-js`

| Recurso | `curve25519-js` | `curve25519-node` |
| --- | --- | --- |
| Esquema de assinatura (moderno) | axlsign | Ed25519 (padrão) |
| Esquema de assinatura (legado) | axlsign | axlsign (namespace `axlsign`) |
| Acordo de chave | X25519 | X25519 |
| Mesma chave para assinatura + ECDH | sim | apenas no namespace `axlsign` |
| `opt_random` nas APIs de assinatura | sim | sim no `axlsign`, não no top-level/`ed25519` |
| Backend OpenSSL | não | sim |

Importante:

- Chaves públicas X25519 e Ed25519 são diferentes.
- `node:crypto` não expõe API para converter public key X25519 ↔ Ed25519.
- Top-level `sign`/`signMessage` e namespace `ed25519` continuam com semântica Ed25519 e rejeitam `opt_random`.
- Para compatibilidade com `curve25519-js` (incluindo `opt_random`), use o namespace `axlsign`.
- Assinaturas Ed25519 continuam determinísticas (comportamento padrão do OpenSSL).

---

## Motivação

O `curve25519-js` é um projeto importante, mas usa aritmética de campo manual em JS (`Float64Array`, estilo TweetNaCl).

Este pacote foca em Node moderno com primitivas do OpenSSL:

- caminho de implementação mais seguro
- melhor desempenho em Node >= 20
- API menor e explícita
- tipagem forte com zero dependências de runtime

Além disso, o namespace `axlsign` via WASM permite migração progressiva de código legado sem reintroduzir aritmética de curva em JavaScript puro.

---

## Tipos Branded

- `Bytes32`
- `Bytes64`

Helpers (validam sem copiar):

- `asBytes32(u8)`
- `asBytes64(u8)`

---

## Mapa de RFCs (uso no projeto)

| RFC | Seções usadas | Uso no projeto | Onde no código |
| --- | --- | --- | --- |
| RFC 7748 (X25519) | Seção 5 (`The X25519 and X448 Functions`) | Regras de clamping/decoding do escalar e comportamento da função X25519 (zera 3 bits baixos, zera bit mais alto, seta o segundo bit mais alto). | `src/x25519.ts` |
| RFC 7748 (X25519) | Seção 5.2 (`Test Vectors`), Seção 6.1 (`Diffie-Hellman / Curve25519`) | Vetores oficiais para validação de interoperabilidade e corretude. | `test/x25519.test.mjs` |
| RFC 8032 (Ed25519) | Seção 5.1.5 (`Key Generation`), 5.1.6 (`Sign`), 5.1.7 (`Verify`) | Semântica de keygen/sign/verify Ed25519 (executada por OpenSSL via `node:crypto`). | `src/ed25519.ts` |
| RFC 8032 (Ed25519) | Seção 7.1 (`Test Vectors for Ed25519`) | Vetores determinísticos para validação de chave pública e assinatura. | `test/ed25519.test.mjs` |
| RFC 8410 (X25519/Ed25519 em PKIX) | Seção 3 (identificadores de algoritmo), Seção 4 (`Subject Public Key Fields`), Seção 7 (`Private Key Format`) | Estrutura DER para import/export de chaves raw de 32 bytes em SPKI/PKCS#8 com OIDs de X25519 e Ed25519. | `src/internal/der.ts` |

Referências indiretas por estrutura ASN.1/PKIX:

- RFC 5958 (OneAsymmetricKey / família PKCS#8)
- RFC 5280, Seção 4.1.2.7 (`Subject Public Key Info`)

Observações:

- O projeto não reimplementa aritmética de curva em JS; as operações criptográficas usam OpenSSL via `node:crypto`.
- A suíte de testes cobre vetores oficiais do RFC 7748 e RFC 8032.

Rodar testes:

```bash
npm test
```

---

## Detalhes Técnicos (DER / RFC 8410)

Chaves raw de 32 bytes são importadas/exportadas com prefixos fixos:

- X25519 PKCS#8: `302e020100300506032b656e04220420`
- X25519 SPKI: `302a300506032b656e032100`
- Ed25519 PKCS#8: `302e020100300506032b657004220420`
- Ed25519 SPKI: `302a300506032b6570032100`

Notas de implementação:

- buffers prealocados + `.set`
- views zero-copy de `Uint8Array` quando seguro
- sem `Buffer.concat` em hot path

---

## Notas de Performance

- Evita cópias desnecessárias de bytes nos caminhos críticos.
- `signMessage` monta `assinatura || mensagem` com um único `Uint8Array` prealocado.
- Para throughput máximo em loops longos, cache de `KeyObject` no nível da aplicação reduz overhead de parse ASN.1.

---

## Notas de Segurança

- validação estrita de tipo/tamanho nas APIs públicas
- sem log de segredos
- `timingSafeEqual` em comparações internas de tamanho fixo quando necessário

---

## Benchmarks

A suíte de benchmark fica isolada em `bench/` (subprojeto separado) e compara com `curve25519-js`.

```bash
npm run build
cd bench
npm install
npm run bench
```

### Snapshot real de benchmark (`npm run bench:full`) no GitHub Codespaces

Comando:

```bash
node --expose-gc bench.mjs --rounds=16 --roundMs=350 --warmupMs=500 --variants=raw,cached,nocopy,copy --verifyDuringBench --verifyEvery=64
```

Ambiente:

- Node: `v24.11.1`
- OpenSSL: `3.5.4`
- CPU: `AMD EPYC 7763 64-Core Processor`
- Cores lógicos: `4`
- Vetores: `64`

Resultados selecionados (média em ops/s):

| Variante | Operação | Moderno | Legado (`curve25519-js`) | Speedup |
| --- | --- | ---: | ---: | ---: |
| raw | x25519.generateKeyPair | 14,201 | 1,627 | 8.73x |
| raw | x25519.sharedKey | 9,985 | 1,634 | 6.11x |
| raw | ed25519.sign (msg32) | 11,174 | 145 | 77.08x |
| raw | ed25519.verify (msg32) | 7,413 | 146 | 50.76x |
| raw | ed25519.signMessage (msg256) | 10,952 | 145 | 75.45x |
| raw | ed25519.openMessage (msg256) | 7,199 | 143 | 50.30x |
| cached | x25519.generateKeyPair | 48,553 | 1,624 | 29.90x |
| cached | x25519.sharedKey | 25,283 | 1,641 | 15.41x |
| cached | ed25519.sign (msg32) | 24,345 | 142 | 171.00x |
| cached | ed25519.verify (msg32) | 8,184 | 145 | 56.42x |
| cached | ed25519.signMessage (msg256) | 23,410 | 135 | 173.56x |
| cached | ed25519.openMessage (msg256) | 8,118 | 145 | 56.07x |
| nocopy | x25519.sharedKey | 10,383 | 1,617 | 6.42x |
| nocopy | ed25519.sign (msg32) | 11,170 | 145 | 77.18x |
| copy | x25519.sharedKey | 10,292 | 1,617 | 6.37x |
| copy | ed25519.sign (msg32) | 10,922 | 145 | 75.40x |

Notas:

- `cached` isola melhor o throughput criptográfico por reuso de `KeyObject` no lado moderno.
- `raw` / `copy` / `nocopy` ficam mais próximos do custo fim-a-fim de API.
- comparações de `sign`/`verify` medem throughput de API, não equivalência criptográfica (`axlsign` vs Ed25519 padrão).

---

## Build do namespace `axlsign`

No pacote publicado no npm, os artefatos WASM já vêm prontos em `dist/`.

Para buildar a partir do código-fonte, você precisa:

- Rust toolchain
- `wasm-pack` instalado

Com isso, `npm run build` executa:

1. `wasm-pack build` (`wasm/axlsign`)
2. `tsc` ESM + CJS
3. cópia dos artefatos WASM para `dist/internal/axlsign-wasm`

---

## Licença

MIT

---

## Créditos

- [curve25519-js](https://github.com/harveyconnor/curve25519-js) (Harvey Connor, Dmitry Chestnykh)
- [TweetNaCl.js](https://tweetnacl.js.org/)
- Trevor Perrin, ideia de assinaturas Curve25519: <https://moderncrypto.org/mail-archive/curves/2014/000205.html>
- [Documentação Node.js `crypto`](https://nodejs.org/api/crypto.html)
- [OpenSSL](https://www.openssl.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)
- [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
