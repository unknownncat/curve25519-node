# @unknownncat/curve25519-node

> 🇺🇸 English version: [README.en.md](./README.en.md)

Implementação sem dependências de runtime de:

- X25519 + Ed25519 (modo moderno via OpenSSL em `node:crypto`)
- X25519 + Ed25519 (modo moderno opcional via WASM)
- X25519 + Ed25519 + axlsign (modo nativo opcional via Rust `napi-rs`)
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

Moderno via WASM (`wasm`):

```ts
import { asBytes32, wasm } from "@unknownncat/curve25519-node";

const seed = asBytes32(new Uint8Array(32));
const kp = wasm.x25519.generateKeyPair(seed);
const shared = wasm.x25519.sharedKey(kp.private, kp.public);

const msg = new TextEncoder().encode("hello");
const sig = wasm.ed25519.sign(seed, msg);
const ok = wasm.ed25519.verify(wasm.ed25519.publicKey(seed), msg, sig);
```

Nativo via Rust (`napi`):

```ts
import { asBytes32, napi } from "@unknownncat/curve25519-node";

if (napi.isAvailable()) {
  const seed = asBytes32(new Uint8Array(32));
  const kp = napi.x25519.generateKeyPair(seed);
  const sig = napi.ed25519.sign(seed, new TextEncoder().encode("hello"));
  const ok = napi.ed25519.verify(
    napi.ed25519.publicKey(seed),
    new TextEncoder().encode("hello"),
    sig,
  );
}
```

Observação: o namespace `napi` só fica ativo quando o addon nativo existe para o alvo
`${process.platform}-${process.arch}`. Sempre verifique com `napi.isAvailable()` antes de usar.

---

## API

### `x25519`

- `createPrivateKeyObject(secretKey32: Bytes32): KeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): KeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: KeyObject): Bytes32`
- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKeyFromKeyObjects(privateKey: KeyObject, publicKey: KeyObject): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `sharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32` (rejeita segredo all-zero)
- `sharedKeyStrictFromKeyObjects(privateKey: KeyObject, publicKey: KeyObject): Bytes32` (rejeita segredo all-zero)
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

### `wasm` (modo moderno opcional, via WASM)

`wasm.x25519`:

- `createPrivateKeyObject(secretKey32: Bytes32): WasmX25519PrivateKeyObject`
- `createPublicKeyObject(publicKey32: Bytes32): WasmX25519PublicKeyObject`
- `publicKeyFromPrivateKeyObject(privateKey: WasmX25519PrivateKeyObject): Bytes32`
- `publicKey(secretKey32: Bytes32): Bytes32`
- `sharedKeyFromKeyObjects(privateKey: WasmX25519PrivateKeyObject, publicKey: WasmX25519PublicKeyObject): Bytes32`
- `sharedKey(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32`
- `sharedKeyStrict(secretKey32: Bytes32, publicKey32: Bytes32): Bytes32` (rejeita segredo all-zero)
- `sharedKeyStrictFromKeyObjects(privateKey: WasmX25519PrivateKeyObject, publicKey: WasmX25519PublicKeyObject): Bytes32` (rejeita segredo all-zero)
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

### `napi` (modo nativo opcional, via Rust `napi-rs`)

- `isAvailable(): boolean`
- `napi.x25519` com API equivalente ao namespace `wasm.x25519`
- `napi.ed25519` com API equivalente ao namespace `wasm.ed25519`
- `napi.axlsign` com API equivalente ao namespace `axlsign`

### Aliases de compatibilidade (top-level)

- `sharedKey = x25519.sharedKey`
- `sharedKeyStrict = x25519.sharedKeyStrict`
- `generateKeyPair = x25519.generateKeyPair`
- `sign`, `verify`, `signMessage`, `openMessage` (semântica Ed25519)
- `generateKeyPairX25519`, `generateKeyPairEd25519`

---

## Notas de Compatibilidade

Este pacote suporta três modos:

- **moderno nativo (recomendado):** `x25519` + `ed25519` via `node:crypto`
- **moderno WASM (opcional):** namespace `wasm` (`wasm.x25519` + `wasm.ed25519`)
- **legado:** `axlsign` via WASM para compatibilidade com `curve25519-js`

| Recurso                             | `curve25519-js` | `curve25519-node`                            |
| ----------------------------------- | --------------- | -------------------------------------------- |
| Esquema de assinatura (moderno)     | axlsign         | Ed25519 (padrão)                             |
| Esquema moderno alternativo         | não             | Ed25519 via WASM (`wasm.ed25519`)            |
| Esquema de assinatura (legado)      | axlsign         | axlsign (namespace `axlsign`)                |
| Acordo de chave                     | X25519          | X25519                                       |
| Acordo moderno alternativo          | não             | X25519 via WASM (`wasm.x25519`)              |
| Mesma chave para assinatura + ECDH  | sim             | apenas no namespace `axlsign`                |
| `opt_random` nas APIs de assinatura | sim             | sim no `axlsign`, não no top-level/`ed25519` |
| Backend OpenSSL                     | não             | sim                                          |

Importante:

- Chaves públicas X25519 e Ed25519 são diferentes.
- Para fluxos de protocolo mais rígidos (estilo Signal), prefira `sharedKeyStrict` para rejeitar segredo compartilhado all-zero.
- `node:crypto` não expõe API para converter public key X25519 ↔ Ed25519.
- Top-level `sign`/`signMessage` e namespace `ed25519` continuam com semântica Ed25519 e rejeitam `opt_random`.
- Para compatibilidade com `curve25519-js` (incluindo `opt_random`), use o namespace `axlsign`.
- Assinaturas Ed25519 continuam determinísticas (comportamento padrão do OpenSSL).
- Os módulos WASM (`axlsign` e `wasm`) são carregados sob demanda na primeira chamada (importar apenas `x25519`/`ed25519` não inicializa WASM).

---

## Motivação

O `curve25519-js` é um projeto importante, mas usa aritmética de campo manual em JS (`Float64Array`, estilo TweetNaCl).

Este pacote foca em Node moderno com primitivas do OpenSSL:

- caminho de implementação mais seguro
- melhor desempenho em Node >= 20
- API menor e explícita
- tipagem forte com zero dependências de runtime

Além disso:

- o namespace `axlsign` via WASM permite migração progressiva de código legado;
- o namespace `wasm` via WASM oferece uma alternativa moderna sem dependência de `node:crypto` no caminho criptográfico.

---

## Tipos Branded

- `Bytes32`
- `Bytes64`

Helpers (validam sem copiar):

- `asBytes32(u8)`
- `asBytes64(u8)`

---

## Mapa de RFCs (uso no projeto)

| RFC                               | Seções usadas                                                                                                 | Uso no projeto                                                                                                                                  | Onde no código          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| RFC 7748 (X25519)                 | Seção 5 (`The X25519 and X448 Functions`)                                                                     | Regras de clamping/decoding do escalar e comportamento da função X25519 (zera 3 bits baixos, zera bit mais alto, seta o segundo bit mais alto). | `src/x25519.ts`         |
| RFC 7748 (X25519)                 | Seção 5.2 (`Test Vectors`), Seção 6.1 (`Diffie-Hellman / Curve25519`)                                         | Vetores oficiais para validação de interoperabilidade e corretude.                                                                              | `test/x25519.test.mjs`  |
| RFC 8032 (Ed25519)                | Seção 5.1.5 (`Key Generation`), 5.1.6 (`Sign`), 5.1.7 (`Verify`)                                              | Semântica de keygen/sign/verify Ed25519 (executada por OpenSSL via `node:crypto`).                                                              | `src/ed25519.ts`        |
| RFC 8032 (Ed25519)                | Seção 7.1 (`Test Vectors for Ed25519`)                                                                        | Vetores determinísticos para validação de chave pública e assinatura.                                                                           | `test/ed25519.test.mjs` |
| RFC 8410 (X25519/Ed25519 em PKIX) | Seção 3 (identificadores de algoritmo), Seção 4 (`Subject Public Key Fields`), Seção 7 (`Private Key Format`) | Estrutura DER para import/export de chaves raw de 32 bytes em SPKI/PKCS#8 com OIDs de X25519 e Ed25519.                                         | `src/internal/der.ts`   |

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
- Para throughput máximo em loops longos, use os helpers de `KeyObject` (`create*KeyObject`, `*FromKeyObjects`) para reduzir overhead de parse ASN.1.

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

### Snapshot real de benchmark (`npm run bench:ci`) no GitHub Codespaces

Comando:

```bash
node --expose-gc bench.mjs --rounds=16 --roundMs=350 --warmupMs=500 --vectors=64 --variants=raw,cached --strict --verifyEvery=64 --jsonFile=results/bench-results.json
```

Ambiente:

- Node: `v24.11.1`
- OpenSSL: `3.5.4`
- CPU: `AMD EPYC 7763 64-Core Processor`
- Cores lógicos: `4`
- Vetores: `64`

### Tabela 1 - API moderna (nativa + WASM)

`sign`/`verify` abaixo comparam throughput de API, não equivalência criptográfica (Ed25519 vs axlsign legado).

| Operação                            | Moderno raw | Legado raw (`curve25519-js`) | Speedup raw | Moderno cached | Legado cached (`curve25519-js`) | Speedup cached |
| ----------------------------------- | ----------: | ---------------------------: | ----------: | -------------: | ------------------------------: | -------------: |
| `x25519.generateKeyPair`            |      14,082 |                        1,579 |       8.92x |         49,035 |                           1,576 |         31.12x |
| `x25519.sharedKey`                  |      10,134 |                        1,568 |       6.46x |         25,423 |                           1,578 |         16.11x |
| `wasm.x25519.generateKeyPair`       |       8,415 |                        1,571 |       5.36x |          8,385 |                           1,574 |          5.33x |
| `wasm.x25519.sharedKey`             |       8,333 |                        1,577 |       5.28x |          8,350 |                           1,583 |          5.28x |
| `ed25519.sign (msg32)`              |      11,273 |                          142 |      79.56x |         23,886 |                             137 |        174.75x |
| `wasm.ed25519.sign (msg32)`         |       3,945 |                          142 |      27.80x |          3,956 |                             140 |         28.27x |
| `ed25519.sign (msg1024)`            |      10,759 |                          136 |      79.31x |         22,335 |                             138 |        162.38x |
| `wasm.ed25519.sign (msg1024)`       |       3,872 |                          137 |      28.27x |          3,873 |                             137 |         28.37x |
| `ed25519.verify (msg32)`            |       7,333 |                          142 |      51.65x |          8,186 |                             141 |         58.01x |
| `wasm.ed25519.verify (msg32)`       |       7,747 |                          141 |      54.84x |          7,629 |                             143 |         53.26x |
| `ed25519.verify (msg1024)`          |       7,241 |                          134 |      54.20x |          8,081 |                             136 |         59.35x |
| `wasm.ed25519.verify (msg1024)`     |       7,505 |                          135 |      55.76x |          7,480 |                             134 |         55.66x |
| `ed25519.signMessage (msg256)`      |      10,859 |                          140 |      77.67x |         23,607 |                             132 |        178.57x |
| `wasm.ed25519.signMessage (msg256)` |       3,888 |                          139 |      27.99x |          3,867 |                             137 |         28.23x |
| `ed25519.openMessage (msg256)`      |       7,113 |                          145 |      49.03x |          8,012 |                             141 |         56.96x |
| `wasm.ed25519.openMessage (msg256)` |       7,428 |                          137 |      54.26x |          7,476 |                             137 |         54.74x |

### Tabela 2 - Compatibilidade `axlsign` (equivalente ao `curve25519-js`)

Aqui a comparação é de mesmo esquema criptográfico (equivalência + throughput).

| Operação                                  | Moderno raw | Legado raw (`curve25519-js`) | Speedup raw | Moderno cached | Legado cached (`curve25519-js`) | Speedup cached |
| ----------------------------------------- | ----------: | ---------------------------: | ----------: | -------------: | ------------------------------: | -------------: |
| `axlsign.generateKeyPair`                 |       8,382 |                        1,571 |       5.34x |          8,357 |                           1,579 |          5.29x |
| `axlsign.sharedKey`                       |       8,361 |                        1,583 |       5.28x |          8,422 |                           1,564 |          5.39x |
| `axlsign.sign (msg32)`                    |       4,010 |                          140 |      28.59x |          3,970 |                             141 |         28.10x |
| `axlsign.sign (msg32,opt_random)`         |       4,000 |                          142 |      28.07x |          3,965 |                             136 |         29.08x |
| `axlsign.sign (msg1024)`                  |       3,883 |                          138 |      28.17x |          3,878 |                             138 |         28.03x |
| `axlsign.verify (msg32)`                  |       6,604 |                          144 |      45.83x |          6,585 |                             143 |         46.17x |
| `axlsign.verify (msg32,opt_random)`       |       6,531 |                          143 |      45.69x |          6,527 |                             142 |         46.08x |
| `axlsign.verify (msg1024)`                |       6,428 |                          138 |      46.47x |          6,377 |                             136 |         46.82x |
| `axlsign.signMessage (msg256)`            |       3,913 |                          140 |      27.85x |          3,935 |                             136 |         28.92x |
| `axlsign.signMessage (msg256,opt_random)` |       3,941 |                          139 |      28.39x |          3,878 |                             139 |         27.93x |
| `axlsign.openMessage (msg256)`            |       6,440 |                          138 |      46.78x |          6,407 |                             136 |         47.18x |
| `axlsign.openMessage (msg256,opt_random)` |       6,513 |                          134 |      48.53x |          6,431 |                             133 |         48.19x |

Notas:

- `raw` inclui custo fim-a-fim da API.
- `cached` reduz overhead de setup para evidenciar melhor o throughput criptográfico.
- Fonte dos números: saída JSON de `bench:ci` (`results/bench-results.json`).

---

## Build dos namespaces WASM (`axlsign` e `wasm`)

No pacote publicado no npm, os artefatos WASM já vêm prontos em `dist/`.

Para buildar a partir do código-fonte, você precisa:

- Rust toolchain
- `wasm-pack` instalado

Com isso, `npm run build` executa:

1. `wasm-pack build` (`../../rust/crates/axlsign-wasm`)
2. `wasm-pack build` (`../../rust/crates/curve-wasm`)
3. `tsc` ESM + CJS
4. cópia dos artefatos WASM para `dist/internal/axlsign-wasm` e `dist/internal/curve25519-wasm`

Referência dos crates Rust: [../../rust/README.md](../../rust/README.md)

---

## Contribuição

- Guia: [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
- Código de conduta: [../../CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)
- Segurança: [SECURITY.md](./SECURITY.md)

Validação local completa:

```bash
npm run ci
```

Checagens extras de robustez/supply-chain:

```bash
npm run audit
npm run audit:prod
npm run release:check
```

---

## Licença

MIT

Documentos complementares:

- [NOTICE.md](./NOTICE.md) (aviso oficial de terceiros)
- [THIRD_PARTY_NOTICE.md](./THIRD_PARTY_NOTICE.md) e [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) (aliases de compatibilidade)
- [SECURITY.md](./SECURITY.md) (política de segurança e reporte de vulnerabilidades)

---

## Créditos

- [curve25519-js](https://github.com/harveyconnor/curve25519-js) (Harvey Connor, Dmitry Chestnykh)
- [TweetNaCl.js](https://tweetnacl.js.org/)
- Trevor Perrin, ideia de assinaturas Curve25519: <https://moderncrypto.org/mail-archive/curves/2014/000205.html>
- [Documentação Node.js `crypto`](https://nodejs.org/api/crypto.html)
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
