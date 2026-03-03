# @unknownncat/curve25519-node

> English version: [README.en.md](./README.en.md)

Implementacao para Node.js com API limpa:

- `x25519` e `ed25519` via `node:crypto` (OpenSSL)
- `axlsign` de compatibilidade legado em runtime Node
- sem namespace `wasm`
- sem namespace `napi`

## Instalar

```bash
npm i @unknownncat/curve25519-node
```

## Uso rapido

```ts
import { randomBytes } from "node:crypto";
import { asBytes32, x25519, ed25519, axlsign } from "@unknownncat/curve25519-node";

const seedA = asBytes32(randomBytes(32));
const seedB = asBytes32(randomBytes(32));

const alice = x25519.generateKeyPair(seedA);
const bob = x25519.generateKeyPair(seedB);
const shared = x25519.sharedKey(alice.private, bob.public);

const msg = new TextEncoder().encode("hello");
const sig = ed25519.sign(seedA, msg);
const ok = ed25519.verify(ed25519.publicKey(seedA), msg, sig);

const axlSig = axlsign.sign(alice.private, msg, randomBytes(64));
const axlOk = axlsign.verify(alice.public, msg, axlSig);
```

CommonJS:

```js
const { x25519, ed25519, axlsign } = require("@unknownncat/curve25519-node");
```

## Exports

- `x25519`
- `ed25519`
- `axlsign`
- aliases top-level: `sharedKey`, `sharedKeyStrict`, `generateKeyPair`, `sign`, `verify`, `signMessage`, `openMessage`
- tipos/helpers: `Bytes32`, `Bytes64`, `asBytes32`, `asBytes64`

## Observacoes

- `sign`/`verify` top-level seguem semantica Ed25519 e rejeitam `opt_random`.
- Para fluxo legado compativel com `curve25519-js`, use `axlsign.*`.
- Se voce precisa de WASM no navegador, use `@unknownncat/curve25519-browser`.

## Licenca e avisos

- [LICENSE](./LICENSE)
- [NOTICE.md](./NOTICE.md)
- [THIRD_PARTY_NOTICE.md](./THIRD_PARTY_NOTICE.md)
- [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)
- [SECURITY.md](./SECURITY.md)
