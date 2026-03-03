# @unknownncat/curve25519-node

> Portuguese version: [README.md](./README.md)

Node.js implementation with a clean API:

- `x25519` and `ed25519` via `node:crypto` (OpenSSL)
- legacy-compatible `axlsign` accelerated by an internal Rust/WASM backend
- no `wasm` namespace
- no `napi` namespace

## Install

```bash
npm i @unknownncat/curve25519-node
```

## Quick usage

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
- top-level aliases: `sharedKey`, `sharedKeyStrict`, `generateKeyPair`, `sign`, `verify`, `signMessage`, `openMessage`
- types/helpers: `Bytes32`, `Bytes64`, `asBytes32`, `asBytes64`

## Notes

- Top-level `sign`/`verify` keep Ed25519 semantics and reject `opt_random`.
- For legacy compatibility with `curve25519-js`, use `axlsign.*`.
- For browser WASM runtime, use `@unknownncat/curve25519-browser`.

## License and notices

- [LICENSE](./LICENSE)
- [NOTICE.md](./NOTICE.md)
- [THIRD_PARTY_NOTICE.md](./THIRD_PARTY_NOTICE.md)
- [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)
- [SECURITY.md](./SECURITY.md)
