# @unknownncat/curve25519-browser

WASM-first X25519 + Ed25519 + legacy axlsign for browser environments.

## Install

```bash
npm i @unknownncat/curve25519-browser
```

## Initialize

You must initialize WASM before using crypto functions:

```ts
import { initWasm, x25519 } from "@unknownncat/curve25519-browser";

await initWasm();
const kp = x25519.generateKeyPair(new Uint8Array(32));
```

For custom loaders, pass explicit module inputs:

```ts
await initWasm({
  axlsign: "/assets/axlsign_wasm_bg.wasm",
  curve25519: "/assets/curve25519_wasm_bg.wasm",
});
```

## Exports

- `x25519` (WASM modern API)
- `ed25519` (WASM modern API)
- `axlsign` (legacy compatibility via WASM)
- top-level aliases (`sharedKey`, `sign`, `verify`, etc.)
