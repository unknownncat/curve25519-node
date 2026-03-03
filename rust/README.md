# Rust Workspace

Este diretório contém o workspace Rust usado pelos pacotes Node e Browser.

## Estrutura

- `rust/Cargo.toml`  
  Workspace com todos os crates.
- `rust/crates/axlsign-wasm`  
  Compatibilidade legada com `curve25519-js` (esquema axlsign).
- `rust/crates/curve-wasm`  
  Implementação WASM da API moderna (`x25519` + `ed25519`).
- `rust/crates/curve-napi`  
  Addon nativo Node.js via `napi-rs` com foco em throughput.

## Artefatos gerados

- `packages/node/src/internal/*-wasm` (target `nodejs`)
- `packages/node/src/internal/napi/curve25519_node_napi.node`
- `packages/browser/src/internal/*-wasm` (target `web`)

Depois esses arquivos são copiados para `dist/internal/*-wasm` em cada pacote.

## Pré-requisitos

- Rust toolchain (stable)
- target `wasm32-unknown-unknown`
- `wasm-pack`

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## Build

Na raiz do monorepo:

```bash
npm run build:node
npm run build:browser
```
