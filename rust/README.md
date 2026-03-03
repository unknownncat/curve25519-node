# Rust Workspace

Este diretório contém o workspace Rust usado pelos pacotes Node e Browser.

## Estrutura

- `rust/Cargo.toml`  
  Workspace com todos os crates.
- `rust/crates/axlsign-wasm`  
  Compatibilidade legada com `curve25519-js` (esquema axlsign).
- `rust/crates/curve-wasm`  
  Implementação WASM da API moderna (`x25519` + `ed25519`).

## Artefatos gerados

- `packages/browser/src/internal/*-wasm` (target `web`)

Depois esses arquivos são copiados para `dist/internal/*-wasm` do pacote browser.

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
npm run build:browser
```
