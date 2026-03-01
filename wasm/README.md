# WASM Crates

Este diretório contém os crates Rust usados para os módulos WASM opcionais do pacote.

## Estrutura

- `wasm/axlsign`  
  Compatibilidade legada com `curve25519-js` (esquema axlsign).
- `wasm/curve25519-wasm`  
  Implementação WASM da API moderna (`x25519` + `ed25519`).

Os artefatos gerados são publicados em:

- `src/internal/axlsign-wasm`
- `src/internal/curve25519-wasm`

E copiados para `dist/internal/*-wasm` durante o build.

## Pré-requisitos

- Rust toolchain (stable)
- `wasm32-unknown-unknown` target
- `wasm-pack`

Instalação rápida:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## Build

No diretório raiz do projeto:

```bash
npm run build:wasm
```

Build completo do pacote:

```bash
npm run build
```

## Nota de arquitetura

Os namespaces WASM (`axlsign` e `wasm`) são carregados com lazy-loading no runtime.  
Importar apenas a API nativa (`x25519`/`ed25519` via `node:crypto`) não inicializa WASM automaticamente.

## Compliance e segurança

- Avisos/licenças de terceiros: [NOTICE.md](../NOTICE.md)
- Política de segurança: [SECURITY.md](../SECURITY.md)
