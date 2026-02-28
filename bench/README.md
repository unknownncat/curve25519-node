# Benchmarks (isolated project)

Esta pasta e um subprojeto separado para benchmark, sem adicionar dependencias ao pacote principal.

## Objetivo

Comparar throughput de `@unknownncat/curve25519-node` vs `curve25519-js` em:

- `generateKeyPair`
- `sharedKey`
- `sign` / `verify`
- `signMessage` / `openMessage`

## Importante

- `sharedKey` e `generateKeyPair` sao comparacoes diretas de X25519.
- `sign`/`verify` e `signMessage`/`openMessage` **nao** sao esquema-identicos:
  - moderno: Ed25519 padrao
  - legado (`curve25519-js`): esquema axlsign (conversoes e sign bit)
- o legado pode mutar o `signedMessage` em `openMessage`; por isso o bench usa copia por iteracao.

Use essas comparacoes de assinatura como referencia de throughput de API, nao equivalencia criptografica.

## Como rodar

Na raiz do repositório:

```bash
npm run build
cd bench
npm install
npm run bench
```

Perfis:

```bash
npm run bench:quick
npm run bench:full
```

Parametros custom:

```bash
node --expose-gc bench.mjs --rounds=20 --roundMs=400 --warmupMs=600
```

## Saida

Para cada par de testes:

- `mean ops/s`
- `p50`
- `p95`
- `stdev`
- `rounds`
- fator relativo (`X is Yx faster than Z`)
