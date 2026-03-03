# Benchmarks (subprojeto isolado)

> English version: [README.en.md](./README.en.md)

Esta pasta e um projeto separado para benchmark.  
Nao adiciona dependencias runtime ao pacote principal.
Este subprojeto e privado (`private: true`) e nao deve ser publicado no npm.

## O que este bench garante

- fairness: warmup, rounds, round duration, ordem aleatoria por round
- medicao com `process.hrtime.bigint()`
- estatisticas: `mean`, `p50`, `p95`, `stdev`
- pool rotativo de vetores (minimo 64 seeds/messages/keypairs)
- validacao de corretude antes de medir
- validacao opcional durante benchmark (`--verifyDuringBench`)
- saida humana + JSON (`--json` / `--jsonFile=...`)
- modo estrito (`--strict`) para falhar em inconsistencias
- suporte a baseline para detectar regressao
- pares extras NAPI (Rust addon) quando o `.node` nativo estiver disponivel

## Importante sobre assinaturas

`@unknownncat/curve25519-node` usa Ed25519 padrao.  
`curve25519-js` usa esquema axlsign.

Por isso:

- comparacoes de `sign`/`verify` e `signMessage`/`openMessage` medem throughput de API
- nao medem equivalencia criptografica entre esquemas diferentes

Mensagem exibida no bench:

`sign/verify comparisons measure API throughput, not cryptographic equivalence`

## Variantes

- `raw`: caminho normal da API
- `cached`: reutiliza `KeyObject` quando possivel (lado moderno)
- `copy`: copia buffers antes das chamadas
- `nocopy`: evita copias quando seguro  
  observacao: `legacy openMessage` sempre recebe copia porque muta o input

## Como rodar

Na raiz:

```bash
npm install
npm run build:node
```

Publicacao npm deve ser feita na raiz do projeto principal, nao dentro de `bench/`.

Execucoes (na raiz, via workspace):

```bash
npm run -w curve25519-node-bench bench
npm run -w curve25519-node-bench bench:quick
npm run -w curve25519-node-bench bench:full
npm run -w curve25519-node-bench bench:strict
npm run -w curve25519-node-bench bench:ci
```

Se voce preferir entrar em `bench/`, os mesmos scripts funcionam com `npm run bench:*`.

## NAPI (Rust addon)

- quando `@unknownncat/curve25519-node` tiver o addon N-API carregavel, o bench inclui pares `napi.*`
- quando nao estiver disponivel, o bench continua e marca warning: `napi addon unavailable; skipping napi benchmark pairs`
- os pares `napi.*` comparam o backend Rust nativo contra o backend Node/OpenSSL (mesmo esquema)

## Flags CLI

```bash
node --expose-gc bench.mjs \
  --rounds=16 \
  --roundMs=350 \
  --warmupMs=500 \
  --vectors=64 \
  --variants=raw,cached \
  --verifyDuringBench \
  --verifyEvery=64 \
  --strict \
  --debug \
  --json \
  --jsonFile=results/bench-results.json
```

Flags disponiveis:

- `--rounds=<n>`
- `--roundMs=<ms>`
- `--warmupMs=<ms>`
- `--vectors=<n>` (minimo 64)
- `--variants=raw,cached,copy,nocopy`
- `--gc` / `--no-gc`
- `--verifyDuringBench`
- `--verifyEvery=<n>`
- `--strict`
- `--debug`
- `--json`
- `--jsonFile=<path>`
- `--baseline=<path>`
- `--maxRegressionPct=<n>`
- `--failOnRegression`

## Regressao

Gerar baseline:

```bash
node --expose-gc bench.mjs --variants=raw,cached --jsonFile=results/bench-baseline.json
```

Comparar com baseline e falhar se piorar acima do limite:

```bash
node --expose-gc bench.mjs \
  --variants=raw,cached \
  --baseline=results/bench-baseline.json \
  --maxRegressionPct=10 \
  --failOnRegression
```
