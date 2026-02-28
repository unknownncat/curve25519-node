# Benchmarks (subprojeto isolado)

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
npm run build
cd bench
npm install
```

Publicacao npm deve ser feita na raiz do projeto principal, nao dentro de `bench/`.

Execucoes:

```bash
npm run bench
npm run bench:quick
npm run bench:full
npm run bench:strict
npm run bench:ci
```

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
