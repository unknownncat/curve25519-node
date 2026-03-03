# Benchmarks (isolated subproject)

> Versao em portugues (principal): [README.md](./README.md)

This folder is a separate benchmark project.  
It does not add runtime dependencies to the main package.
This subproject is private (`private: true`) and must not be published to npm.

## What this bench guarantees

- fairness: warmup, rounds, round duration, random order per round
- measurement using `process.hrtime.bigint()`
- stats: `mean`, `p50`, `p95`, `stdev`
- rotating vector pools (at least 64 seeds/messages/keypairs)
- correctness validation before measuring
- optional validation during benchmark (`--verifyDuringBench`)
- human-readable output + JSON (`--json` / `--jsonFile=...`)
- strict mode (`--strict`) to fail on inconsistencies
- baseline support for regression detection
- extra NAPI (Rust addon) pairs when the native `.node` addon is available

## Important note on signatures

`@unknownncat/curve25519-node` uses standard Ed25519.  
`curve25519-js` uses the axlsign scheme.

Because of that:

- `sign`/`verify` and `signMessage`/`openMessage` comparisons measure API throughput
- they do not measure cryptographic equivalence between different schemes

Bench message:

`sign/verify comparisons measure API throughput, not cryptographic equivalence`

## Variants

- `raw`: default API path
- `cached`: reuses `KeyObject` where possible (modern side)
- `copy`: copies buffers before calls
- `nocopy`: avoids copies where safe  
  note: `legacy openMessage` always receives a copy because it mutates input

## How to run

From repository root:

```bash
npm install
npm run build:node
```

Publish to npm from repository root package, not from `bench/`.

Commands (from repository root, via workspace):

```bash
npm run -w curve25519-node-bench bench
npm run -w curve25519-node-bench bench:quick
npm run -w curve25519-node-bench bench:full
npm run -w curve25519-node-bench bench:strict
npm run -w curve25519-node-bench bench:ci
```

If you prefer entering `bench/`, the same scripts also work with `npm run bench:*`.

## NAPI (Rust addon)

- when `@unknownncat/curve25519-node` can load its N-API addon, the bench includes `napi.*` pairs
- when it is unavailable, the bench still runs and records warning: `napi addon unavailable; skipping napi benchmark pairs`
- `napi.*` pairs compare native Rust backend vs Node/OpenSSL backend (same scheme)

## CLI flags

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

Available flags:

- `--rounds=<n>`
- `--roundMs=<ms>`
- `--warmupMs=<ms>`
- `--vectors=<n>` (minimum 64)
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

## Regression checks

Generate baseline:

```bash
node --expose-gc bench.mjs --variants=raw,cached --jsonFile=results/bench-baseline.json
```

Compare against baseline and fail above threshold:

```bash
node --expose-gc bench.mjs \
  --variants=raw,cached \
  --baseline=results/bench-baseline.json \
  --maxRegressionPct=10 \
  --failOnRegression
```
