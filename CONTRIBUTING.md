# Contribuindo

Obrigado por contribuir com `@unknownncat/curve25519-node`.

## Pré-requisitos

- Node.js `>= 20`
- npm
- Rust + `wasm-pack` (necessário para `npm run build` e `npm test`)

## Setup local

```bash
npm ci
```

## Fluxo recomendado

1. Crie uma branch a partir de `main`.
2. Faça alterações pequenas e focadas.
3. Rode validações locais antes de abrir PR.
4. Abra Pull Request com contexto claro e testes.

## Comandos de qualidade

```bash
npm run format
npm run lint
npm run typecheck
npm test
```

Validação completa (mesmo padrão do CI):

```bash
npm run ci
```

## Escopo de mudanças

- Evite misturar refactor grande com correção funcional no mesmo PR.
- Mantenha compatibilidade da API pública, salvo quando a mudança for documentada.
- Atualize README/testes quando a semântica pública mudar.

## Benchmarks

Benchmarks ficam isolados no subprojeto `bench/`:

```bash
npm run build
npm --prefix bench ci
npm --prefix bench run bench:ci
```

## Diretrizes de commit e PR

- Commits pequenos e descritivos.
- PR deve incluir:
  - motivação da mudança
  - impacto em compatibilidade/performance
  - como foi testado
