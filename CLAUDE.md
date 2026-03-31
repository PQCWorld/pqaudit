# pqaudit

Post-quantum cryptography readiness scanner. Finds quantum-vulnerable cryptography in codebases and generates CycloneDX CBOM (Cryptographic Bill of Materials).

## Quick reference

```bash
npm run dev -- <target>          # Run scanner via tsx
npm run build                    # Compile TypeScript
npm run test:run                 # Run tests once
npm test                         # Watch mode
```

## Architecture

Layered detection engine:

- **L0 (current)**: Regex pattern matching against YAML rules in `rules/crypto-patterns.yaml`
- **L1 (planned)**: AST-based analysis via tree-sitter for reduced false positives
- **L2 (planned)**: Data flow / taint analysis for tracing crypto through call chains

### Key directories

- `src/scanner/` — detection engine, file scanner, dependency scanner, rules loader
- `src/reporter/` — output formatters (text, JSON, CycloneDX CBOM, SARIF)
- `src/__fixtures__/` — test sample files (vulnerable + PQC-safe)
- `rules/` — YAML detection rule definitions

### Adding detection rules

Add entries to `rules/crypto-patterns.yaml`. Each rule needs: `id`, `description`, `severity`, `category`, `algorithm`, `replacement`, `effort`, `languages`, `patterns` (regex array).

### Output formats

- `text` — human-readable CLI output (default)
- `json` — raw scan results
- `cbom` — CycloneDX 1.6 Cryptographic Bill of Materials
- `sarif` — GitHub Code Scanning compatible

## Conventions

- TypeScript, ESM, Node 20+
- Tests use Vitest, colocated as `*.test.ts`
- No default exports — use named exports
