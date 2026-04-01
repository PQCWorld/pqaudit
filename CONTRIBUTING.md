# Contributing to pqaudit

Thanks for your interest in improving post-quantum cryptography readiness tooling.

## Getting started

```bash
git clone https://github.com/PQCWorld/pqaudit.git
cd pqaudit
npm install
npm test        # watch mode
npm run test:run # single run
npm run build    # compile TypeScript
npm run dev -- . # run scanner via tsx
```

## Project structure

```
pqaudit/
  src/
    cli.ts                    # CLI entry point (commander)
    index.ts                  # Library exports
    types.ts                  # All TypeScript interfaces
    scanner/
      engine.ts               # Scan orchestrator
      engine.test.ts          # Engine tests
      file-scanner.ts         # Per-file regex detection
      dependency-scanner.ts   # npm package.json analysis
      rules.ts                # YAML rule loader
    reporter/
      text.ts                 # Human-readable CLI output
      json.ts                 # Raw JSON
      cbom.ts                 # CycloneDX 1.6 CBOM
      cbom.test.ts            # CBOM tests
      sarif.ts                # SARIF 2.1.0 for GitHub
    __fixtures__/             # Test sample files
  rules/
    crypto-patterns.yaml      # Detection rules
```

## How to contribute

### Adding a detection rule

This is the easiest way to contribute. Detection rules live in `rules/crypto-patterns.yaml`.

Each rule has this schema:

```yaml
- id: UNIQUE_RULE_ID        # Uppercase, underscored
  description: "What this detects and why it matters"
  severity: critical         # critical | high | medium | low | safe
  category: signature        # kem | signature | hash | symmetric | protocol | kdf
  algorithm: Ed25519         # Display name
  replacement: ML-DSA-65     # NIST PQC replacement, or null if safe
  effort: moderate           # trivial | moderate | complex | breaking
  languages: []              # Empty = all languages. Or: ["javascript", "python"]
  patterns:                  # Regex patterns (case-insensitive, global)
    - "ed25519"
    - "@noble/ed25519"
```

**Severity guide:**
- `critical` — Broken by Shor's algorithm (RSA, ECC, DH)
- `high` — Weakened by Grover's algorithm (AES-128)
- `medium` — Already weak classically (MD5, SHA-1, 3DES)
- `low` — Informational, worth documenting
- `safe` — Already quantum-resistant (ML-KEM, ML-DSA, AES-256)

**To submit a new rule:**
1. Add the rule to `rules/crypto-patterns.yaml`
2. Add a test pattern to `src/__fixtures__/vulnerable-sample.ts` or `pqc-safe-sample.ts`
3. Run `npm run test:run` to verify detection
4. Open a PR with the title: `rule: <algorithm/library name>`

### Adding a dependency scanner

Dependency scanners live in `src/scanner/dependency-scanner.ts`. Currently we scan npm `package.json`. To add support for another ecosystem:

1. Create a `scan<Ecosystem>Dependencies(targetDir: string): Finding[]` function
2. Check for the manifest file (e.g., `Cargo.toml`, `go.mod`, `requirements.txt`)
3. Map known crypto packages to findings using the same schema
4. Wire it into `engine.ts` alongside `scanNpmDependencies`
5. Add tests

### Fixing a bug or false positive

1. Create a minimal reproduction in `src/__fixtures__/`
2. Write a failing test in `src/scanner/engine.test.ts`
3. Fix the issue
4. Verify all tests pass

### Adding an output format

Reporters live in `src/reporter/`. Each exports a single `format<Name>(result: ScanResult): string` function. Add it to `src/index.ts` exports and wire the `--format` option in `src/cli.ts`.

## Code conventions

- TypeScript, ESM (`"type": "module"`)
- Node 20+
- Tests use Vitest, colocated as `*.test.ts`
- Named exports only (no default exports)
- No unnecessary abstractions — keep it simple
- Run `npm run test:run` before submitting

## Branching and PRs

- Branch from `main`
- One feature per PR
- Branch naming: `feat/<name>`, `fix/<name>`, `rule/<name>`
- PRs require passing CI (build + test on Node 20 and 22)
- Keep PRs small and focused

## Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Patch** (`0.1.x`): bug fixes, false positive corrections, new detection rules
- **Minor** (`0.x.0`): new features (output formats, dependency scanners, CLI options)
- **Major** (`x.0.0`): breaking changes to CLI interface, output format schema, or rule schema

**Current phase:** `0.x.y` — the API is not yet stable. Minor versions may include breaking changes until `1.0.0`.

### Release process

Releases are done from `main` by a maintainer:

```bash
# 1. Ensure main is clean and tests pass
git checkout main && git pull
npm run test:run
npm run build

# 2. Bump version (pick one)
npm version patch   # 0.1.0 → 0.1.1 (rule additions, bug fixes)
npm version minor   # 0.1.1 → 0.2.0 (new features)
npm version major   # 0.2.0 → 1.0.0 (breaking changes)

# 3. Push the version commit and tag
git push && git push --tags

# 4. Publish to npm
npm publish

# 5. Create GitHub release
gh release create v$(node -p "require('./package.json').version") --generate-notes
```

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
