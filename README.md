# pqaudit

Scan codebases for quantum-vulnerable cryptography. Get a clear picture of what needs to migrate before [Q-Day](https://en.wikipedia.org/wiki/Q-day).

pqaudit detects usage of RSA, ECDSA, Ed25519, ECDH, DH, and other algorithms broken by Shor's algorithm. It also identifies already-migrated PQC usage (ML-KEM, ML-DSA, SLH-DSA) so you can track migration progress. Output as human-readable text, JSON, [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), or [SARIF](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning.

## Why now

On March 31, 2026, Google published research showing that breaking ECDSA-256 requires [20x fewer qubits than previously estimated](https://research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/) — roughly 1,200 logical qubits and under 500,000 physical qubits. NSA's CNSA 2.0 mandates PQC for new national security systems by 2027. The migration window is open but closing.

## Install

```bash
npx pqaudit ./my-project
```

Or install globally:

```bash
npm install -g pqaudit
pqaudit ./my-project
```

## Usage

```bash
# Scan current directory, human-readable output
pqaudit .

# Only show critical and high findings
pqaudit ./src --severity high

# Generate CycloneDX CBOM
pqaudit . --format cbom --output cbom.json

# Generate SARIF for GitHub Code Scanning
pqaudit . --format sarif --output results.sarif

# CI mode — exit code 1 if critical/high findings exist
pqaudit . --ci

# Skip dependency scanning
pqaudit . --no-deps

# Use custom rules
pqaudit . --rules ./my-rules.yaml
```

## Example output

```
  pqaudit — Post-Quantum Cryptography Readiness Scanner
  Scanned: ./my-project
  Date: 2026-04-01T00:00:00.000Z

  NOT PQC READY — Quantum-vulnerable cryptography detected

  Files scanned: 65  |  Findings: 18
  Critical: 12  High: 2  Medium: 1  Low: 0  Safe: 3

  --- CRITICAL (12) ---

  [!!] Ed25519 — Ed25519 signatures — elliptic curve, vulnerable to Shor's algorithm
      src/crypto/signing.ts:14
      > import { sign, verify } from "@noble/ed25519";
      Fix: ML-DSA-65 (FIPS 204) or hybrid Ed25519+ML-DSA-65
      Confidence: 90% | Effort: moderate | Via: regex
  ...
```

## What it detects

### Critical (quantum-vulnerable — must migrate)

| Algorithm | Threat | Replacement |
|-----------|--------|-------------|
| RSA (any key size) | Shor's algorithm | ML-KEM-768 / ML-DSA-65 |
| ECDSA / Ed25519 | Shor's on elliptic curves | ML-DSA-65 (FIPS 204) |
| ECDH / X25519 / DH | Shor's on key exchange | ML-KEM-768 (FIPS 203) |
| DSA | Shor's algorithm | ML-DSA-65 (FIPS 204) |

### High (weakened by quantum)

| Algorithm | Threat | Replacement |
|-----------|--------|-------------|
| AES-128 | Grover reduces to 64-bit | AES-256 |

### Safe (already quantum-resistant)

ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), AES-256, ChaCha20-Poly1305, SHA-256, SHA-3

## Output formats

### CycloneDX CBOM

Generates a [Cryptographic Bill of Materials](https://cyclonedx.org/capabilities/cbom/) conforming to CycloneDX 1.6. Each cryptographic finding becomes a `crypto-asset` component with `cryptoProperties`, NIST quantum security levels, and evidence locations.

```bash
pqaudit . --format cbom --output cbom.json
```

### SARIF (GitHub Code Scanning)

Generates SARIF 2.1.0 output compatible with GitHub's code scanning. Upload via `github/codeql-action/upload-sarif`.

```bash
pqaudit . --format sarif --output results.sarif
```

## GitHub Action

```yaml
name: PQC Audit
on: [push, pull_request]
jobs:
  pqaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx pqaudit . --format sarif --output pqaudit.sarif --ci
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: pqaudit.sarif
          category: pqaudit
```

## Dependency scanning

pqaudit checks `package.json` for known cryptographic libraries and flags quantum-vulnerable dependencies:

- `@noble/ed25519`, `@noble/secp256k1` — ECC signatures
- `tweetnacl`, `elliptic`, `node-rsa` — various asymmetric crypto
- `jsonwebtoken`, `jose` — JWT libraries (typically RSA/ECDSA)
- `@solana/web3.js`, `ethers`, `web3` — blockchain (Ed25519/secp256k1)
- `@noble/post-quantum` — flagged as **safe**

## Custom rules

Rules are defined in YAML:

```yaml
- id: MY_CUSTOM_RULE
  description: "Custom quantum-vulnerable pattern"
  severity: critical
  category: signature
  algorithm: MyAlgo
  replacement: ML-DSA-65
  effort: complex
  languages: ["javascript", "typescript"]
  patterns:
    - "myVulnerableFunction\\("
    - "import.*myVulnerableLib"
```

## Detection methods

Currently implements L0 (regex) detection. Planned:

- **L1**: AST-based analysis via tree-sitter for semantic understanding and fewer false positives
- **L2**: Data flow / taint analysis for tracing cryptographic data through call chains
- **Network scanning**: TLS/SSH endpoint analysis
- **More languages**: Cargo.toml, build.gradle, requirements.txt dependency scanning

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NSA CNSA 2.0 Timeline](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [Google PQC Migration Timeline (March 2026)](https://blog.google/innovation-and-ai/technology/safety-security/cryptography-migration-timeline/)
- [Google Quantum Vulnerability Research (March 2026)](https://research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/)

## License

MIT
