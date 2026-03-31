# pqaudit — Project Plan

## Current state (v0.1.0)

Working MVP with regex-based detection, 4 output formats, dependency scanning, 10 passing tests. Scanned a real 65-file project and found 149 critical findings correctly.

### What exists

- [x] CLI with `commander` (`npx pqaudit ./target`)
- [x] L0 regex detection engine with YAML rule definitions
- [x] 25+ rules: RSA, ECDSA, Ed25519, ECDH, DH, DSA, AES-128, MD5, SHA-1, 3DES
- [x] PQC-safe detection: ML-KEM, ML-DSA, SLH-DSA, AES-256, ChaCha20, SHA-256
- [x] npm dependency scanner (known crypto library database)
- [x] Text reporter (human-readable CLI output with severity colors)
- [x] JSON reporter
- [x] CycloneDX 1.6 CBOM reporter
- [x] SARIF 2.1.0 reporter (GitHub Code Scanning)
- [x] GitHub Action definition (`action.yml`)
- [x] `--ci` flag (exit code 1 on critical/high)
- [x] `--severity` filter
- [x] 10 passing tests (engine + CBOM)
- [x] Test fixtures (vulnerable + PQC-safe samples)

---

## What to do next

Roughly ordered by impact. Do these one at a time, ship each as its own commit/PR.

### 1. Reduce false positives from comments and strings

**Why first:** The current scanner fires on comments like `// CRITICAL: Ed25519`.
The confidence is already lower (0.3) but they still clutter output. This is the
#1 usability issue.

**What to do:**
- Add a `--min-confidence <0-100>` CLI flag, default 50
- Filter findings below the threshold before output
- This one change eliminates most comment noise without needing AST parsing

**Effort:** ~30 minutes

### 2. Deduplicate findings per file

**Why:** The scanner currently reports the same rule multiple times in the same file
if the pattern appears on different lines. For inventory purposes, you want per-file
dedup with a count.

**What to do:**
- Add a `--dedupe` flag (or make it default) that collapses findings per rule+file
- Show count: `Ed25519 — 12 occurrences in src/crypto/signing.ts`
- Keep the detailed mode available via `--no-dedupe`

**Effort:** ~1 hour

### 3. Add more dependency scanners

**Why:** npm is done but many projects use other ecosystems.

**What to do:**
- `Cargo.toml` / `Cargo.lock` scanner (detect `ed25519-dalek`, `ring`, `rsa`, `p256`, etc.)
- `go.mod` scanner (detect `crypto/ecdsa`, `crypto/rsa`, `golang.org/x/crypto`)
- `requirements.txt` / `pyproject.toml` (detect `cryptography`, `pycryptodome`, `ecdsa`)
- `build.gradle` / `pom.xml` (detect BouncyCastle, JCA usage patterns)

**Effort:** ~2-3 hours per ecosystem

### 4. Add protocol/config detection rules

**Why:** Many crypto decisions live in config files, not code.

**What to do:**
- TLS cipher suite patterns in nginx/apache/haproxy configs
- SSH key type patterns in `sshd_config` / `ssh_config`
- JWT `algorithm` fields in config files
- Dockerfile patterns (OpenSSL versions, crypto library installs)
- Kubernetes TLS secret references

**Effort:** ~2 hours (just more YAML rules)

### 5. HTML report

**Why:** Shareable, visual, good for stakeholders who won't use a CLI.

**What to do:**
- Single self-contained HTML file (inline CSS, no external deps)
- Summary dashboard: pie chart of severity, PQC readiness score
- Findings table with severity badges, file links, replacement guidance
- Migration effort estimate (total hours based on effort ratings)

**Effort:** ~3-4 hours

### 6. AST-level scanning (L1)

**Why:** Regex catches patterns in comments, strings, and variable names. AST
parsing understands code structure — only flags actual crypto API calls.

**What to do:**
- Add `tree-sitter` with `tree-sitter-javascript`, `tree-sitter-typescript` parsers
- For each file, parse AST, walk import declarations and call expressions
- Match crypto API calls by library + function name + arguments
- Assign higher confidence (0.9+) to AST findings vs regex (0.7)

**Effort:** ~1-2 days. Start with JS/TS only since that's your primary ecosystem.

### 7. Scan popular open-source projects and publish results

**Why:** This is what generates attention. Pick 10 well-known projects, scan them,
write up the findings responsibly (don't publish exploit details, just inventory).

**Suggestions:**
- Signal Desktop (should be partially PQC already — PQXDH)
- Express.js / Fastify (TLS, JWT middleware ecosystem)
- Next.js (common JWT/auth patterns)
- Prisma (database connection TLS)
- A Solana program (Ed25519 everywhere)
- An Ethereum DApp (secp256k1)
- OpenSSL bindings for Node.js

**Effort:** ~1 day for scanning + writeup

### 8. npm publish

**Why:** `npx pqaudit .` should just work.

**What to do:**
- `npm run build` to verify dist/ output
- `npm publish` (need npm account + 2FA)
- Test `npx pqaudit` from a different directory
- Add shields.io badges to README (npm version, tests passing, license)

**Effort:** ~30 minutes

### 9. GitHub Actions workflow for pqaudit itself

**Why:** Eat your own dogfood. Run pqaudit on pqaudit in CI.

**What to do:**
- `.github/workflows/ci.yml` — build, test, lint
- `.github/workflows/pqaudit.yml` — run pqaudit on itself, upload SARIF
- This also serves as a working example for users

**Effort:** ~30 minutes

### 10. Contribution guide + issue templates

**Why:** Open source lives on contributors. Make it easy for people to add rules
for their language/ecosystem.

**What to do:**
- `CONTRIBUTING.md` — how to add rules, how to add a language scanner, how to run tests
- Issue templates: "New detection rule request", "False positive report", "Language support request"
- Label scheme: `rule-request`, `false-positive`, `language-support`, `good-first-issue`

**Effort:** ~1 hour

---

## Longer-term roadmap

These are bigger lifts for after the core is solid.

### Network scanning
Probe live TLS/SSH endpoints for cipher suite support and certificate algorithms.
Similar to pqcscan (Anvil Secure) but integrated into the same tool and CBOM output.

### SBOM integration
Accept an existing SBOM (CycloneDX or SPDX) as input. Enrich it with cryptographic
findings to produce a combined SBOM+CBOM. This is what enterprises want for
compliance reporting.

### Policy engine
Define organizational crypto policies in YAML (e.g., "no RSA after 2027-01-01",
"ML-DSA required for all signing by 2028"). Scanner checks code against policy and
reports violations. This is the path to the enterprise/commercial tier.

### Migration automation
Given a finding, generate a code diff that replaces the vulnerable crypto with PQC.
Start with simple cases (swap `@noble/ed25519` import for `@noble/post-quantum/ml-dsa`).
This is the hardest but most valuable feature.

---

## Competitive positioning

| Tool | Code scan | Deps | CBOM | SARIF | JS/TS | Network | License |
|------|-----------|------|------|-------|-------|---------|---------|
| **pqaudit** | L0 regex (L1 planned) | npm | Yes | Yes | **Yes** | Planned | MIT |
| PQSwitch | L0+L1+L2 | No | No | Yes | Partial | No | Apache-2.0 |
| CBOMkit-hyperion | L1 (Sonar) | No | Yes | No | **No** | No | Apache-2.0 |
| CBOMkit-theia | Binary/FS | No | Yes | No | N/A | No | Apache-2.0 |
| pqcscan | No | No | No | No | N/A | SSH/TLS | BSD-2 |
| Wind River | L0 regex | No | No | No | No | No | Apache-2.0 |
| SandboxAQ | Full | Full | Yes | Unknown | Yes | Yes | Commercial |

**pqaudit's niche:** The only open-source tool with JS/TS support + CBOM + SARIF +
dependency scanning in a single `npx` command.
