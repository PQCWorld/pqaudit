# pqaudit Scan Results: 8 Popular Open-Source Projects

> Scanned on 2026-04-07 using pqaudit v0.3.0+ (AST + regex, dedupe on, min-confidence 50)
> All repos cloned at HEAD (shallow clone, `--depth 1`)
> Previous scan: 2026-04-01 with v0.2.0 (regex only)

## Summary

| Project | Files | Critical | High | Medium | Safe | PQC Ready | Detection | Vulnerable Algorithms |
|---------|------:|----------|------|--------|------|-----------|-----------|----------------------|
| [Express](https://github.com/expressjs/express) | 142 | 0 | 0 | 92 | 0 | Yes | regex | — |
| [Fastify](https://github.com/fastify/fastify) | 295 | 1 | 0 | 71 | 0 | No | ast+regex | RSA |
| [Next.js](https://github.com/vercel/next.js) | 22,535 | 19 | 1 | 3,469 | 36 | No | ast+regex | RSA, ECDSA, ECDH, Ed25519, DH, AES-128 |
| [Prisma](https://github.com/prisma/prisma) | 3,297 | 0 | 0 | 566 | 9 | Yes | ast+regex | — |
| [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) | 65 | 24 | 0 | 38 | 0 | No | ast+regex | RSA, ECDSA |
| [Solana web3.js](https://github.com/solana-labs/solana-web3.js) | 104 | 17 | 0 | 41 | 8 | No | regex | ECDSA, Ed25519 |
| [Ethereum web3.js](https://github.com/web3/web3.js) | 1,194 | 54 | 3 | 522 | 62 | No | ast+regex | ECDSA, AES-128 |
| [Signal Desktop](https://github.com/signalapp/Signal-Desktop) | 2,862 | 12 | 0 | 1,036 | 52 | No | ast+regex | ECDH, ECDSA |

**30,494 files scanned across 8 projects. 6 of 8 are NOT quantum-ready.**

### Changes from v0.2.0 scan

| Project | v0.2.0 Critical | v0.3.0 Critical | Delta | Notes |
|---------|:-:|:-:|:-:|-------|
| Express | 0 | 0 | — | Still clean |
| Fastify | 1 | 1 | — | AST now confirms the RSA finding |
| Next.js | 17 | 19 | +2 | AST found 2 additional confirmed crypto API calls |
| Prisma | 0 | 0 | — | Still clean, AST found 4 safe inventory items |
| jsonwebtoken | 21 | 24 | +3 | AST confirmed JWT signing patterns in tests |
| Solana web3.js | 17 | 17 | — | Unchanged |
| Ethereum web3.js | 12 | 54 | +42 | AST surfaced ECDSA usage across test suites |
| Signal Desktop | 12 | 12 | — | Unchanged |

AST scanning improved detection quality: findings confirmed via AST have 0.95-0.98 confidence vs 0.7-0.85 for regex alone. False positives from comments are eliminated.

---

## Per-Project Details

### Express — PQC Ready
Express is a minimal HTTP framework with no built-in cryptographic operations. Zero quantum-vulnerable findings. The 92 medium findings are SHA-1/MD5 references in documentation and comments.

### Fastify — 1 critical finding
Single RSA-2048 key generation in a test helper, now confirmed by AST:
```
[!!] RSA — test/build-certificate.js:20
     > forge.pki.rsa.generateKeyPair(options.bits || 2048)
     Fix: ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)
     Confidence: 96% | Via: ast
```

### Next.js — 19 critical, 1 high
Findings concentrated in compiled vendor bundles, not Next.js core:
- **crypto-browserify** bundle contains RSA, ECDSA, Ed25519, ECDH, DH polyfills — AST confirmed actual function calls
- **Compiled jsonwebtoken** references RS256/ES256 — AST confirmed JWT signing patterns
- **constants-browserify** exposes RSA padding and ECDSA engine constants
- **1 high**: AES-128 in crypto-browserify
- **36 AST findings** provided high-confidence structural confirmation

### Prisma — PQC Ready
Zero quantum-vulnerable findings. Prisma delegates crypto to the database and TLS runtime. AST scanning found 4 safe SHA-256 usage patterns for inventory.

### jsonwebtoken — 24 critical findings
The most finding-dense project (24 findings in 65 files). JWT is built on RSA and ECDSA:
- `sign.js` and `verify.js` define RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512
- `validateAsymmetricKey.js` validates RSA and EC key types
- AST confirmed 9 actual crypto API calls in test suite (generateKeyPairSync, jwt.sign with algorithm options)
- 80+ total occurrences before dedupe

This library will need significant rework for post-quantum JWT algorithms.

### Solana web3.js — 17 critical findings
Ed25519 is Solana's foundation:
- `src/account.ts`, `src/keypair.ts`, `src/transaction/` — Ed25519 throughout
- `src/programs/ed25519.ts` — dedicated Ed25519 program module
- `src/programs/secp256k1.ts` — secp256k1 ECDSA program (26 occurrences)
- 8 safe findings (SHA-256 inventory)

Migration is blocked by Solana protocol-level Ed25519 dependency.

### Ethereum web3.js — 54 critical, 3 high
secp256k1 ECDSA dominates. AST scanning surfaced significantly more findings:
- `web3-eth-accounts/src/account.ts` — secp256k1 signing
- `web3-eth-accounts/test/` — 42 AST-confirmed ECDSA usages across test suites
- `web3-eth-contract/` — ECDSA in contract interaction tests
- **3 high**: AES-128 usage in multiple packages
- **62 safe findings** (SHA-256, SHA-3 inventory)

Migration blocked by Ethereum's secp256k1 dependency.

### Signal Desktop — 12 critical findings
X25519 key exchange and ECDSA detected:
- `sticker-creator/` uses `@stablelib/x25519` for provisioning
- Multiple X25519 references across crypto utilities
- AST confirmed 1 SHA-256 safe usage in updater signature verification
- Note: Signal has deployed PQXDH (post-quantum extended Diffie-Hellman) in the Signal Protocol, but the desktop app still has classical crypto references in sticker creation and some utility code.

---

## Key Takeaways

1. **6 of 8 popular projects are NOT quantum-ready.** Only Express and Prisma — both of which delegate crypto to the runtime — pass.

2. **AST scanning reveals more confirmed vulnerabilities.** v0.3.0 found 42 additional critical findings in Ethereum web3.js alone by parsing actual code structure rather than just text matching. All confirmed at 0.95+ confidence.

3. **JWT is a systemic risk.** jsonwebtoken has 24 critical findings in 65 files. Every app using RS256/ES256 JWTs inherits this vulnerability. AST confirmed actual jwt.sign() calls with vulnerable algorithm options.

4. **Blockchain libraries are the most exposed.** Solana (Ed25519) and Ethereum (secp256k1) are quantum-vulnerable by design. Migration requires protocol-level changes.

5. **Vendor bundles inherit vulnerabilities.** Next.js has 19 critical findings, but all come from compiled dependencies (crypto-browserify, jsonwebtoken), not from Next.js source code.

6. **Signal is partially migrated.** Signal Protocol has PQXDH, but the desktop app still has classical crypto in sticker creation and provisioning.

7. **PQC adoption is near zero** in the npm ecosystem. No project uses ML-KEM or ML-DSA yet. Only `@noble/post-quantum` exists as an option.

---

Reproduce these results: `npx pqaudit ./any-project`
