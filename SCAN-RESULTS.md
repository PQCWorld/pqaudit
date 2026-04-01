# pqaudit Scan Results: 8 Popular Open-Source Projects

> Scanned on 2026-04-01 using pqaudit v0.2.0 (dedupe on, min-confidence 50)
> All repos cloned at HEAD (shallow clone, `--depth 1`)

## Summary

| Project | Files | Critical | High | Safe | PQC Ready | Vulnerable Algorithms |
|---------|------:|----------|------|------|-----------|----------------------|
| [Express](https://github.com/expressjs/express) | 142 | 0 | 0 | 0 | Yes | — |
| [Fastify](https://github.com/fastify/fastify) | 295 | 1 | 0 | 0 | No | RSA |
| [Next.js](https://github.com/vercel/next.js) | 22,478 | 17 | 1 | 44 | No | ECDSA, RSA, ECDH, Ed25519, DH, AES-128 |
| [Prisma](https://github.com/prisma/prisma) | 3,291 | 0 | 0 | 9 | Yes | — |
| [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) | 65 | 21 | 0 | 0 | No | RSA, ECDSA |
| [Solana web3.js](https://github.com/solana-labs/solana-web3.js) | 104 | 17 | 0 | 8 | No | ECDSA, Ed25519 |
| [Ethereum web3.js](https://github.com/ethereum/web3.js) | 1,194 | 12 | 3 | 62 | No | ECDSA, AES-128 |
| [Signal Desktop](https://github.com/signalapp/Signal-Desktop) | 2,854 | 12 | 0 | 50 | No | ECDH, ECDSA |

**30,423 files scanned across 8 projects. 6 of 8 are NOT quantum-ready.**

---

## Per-Project Details

### Express — PQC Ready
Express is a minimal HTTP framework with no built-in cryptographic operations. Zero quantum-vulnerable findings.

### Fastify — 1 critical finding
Single RSA-2048 key generation in a test helper:
```
[!!] RSA — test/build-certificate.js:20
     > forge.pki.rsa.generateKeyPair(options.bits || 2048)
     Fix: ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)
```

### Next.js — 17 critical, 1 high
Findings concentrated in compiled vendor bundles (`packages/next/src/compiled/`), not Next.js core:
- **crypto-browserify** bundle contains RSA, ECDSA, Ed25519, ECDH, DH polyfills
- **Compiled jsonwebtoken** references RS256/ES256
- **constants-browserify** exposes RSA padding and ECDSA engine constants
- **1 high**: AES-128 in crypto-browserify (Grover reduces to 64-bit)

### Prisma — PQC Ready
Zero quantum-vulnerable findings. Prisma delegates crypto to the database and TLS runtime.

### jsonwebtoken — 21 critical findings
The most finding-dense project (21 findings in 65 files). JWT is built on RSA and ECDSA:
- `sign.js` and `verify.js` define RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512
- `validateAsymmetricKey.js` validates RSA and EC key types
- Test suite exercises all algorithm variants (80+ total occurrences before dedupe)

This library will need significant rework for post-quantum JWT algorithms.

### Solana web3.js — 17 critical findings
Ed25519 is Solana's foundation:
- `src/account.ts`, `src/keypair.ts`, `src/transaction/` — Ed25519 throughout
- `src/programs/ed25519.ts` — dedicated Ed25519 program module
- `src/programs/secp256k1.ts` — secp256k1 ECDSA program (26 occurrences)

Migration is blocked by Solana protocol-level Ed25519 dependency.

### Ethereum web3.js — 12 critical, 3 high
secp256k1 ECDSA dominates:
- `web3-eth-accounts/src/account.ts` — secp256k1 signing (6 occurrences)
- `web3-eth-accounts/src/tx/` — transaction signing throughout
- **3 high**: AES-128 usage in multiple packages

Migration blocked by Ethereum's secp256k1 dependency.

### Signal Desktop — 12 critical findings
X25519 key exchange and ECDSA detected:
- `sticker-creator/` uses `@stablelib/x25519` for provisioning
- Multiple X25519 references across crypto utilities
- Note: Signal has deployed PQXDH (post-quantum extended Diffie-Hellman) in the Signal Protocol, but the desktop app still has classical crypto references in sticker creation and some utility code.

---

## Key Takeaways

1. **6 of 8 popular projects are NOT quantum-ready.** Only Express and Prisma — both of which delegate crypto to the runtime — pass.

2. **JWT is a systemic risk.** jsonwebtoken has 21 critical findings in 65 files. Every app using RS256/ES256 JWTs inherits this vulnerability.

3. **Blockchain libraries are the most exposed.** Solana (Ed25519) and Ethereum (secp256k1) are quantum-vulnerable by design. Migration requires protocol-level changes.

4. **Vendor bundles inherit vulnerabilities.** Next.js has 17 critical findings, but all come from compiled dependencies (crypto-browserify, jsonwebtoken), not from Next.js source code.

5. **Signal is partially migrated.** Signal Protocol has PQXDH, but the desktop app still has classical crypto in sticker creation and provisioning.

6. **PQC adoption is near zero** in the npm ecosystem. No project uses ML-KEM or ML-DSA yet.

---

Reproduce these results: `npx pqaudit ./any-project`
