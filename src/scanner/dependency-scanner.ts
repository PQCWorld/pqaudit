import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";

/** Known npm packages and their cryptographic implications */
const KNOWN_CRYPTO_PACKAGES: Record<
  string,
  { algorithm: string; severity: Finding["severity"]; category: Finding["category"]; description: string; replacement: string | null }
> = {
  // PQC-safe libraries
  "@noble/post-quantum": {
    algorithm: "ML-KEM / ML-DSA",
    severity: "safe",
    category: "kem",
    description: "Post-quantum cryptography library (ML-KEM, ML-DSA, SLH-DSA)",
    replacement: null,
  },

  // Quantum-vulnerable signature libraries
  "@noble/ed25519": {
    algorithm: "Ed25519",
    severity: "critical",
    category: "signature",
    description: "Ed25519 signatures — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via @noble/post-quantum",
  },
  "@noble/secp256k1": {
    algorithm: "secp256k1 (ECDSA)",
    severity: "critical",
    category: "signature",
    description: "secp256k1 ECDSA — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via @noble/post-quantum",
  },
  "tweetnacl": {
    algorithm: "Ed25519 / X25519",
    severity: "critical",
    category: "signature",
    description: "NaCl crypto (Ed25519 signatures, X25519 key exchange) — both quantum-vulnerable",
    replacement: "ML-DSA-65 + ML-KEM-768 via @noble/post-quantum",
  },
  "elliptic": {
    algorithm: "ECDSA / ECDH",
    severity: "critical",
    category: "signature",
    description: "Elliptic curve library — all ECC is quantum-vulnerable",
    replacement: "ML-DSA-65 + ML-KEM-768",
  },
  "node-rsa": {
    algorithm: "RSA",
    severity: "critical",
    category: "kem",
    description: "RSA encryption/signatures — vulnerable to Shor's algorithm",
    replacement: "ML-KEM-768 + ML-DSA-65",
  },
  "jsonwebtoken": {
    algorithm: "RS256/ES256 (likely)",
    severity: "critical",
    category: "signature",
    description: "JWT library — likely uses RSA or ECDSA for signing",
    replacement: "Consider ML-DSA-based JWT signing when IETF PQC JWT standards emerge",
  },
  "jose": {
    algorithm: "RS256/ES256 (configurable)",
    severity: "critical",
    category: "signature",
    description: "JOSE/JWT library — supports RSA and ECDSA signing",
    replacement: "Monitor IETF PQC JWT standards progress",
  },

  // Solana/blockchain (quantum-vulnerable by design)
  "@solana/web3.js": {
    algorithm: "Ed25519 (Solana)",
    severity: "critical",
    category: "signature",
    description: "Solana Web3 — all Solana keys are Ed25519, quantum-vulnerable",
    replacement: "Blocked by Solana ecosystem PQC migration. Monitor Solana PQC proposals.",
  },
  "ethers": {
    algorithm: "secp256k1 (Ethereum)",
    severity: "critical",
    category: "signature",
    description: "Ethers.js — Ethereum uses secp256k1 ECDSA, quantum-vulnerable",
    replacement: "Blocked by Ethereum PQC migration. Monitor EIP proposals.",
  },
  "web3": {
    algorithm: "secp256k1 (Ethereum)",
    severity: "critical",
    category: "signature",
    description: "Web3.js — Ethereum uses secp256k1 ECDSA, quantum-vulnerable",
    replacement: "Blocked by Ethereum PQC migration. Monitor EIP proposals.",
  },

  // Symmetric / safe
  "libsodium-wrappers": {
    algorithm: "XChaCha20-Poly1305 / Ed25519",
    severity: "critical",
    category: "signature",
    description: "libsodium — symmetric crypto is safe but Ed25519/X25519 are quantum-vulnerable",
    replacement: "Audit usage: keep symmetric ops, migrate asymmetric to PQC",
  },
};

export function scanNpmDependencies(targetDir: string): Finding[] {
  const packageJsonPath = join(targetDir, "package.json");
  if (!existsSync(packageJsonPath)) return [];

  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const known = KNOWN_CRYPTO_PACKAGES[name];
    if (!known) continue;

    findings.push({
      ruleId: `DEP_${name.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`,
      description: known.description,
      severity: known.severity,
      category: known.category,
      algorithm: known.algorithm,
      replacement: known.replacement,
      effort: "complex",
      location: {
        file: "package.json",
        snippet: `"${name}": "${version}"`,
      },
      detectionMethod: "dependency",
      confidence: 0.95,
    });
  }

  return findings;
}

// TODO: Add scanCargoDependencies, scanGradleDependencies, scanPipDependencies
