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

/** Known Cargo crates and their cryptographic implications */
const KNOWN_CRYPTO_CRATES: Record<
  string,
  { algorithm: string; severity: Finding["severity"]; category: Finding["category"]; description: string; replacement: string | null }
> = {
  "ed25519-dalek": {
    algorithm: "Ed25519",
    severity: "critical",
    category: "signature",
    description: "Ed25519 signatures — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via pqcrypto crate",
  },
  "rsa": {
    algorithm: "RSA",
    severity: "critical",
    category: "kem",
    description: "RSA encryption/signatures — vulnerable to Shor's algorithm",
    replacement: "ML-KEM-768 + ML-DSA-65 via pqcrypto crate",
  },
  "p256": {
    algorithm: "ECDSA (P-256)",
    severity: "critical",
    category: "signature",
    description: "ECDSA P-256 signatures — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via pqcrypto crate",
  },
  "p384": {
    algorithm: "ECDSA (P-384)",
    severity: "critical",
    category: "signature",
    description: "ECDSA P-384 signatures — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via pqcrypto crate",
  },
  "x25519-dalek": {
    algorithm: "X25519",
    severity: "critical",
    category: "kem",
    description: "X25519 key exchange — vulnerable to Shor's algorithm",
    replacement: "ML-KEM-768 via pqcrypto crate",
  },
  "ring": {
    algorithm: "RSA/ECDSA/Ed25519",
    severity: "critical",
    category: "signature",
    description: "ring crypto library — contains quantum-vulnerable RSA, ECDSA, Ed25519",
    replacement: "Audit usage: migrate asymmetric operations to pqcrypto crate",
  },
  "secp256k1": {
    algorithm: "secp256k1",
    severity: "critical",
    category: "signature",
    description: "secp256k1 ECDSA — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via pqcrypto crate",
  },
  "pqcrypto": {
    algorithm: "ML-KEM/ML-DSA",
    severity: "safe",
    category: "kem",
    description: "Post-quantum cryptography library (ML-KEM, ML-DSA)",
    replacement: null,
  },
  "oqs": {
    algorithm: "PQC",
    severity: "safe",
    category: "kem",
    description: "Open Quantum Safe — post-quantum cryptography bindings",
    replacement: null,
  },
};

export function scanCargoDependencies(targetDir: string): Finding[] {
  const cargoTomlPath = join(targetDir, "Cargo.toml");
  if (!existsSync(cargoTomlPath)) return [];

  let content: string;
  try {
    content = readFileSync(cargoTomlPath, "utf-8");
  } catch {
    return [];
  }

  const findings: Finding[] = [];

  // Parse [dependencies] section entries
  // Match lines like: crate-name = "version" or crate-name = { version = "..." }
  for (const [crateName, known] of Object.entries(KNOWN_CRYPTO_CRATES)) {
    // Match: crateName = "version" or crateName = { ... }
    const pattern = new RegExp(`^\\s*${crateName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*(.+)`, "m");
    const match = content.match(pattern);
    if (!match) continue;

    const versionLine = match[1].trim();
    // Extract version string from either "version" or { version = "version", ... }
    const versionMatch = versionLine.match(/^"([^"]*)"/) ?? versionLine.match(/version\s*=\s*"([^"]*)"/);
    const version = versionMatch ? versionMatch[1] : "unknown";

    findings.push({
      ruleId: `DEP_CRATE_${crateName.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`,
      description: known.description,
      severity: known.severity,
      category: known.category,
      algorithm: known.algorithm,
      replacement: known.replacement,
      effort: "complex",
      location: {
        file: "Cargo.toml",
        snippet: `${crateName} = "${version}"`,
      },
      detectionMethod: "dependency",
      confidence: 0.95,
    });
  }

  return findings;
}

/** Known Go modules and their cryptographic implications */
const KNOWN_CRYPTO_GO_MODULES: Record<
  string,
  { algorithm: string; severity: Finding["severity"]; category: Finding["category"]; description: string; replacement: string | null }
> = {
  "golang.org/x/crypto": {
    algorithm: "Ed25519/Curve25519 (mixed)",
    severity: "critical",
    category: "signature",
    description: "Go extended crypto — contains quantum-vulnerable Ed25519, Curve25519",
    replacement: "Audit usage: migrate asymmetric operations to github.com/cloudflare/circl",
  },
  "github.com/btcsuite/btcd": {
    algorithm: "secp256k1",
    severity: "critical",
    category: "signature",
    description: "btcd Bitcoin library — secp256k1 ECDSA, quantum-vulnerable",
    replacement: "Blocked by Bitcoin ecosystem PQC migration",
  },
  "filippo.io/edwards25519": {
    algorithm: "Ed25519",
    severity: "critical",
    category: "signature",
    description: "Ed25519 curve implementation — vulnerable to Shor's algorithm",
    replacement: "ML-DSA-65 via github.com/cloudflare/circl",
  },
  "github.com/cloudflare/circl": {
    algorithm: "PQC (Kyber/Dilithium)",
    severity: "safe",
    category: "kem",
    description: "Cloudflare CIRCL — post-quantum cryptography support (Kyber, Dilithium)",
    replacement: null,
  },
  "go.dedis.ch/kyber": {
    algorithm: "Kyber",
    severity: "safe",
    category: "kem",
    description: "DEDIS Kyber — post-quantum key encapsulation",
    replacement: null,
  },
};

export function scanGoDependencies(targetDir: string): Finding[] {
  const goModPath = join(targetDir, "go.mod");
  if (!existsSync(goModPath)) return [];

  let content: string;
  try {
    content = readFileSync(goModPath, "utf-8");
  } catch {
    return [];
  }

  const findings: Finding[] = [];

  // Parse require block and single require lines
  // Matches both: require ( ... ) blocks and require module version lines
  for (const [moduleName, known] of Object.entries(KNOWN_CRYPTO_GO_MODULES)) {
    // Match module path in require blocks or standalone require lines
    // e.g., "golang.org/x/crypto v0.14.0" or "require golang.org/x/crypto v0.14.0"
    const escapedName = moduleName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`^\\s*${escapedName}(?:/\\S*)?\\s+(v[^\\s]+)`, "m");
    const match = content.match(pattern);
    if (!match) continue;

    const version = match[1];

    findings.push({
      ruleId: `DEP_GO_${moduleName.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`,
      description: known.description,
      severity: known.severity,
      category: known.category,
      algorithm: known.algorithm,
      replacement: known.replacement,
      effort: "complex",
      location: {
        file: "go.mod",
        snippet: `${moduleName} ${version}`,
      },
      detectionMethod: "dependency",
      confidence: 0.95,
    });
  }

  return findings;
}

/** Known Python packages and their cryptographic implications */
const KNOWN_CRYPTO_PIP_PACKAGES: Record<
  string,
  { algorithm: string; severity: Finding["severity"]; category: Finding["category"]; description: string; replacement: string | null }
> = {
  "cryptography": {
    algorithm: "RSA/ECDSA/DH",
    severity: "critical",
    category: "kem",
    description: "Python cryptography library — default algorithms (RSA, ECDSA, DH) are quantum-vulnerable",
    replacement: "Audit usage: migrate asymmetric operations to pqcrypto or liboqs-python",
  },
  "pycryptodome": {
    algorithm: "RSA/AES/DH",
    severity: "critical",
    category: "kem",
    description: "PyCryptodome — RSA and DH are quantum-vulnerable",
    replacement: "Audit usage: keep symmetric ops, migrate asymmetric to pqcrypto",
  },
  "pycryptodomex": {
    algorithm: "RSA/AES/DH",
    severity: "critical",
    category: "kem",
    description: "PyCryptodomex — RSA and DH are quantum-vulnerable",
    replacement: "Audit usage: keep symmetric ops, migrate asymmetric to pqcrypto",
  },
  "pynacl": {
    algorithm: "Ed25519/X25519",
    severity: "critical",
    category: "signature",
    description: "PyNaCl — Ed25519 signatures and X25519 key exchange are quantum-vulnerable",
    replacement: "ML-DSA-65 + ML-KEM-768 via pqcrypto",
  },
  "ecdsa": {
    algorithm: "ECDSA",
    severity: "critical",
    category: "signature",
    description: "ECDSA library — all elliptic curve signatures are quantum-vulnerable",
    replacement: "ML-DSA-65 via pqcrypto",
  },
  "rsa": {
    algorithm: "RSA",
    severity: "critical",
    category: "kem",
    description: "RSA library — vulnerable to Shor's algorithm",
    replacement: "ML-KEM-768 + ML-DSA-65 via pqcrypto",
  },
  "paramiko": {
    algorithm: "RSA/ECDSA SSH",
    severity: "critical",
    category: "kem",
    description: "Paramiko SSH library — uses RSA and ECDSA for SSH, quantum-vulnerable",
    replacement: "Monitor OpenSSH PQC migration for Paramiko support",
  },
  "pyopenssl": {
    algorithm: "RSA/ECDSA",
    severity: "critical",
    category: "kem",
    description: "pyOpenSSL — RSA and ECDSA operations are quantum-vulnerable",
    replacement: "Audit usage: migrate asymmetric operations to pqcrypto or liboqs-python",
  },
  "pqcrypto": {
    algorithm: "PQC",
    severity: "safe",
    category: "kem",
    description: "Post-quantum cryptography library for Python",
    replacement: null,
  },
  "liboqs-python": {
    algorithm: "PQC",
    severity: "safe",
    category: "kem",
    description: "Open Quantum Safe Python bindings — post-quantum cryptography",
    replacement: null,
  },
};

export function scanPipDependencies(targetDir: string): Finding[] {
  const findings: Finding[] = [];

  // Scan requirements.txt
  const requirementsPath = join(targetDir, "requirements.txt");
  if (existsSync(requirementsPath)) {
    try {
      const content = readFileSync(requirementsPath, "utf-8");
      const lines = content.split("\n");

      for (const line of lines) {
        const trimmed = line.trim();
        // Skip comments and empty lines
        if (!trimmed || trimmed.startsWith("#")) continue;

        // Parse package==version, package>=version, package<=version, package~=version, package!=version, or just package
        const pkgMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:[><=!~]+\s*(\S+))?/);
        if (!pkgMatch) continue;

        const pkgName = pkgMatch[1].toLowerCase();
        const version = pkgMatch[2] ?? "unknown";

        // Check against known packages (case-insensitive)
        const known = KNOWN_CRYPTO_PIP_PACKAGES[pkgName];
        if (!known) continue;

        findings.push({
          ruleId: `DEP_PIP_${pkgName.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`,
          description: known.description,
          severity: known.severity,
          category: known.category,
          algorithm: known.algorithm,
          replacement: known.replacement,
          effort: "complex",
          location: {
            file: "requirements.txt",
            snippet: `${pkgName}==${version}`,
          },
          detectionMethod: "dependency",
          confidence: 0.95,
        });
      }
    } catch {
      // Ignore read errors
    }
  }

  // Scan pyproject.toml
  const pyprojectPath = join(targetDir, "pyproject.toml");
  if (existsSync(pyprojectPath)) {
    try {
      const content = readFileSync(pyprojectPath, "utf-8");

      for (const [pkgName, known] of Object.entries(KNOWN_CRYPTO_PIP_PACKAGES)) {
        // Match package name in dependencies array: "pkgname>=version" or "pkgname==version" etc.
        const escapedName = pkgName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const pattern = new RegExp(`["']${escapedName}\\s*(?:[><=!~]+\\s*([^"']+))?["']`, "i");
        const match = content.match(pattern);
        if (!match) continue;

        const version = match[1]?.trim() ?? "unknown";

        // Avoid duplicate if already found in requirements.txt
        const ruleId = `DEP_PIP_${pkgName.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`;
        if (findings.some((f) => f.ruleId === ruleId)) continue;

        findings.push({
          ruleId,
          description: known.description,
          severity: known.severity,
          category: known.category,
          algorithm: known.algorithm,
          replacement: known.replacement,
          effort: "complex",
          location: {
            file: "pyproject.toml",
            snippet: `${pkgName}>=${version}`,
          },
          detectionMethod: "dependency",
          confidence: 0.95,
        });
      }
    } catch {
      // Ignore read errors
    }
  }

  return findings;
}

/** Known Java/Gradle/Maven packages and their cryptographic implications */
const KNOWN_CRYPTO_JAVA_PACKAGES: Record<
  string,
  { algorithm: string; severity: Finding["severity"]; category: Finding["category"]; description: string; replacement: string | null; artifactPattern: RegExp }
> = {
  "org.bouncycastle:bcprov": {
    algorithm: "RSA/ECDSA/DH",
    severity: "critical",
    category: "kem",
    description: "Bouncy Castle provider — RSA, ECDSA, DH are quantum-vulnerable",
    replacement: "Migrate to org.bouncycastle:bcpqc-jdk* for post-quantum algorithms",
    artifactPattern: /bcprov-jdk\w*/,
  },
  "org.bouncycastle:bcpkix": {
    algorithm: "RSA/ECDSA certificates",
    severity: "critical",
    category: "signature",
    description: "Bouncy Castle PKIX — RSA and ECDSA certificate operations are quantum-vulnerable",
    replacement: "Migrate to PQC certificate algorithms when available",
    artifactPattern: /bcpkix-jdk\w*/,
  },
  "org.bouncycastle:bcpqc": {
    algorithm: "PQC (Kyber/Dilithium)",
    severity: "safe",
    category: "kem",
    description: "Bouncy Castle PQC — post-quantum cryptography (Kyber, Dilithium)",
    replacement: null,
    artifactPattern: /bcpqc-jdk\w*/,
  },
  "com.google.crypto.tink:tink": {
    algorithm: "RSA/ECDSA (configurable)",
    severity: "critical",
    category: "signature",
    description: "Google Tink — default configurations use RSA and ECDSA, quantum-vulnerable",
    replacement: "Monitor Tink PQC support progress",
    artifactPattern: /tink/,
  },
};

export function scanGradleDependencies(targetDir: string): Finding[] {
  const findings: Finding[] = [];
  const foundRuleIds = new Set<string>();

  // Scan Gradle files (build.gradle and build.gradle.kts)
  const gradleFiles = ["build.gradle", "build.gradle.kts"];
  for (const gradleFile of gradleFiles) {
    const gradlePath = join(targetDir, gradleFile);
    if (!existsSync(gradlePath)) continue;

    let content: string;
    try {
      content = readFileSync(gradlePath, "utf-8");
    } catch {
      continue;
    }

    for (const [key, known] of Object.entries(KNOWN_CRYPTO_JAVA_PACKAGES)) {
      const [groupId, _artifactPrefix] = key.split(":");
      const escapedGroup = groupId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      // Match Gradle dependency declarations:
      // implementation 'group:artifact:version'
      // implementation "group:artifact:version"
      // implementation("group:artifact:version")
      const pattern = new RegExp(
        `(?:implementation|api|compile|runtimeOnly|compileOnly)\\s*[("']+${escapedGroup}:(${known.artifactPattern.source}):([^"')]+)["')]`,
        "g",
      );

      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        const artifact = match[1];
        const version = match[2];
        const ruleId = `DEP_MAVEN_${groupId.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_${artifact.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`;

        if (foundRuleIds.has(ruleId)) continue;
        foundRuleIds.add(ruleId);

        findings.push({
          ruleId,
          description: known.description,
          severity: known.severity,
          category: known.category,
          algorithm: known.algorithm,
          replacement: known.replacement,
          effort: "complex",
          location: {
            file: gradleFile,
            snippet: `${groupId}:${artifact}:${version}`,
          },
          detectionMethod: "dependency",
          confidence: 0.95,
        });
      }
    }
  }

  // Scan Maven pom.xml
  const pomPath = join(targetDir, "pom.xml");
  if (existsSync(pomPath)) {
    let content: string;
    try {
      content = readFileSync(pomPath, "utf-8");
    } catch {
      return findings;
    }

    // Match <groupId>...</groupId> followed by <artifactId>...</artifactId> patterns
    const depPattern = /<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/g;

    let match: RegExpExecArray | null;
    while ((match = depPattern.exec(content)) !== null) {
      const groupId = match[1].trim();
      const artifactId = match[2].trim();
      const version = match[3]?.trim() ?? "unknown";

      // Check against known packages
      for (const [key, known] of Object.entries(KNOWN_CRYPTO_JAVA_PACKAGES)) {
        const [knownGroup, _knownArtifactPrefix] = key.split(":");

        if (groupId !== knownGroup) continue;
        if (!known.artifactPattern.test(artifactId)) continue;

        const ruleId = `DEP_MAVEN_${groupId.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_${artifactId.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`;

        if (foundRuleIds.has(ruleId)) continue;
        foundRuleIds.add(ruleId);

        findings.push({
          ruleId,
          description: known.description,
          severity: known.severity,
          category: known.category,
          algorithm: known.algorithm,
          replacement: known.replacement,
          effort: "complex",
          location: {
            file: "pom.xml",
            snippet: `${groupId}:${artifactId}:${version}`,
          },
          detectionMethod: "dependency",
          confidence: 0.95,
        });
      }
    }
  }

  return findings;
}
