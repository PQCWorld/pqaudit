/** AST pattern definitions mapping code constructs to detection rule IDs */

export interface ImportPattern {
  type: "import";
  /** npm package names to match */
  packages: string[];
  /** Rule ID to emit */
  ruleId: string;
  confidence: number;
}

export interface CryptoCallPattern {
  type: "crypto-call";
  /** Method name, e.g. "createHash", "generateKeyPairSync" */
  methodName: string;
  /** Algorithm string arguments to match (case-insensitive) */
  algorithmArgs: string[];
  /** Rule ID to emit */
  ruleId: string;
  confidence: number;
}

export interface MethodCallPattern {
  type: "method-call";
  /** Object name, e.g. "jwt" */
  objectName: string;
  /** Method name, e.g. "sign" */
  methodName: string;
  /** Property in options object to check */
  optionProperty: string;
  /** Values of that property to match */
  optionValues: string[];
  /** Rule ID to emit */
  ruleId: string;
  confidence: number;
}

export type ASTPattern = ImportPattern | CryptoCallPattern | MethodCallPattern;

// --- Import patterns: detect crypto library imports/requires ---

export const IMPORT_PATTERNS: ImportPattern[] = [
  // Quantum-vulnerable
  { type: "import", packages: ["@noble/ed25519"], ruleId: "ED25519_USAGE", confidence: 0.98 },
  { type: "import", packages: ["@noble/secp256k1"], ruleId: "ECDSA_USAGE", confidence: 0.98 },
  { type: "import", packages: ["node-rsa"], ruleId: "RSA_KEY_GEN", confidence: 0.95 },
  { type: "import", packages: ["tweetnacl"], ruleId: "ED25519_USAGE", confidence: 0.95 },
  { type: "import", packages: ["elliptic"], ruleId: "ECDSA_USAGE", confidence: 0.95 },
  { type: "import", packages: ["jsonwebtoken"], ruleId: "RSA_SIGN", confidence: 0.90 },
  { type: "import", packages: ["jose"], ruleId: "RSA_SIGN", confidence: 0.90 },
  { type: "import", packages: ["@solana/web3.js"], ruleId: "ED25519_USAGE", confidence: 0.95 },
  { type: "import", packages: ["ethers"], ruleId: "ECDSA_USAGE", confidence: 0.95 },
  { type: "import", packages: ["web3"], ruleId: "ECDSA_USAGE", confidence: 0.95 },
  { type: "import", packages: ["libsodium-wrappers"], ruleId: "ED25519_USAGE", confidence: 0.90 },
  // PQC-safe
  { type: "import", packages: ["@noble/post-quantum"], ruleId: "ML_KEM", confidence: 0.98 },
];

// --- Crypto API call patterns: detect crypto.createHash("md5"), etc. ---

export const CRYPTO_CALL_PATTERNS: CryptoCallPattern[] = [
  { type: "crypto-call", methodName: "createHash", algorithmArgs: ["md5"], ruleId: "MD5_USAGE", confidence: 0.95 },
  { type: "crypto-call", methodName: "createHash", algorithmArgs: ["sha1"], ruleId: "SHA1_USAGE", confidence: 0.95 },
  { type: "crypto-call", methodName: "createHash", algorithmArgs: ["sha256"], ruleId: "SHA256_SAFE", confidence: 0.95 },
  { type: "crypto-call", methodName: "createHash", algorithmArgs: ["sha3"], ruleId: "SHA3_SAFE", confidence: 0.95 },
  { type: "crypto-call", methodName: "createCipheriv", algorithmArgs: ["aes-128-cbc", "aes-128-gcm", "aes-128-ctr"], ruleId: "AES_128", confidence: 0.95 },
  { type: "crypto-call", methodName: "createCipheriv", algorithmArgs: ["aes-256-gcm", "aes-256-cbc", "aes-256-ctr"], ruleId: "AES_256", confidence: 0.95 },
  { type: "crypto-call", methodName: "createCipheriv", algorithmArgs: ["chacha20-poly1305"], ruleId: "CHACHA20", confidence: 0.95 },
  { type: "crypto-call", methodName: "createCipheriv", algorithmArgs: ["des", "des-cbc", "des-ede3", "des3"], ruleId: "DES_3DES", confidence: 0.95 },
  { type: "crypto-call", methodName: "generateKeyPairSync", algorithmArgs: ["rsa"], ruleId: "RSA_KEY_GEN", confidence: 0.96 },
  { type: "crypto-call", methodName: "generateKeyPair", algorithmArgs: ["rsa"], ruleId: "RSA_KEY_GEN", confidence: 0.96 },
  { type: "crypto-call", methodName: "generateKeyPairSync", algorithmArgs: ["ec", "ed25519"], ruleId: "ED25519_USAGE", confidence: 0.96 },
  { type: "crypto-call", methodName: "generateKeyPair", algorithmArgs: ["ec", "ed25519"], ruleId: "ED25519_USAGE", confidence: 0.96 },
  { type: "crypto-call", methodName: "generateKeyPairSync", algorithmArgs: ["dsa"], ruleId: "DSA_USAGE", confidence: 0.96 },
  { type: "crypto-call", methodName: "createECDH", algorithmArgs: ["secp256k1", "prime256v1", "secp384r1", "secp521r1"], ruleId: "ECDH_KEY_EXCHANGE", confidence: 0.96 },
  { type: "crypto-call", methodName: "createDiffieHellman", algorithmArgs: [], ruleId: "DH_KEY_EXCHANGE", confidence: 0.95 },
  { type: "crypto-call", methodName: "publicEncrypt", algorithmArgs: [], ruleId: "RSA_ENCRYPT", confidence: 0.95 },
  { type: "crypto-call", methodName: "privateDecrypt", algorithmArgs: [], ruleId: "RSA_ENCRYPT", confidence: 0.95 },
];

// --- Method call patterns: detect jwt.sign with algorithm options ---

export const METHOD_CALL_PATTERNS: MethodCallPattern[] = [
  { type: "method-call", objectName: "jwt", methodName: "sign", optionProperty: "algorithm", optionValues: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"], ruleId: "RSA_SIGN", confidence: 0.96 },
  { type: "method-call", objectName: "jwt", methodName: "sign", optionProperty: "algorithm", optionValues: ["ES256", "ES384", "ES512"], ruleId: "ECDSA_USAGE", confidence: 0.96 },
  { type: "method-call", objectName: "jwt", methodName: "verify", optionProperty: "algorithms", optionValues: ["RS256", "RS384", "RS512"], ruleId: "RSA_SIGN", confidence: 0.96 },
  { type: "method-call", objectName: "jwt", methodName: "verify", optionProperty: "algorithms", optionValues: ["ES256", "ES384", "ES512"], ruleId: "ECDSA_USAGE", confidence: 0.96 },
];
