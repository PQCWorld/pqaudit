// Sample file with various cryptographic patterns for testing pqaudit detection

import { sign, verify } from "@noble/ed25519";
import { createCipheriv, createHash, generateKeyPairSync } from "crypto";

// CRITICAL: Ed25519 signature (quantum-vulnerable)
const signature = await sign(message, privateKey);
const isValid = await verify(signature, message, publicKey);

// CRITICAL: RSA key generation
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// CRITICAL: ECDH key exchange
const ecdh = crypto.createECDH("secp256k1");

// HIGH: AES-128 (Grover reduces to 64-bit)
const cipher = createCipheriv("aes-128-cbc", key, iv);

// MEDIUM: MD5 hash
const hash = createHash("md5").update(data).digest("hex");

// SAFE: AES-256-GCM
const safeCipher = createCipheriv("aes-256-gcm", key, iv);

// SAFE: SHA-256
const safeHash = createHash("sha256").update(data).digest("hex");

// JWT with RS256 (CRITICAL: RSA-based)
const token = jwt.sign(payload, secret, { algorithm: "RS256" });
