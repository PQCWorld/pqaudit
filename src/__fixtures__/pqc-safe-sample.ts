// Sample file using post-quantum safe cryptography

import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

// SAFE: ML-KEM-768 key encapsulation
const kemKeys = ml_kem768.keygen();
const { cipherText, sharedSecret: ss1 } = ml_kem768.encapsulate(kemKeys.publicKey);
const ss2 = ml_kem768.decapsulate(cipherText, kemKeys.secretKey);

// SAFE: ML-DSA-65 signatures
const dsaKeys = ml_dsa65.keygen();
const sig = ml_dsa65.sign(dsaKeys.secretKey, message);
const valid = ml_dsa65.verify(dsaKeys.publicKey, message, sig);

// SAFE: ChaCha20-Poly1305
import { chacha20poly1305 } from "@noble/ciphers/chacha";
const encrypted = chacha20poly1305(key, nonce).encrypt(plaintext);

// SAFE: SHA-256
import { sha256 } from "@noble/hashes/sha256";
const digest = sha256(data);
