// This file tests AST detection vs regex detection
// Comments mentioning crypto should NOT produce AST findings:
// crypto.createHash("md5") — this is in a comment
// import { sign } from "@noble/ed25519" — also a comment

import { sign, verify } from "@noble/ed25519";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
const nacl = require("tweetnacl");
const nodeRsa = require("node-rsa");

// Crypto API calls — AST should detect with high confidence
const hash = crypto.createHash("md5");
const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const ecdh = crypto.createECDH("secp256k1");

// JWT signing — AST should detect algorithm in options object
const token = jwt.sign(payload, secret, { algorithm: "RS256" });
const esToken = jwt.sign(payload, secret, { algorithm: "ES256" });

// Safe crypto — AST should still detect for inventory
const safeHash = crypto.createHash("sha256");
const safeCipher = crypto.createCipheriv("aes-256-gcm", key, iv);
