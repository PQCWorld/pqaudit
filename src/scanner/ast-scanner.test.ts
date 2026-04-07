import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { scanFileAST } from "./ast-scanner.js";
import { loadRules } from "./rules.js";
import { scan } from "./engine.js";
import type { ScanConfig } from "../types.js";

const FIXTURES = resolve(import.meta.dirname, "../__fixtures__");
const rules = loadRules();

describe("AST scanner", () => {
  it("detects import declarations with high confidence", async () => {
    const content = readFileSync(resolve(FIXTURES, "ast-test-sample.ts"), "utf-8");
    const findings = await scanFileAST(
      resolve(FIXTURES, "ast-test-sample.ts"),
      "ast-test-sample.ts",
      content,
      "typescript",
      rules,
    );

    // Should detect @noble/ed25519 import
    const ed25519 = findings.filter((f) => f.ruleId === "ED25519_USAGE");
    expect(ed25519.length).toBeGreaterThan(0);
    expect(ed25519[0].confidence).toBeGreaterThanOrEqual(0.95);
    expect(ed25519[0].detectionMethod).toBe("ast");

    // Should detect @noble/post-quantum import (safe)
    const mlkem = findings.filter((f) => f.ruleId === "ML_KEM");
    expect(mlkem.length).toBeGreaterThan(0);
    expect(mlkem[0].confidence).toBeGreaterThanOrEqual(0.95);
  });

  it("detects require() calls", async () => {
    const content = readFileSync(resolve(FIXTURES, "ast-test-sample.ts"), "utf-8");
    const findings = await scanFileAST(
      resolve(FIXTURES, "ast-test-sample.ts"),
      "ast-test-sample.ts",
      content,
      "typescript",
      rules,
    );

    // Should detect tweetnacl require
    const nacl = findings.filter(
      (f) => f.ruleId === "ED25519_USAGE" && f.location.snippet?.includes("tweetnacl"),
    );
    expect(nacl.length).toBe(1);

    // Should detect node-rsa require
    const rsa = findings.filter(
      (f) => f.ruleId === "RSA_KEY_GEN" && f.location.snippet?.includes("node-rsa"),
    );
    expect(rsa.length).toBe(1);
  });

  it("detects crypto API calls with algorithm arguments", async () => {
    const content = readFileSync(resolve(FIXTURES, "ast-test-sample.ts"), "utf-8");
    const findings = await scanFileAST(
      resolve(FIXTURES, "ast-test-sample.ts"),
      "ast-test-sample.ts",
      content,
      "typescript",
      rules,
    );

    // createHash("md5")
    const md5 = findings.filter((f) => f.ruleId === "MD5_USAGE");
    expect(md5.length).toBe(1);
    expect(md5[0].confidence).toBeGreaterThanOrEqual(0.95);

    // createCipheriv("aes-128-cbc")
    const aes128 = findings.filter((f) => f.ruleId === "AES_128");
    expect(aes128.length).toBe(1);

    // generateKeyPairSync("rsa")
    const rsaGen = findings.filter(
      (f) => f.ruleId === "RSA_KEY_GEN" && f.location.snippet?.includes("generateKeyPairSync"),
    );
    expect(rsaGen.length).toBe(1);
    expect(rsaGen[0].confidence).toBeGreaterThanOrEqual(0.95);
  });

  it("detects JWT signing with algorithm options", async () => {
    const content = readFileSync(resolve(FIXTURES, "ast-test-sample.ts"), "utf-8");
    const findings = await scanFileAST(
      resolve(FIXTURES, "ast-test-sample.ts"),
      "ast-test-sample.ts",
      content,
      "typescript",
      rules,
    );

    // jwt.sign with RS256
    const rsaSign = findings.filter((f) => f.ruleId === "RSA_SIGN");
    expect(rsaSign.length).toBe(1);
    expect(rsaSign[0].confidence).toBeGreaterThanOrEqual(0.95);

    // jwt.sign with ES256
    const ecdsaSign = findings.filter((f) => f.ruleId === "ECDSA_USAGE");
    expect(ecdsaSign.length).toBe(1);
  });

  it("does NOT detect crypto patterns in comments", async () => {
    const content = readFileSync(resolve(FIXTURES, "ast-test-sample.ts"), "utf-8");
    const findings = await scanFileAST(
      resolve(FIXTURES, "ast-test-sample.ts"),
      "ast-test-sample.ts",
      content,
      "typescript",
      rules,
    );

    // Lines 3-4 are comments mentioning crypto — AST should not detect them
    const commentFindings = findings.filter(
      (f) => f.location.line !== undefined && f.location.line <= 5,
    );
    expect(commentFindings.length).toBe(0);
  });

  it("deduplication prefers AST over regex findings", async () => {
    const config: ScanConfig = {
      target: FIXTURES,
      format: "json",
      minSeverity: "safe",
      scanDependencies: false,
      dedupe: true,
    };

    const result = await scan(config);

    // For vulnerable-sample.ts, deduped findings should prefer AST (higher confidence)
    const vsFindings = result.findings.filter(
      (f) => f.location.file === "vulnerable-sample.ts",
    );

    // RSA_KEY_GEN should be AST-detected (0.96 > regex 0.85)
    const rsaGen = vsFindings.find((f) => f.ruleId === "RSA_KEY_GEN");
    expect(rsaGen).toBeDefined();
    expect(rsaGen!.detectionMethod).toBe("ast");
    expect(rsaGen!.confidence).toBeGreaterThanOrEqual(0.95);
  });
});
