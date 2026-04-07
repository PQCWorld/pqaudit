import { describe, it, expect } from "vitest";
import { evaluatePolicies } from "./evaluator.js";
import type { Finding, Policy } from "../types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "TEST",
    description: "Test finding",
    severity: "critical",
    category: "kem",
    algorithm: "RSA",
    replacement: "ML-KEM-768",
    effort: "complex",
    location: { file: "test.ts", line: 1, snippet: "test" },
    detectionMethod: "regex",
    confidence: 0.9,
    ...overrides,
  };
}

describe("policy evaluator", () => {
  it("matches findings by algorithm", () => {
    const policies: Policy[] = [
      { id: "no-rsa", algorithm: "RSA", action: "block" },
    ];
    const findings = [
      makeFinding({ algorithm: "RSA" }),
      makeFinding({ algorithm: "AES-256", severity: "safe" }),
      makeFinding({ algorithm: "ECDSA" }),
    ];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(1);
    expect(violations[0].policyId).toBe("no-rsa");
    expect(violations[0].finding.algorithm).toBe("RSA");
  });

  it("matches findings by algorithm array", () => {
    const policies: Policy[] = [
      { id: "no-weak-hashes", algorithm: ["MD5", "SHA-1"], action: "block" },
    ];
    const findings = [
      makeFinding({ algorithm: "MD5", severity: "medium", category: "hash" }),
      makeFinding({ algorithm: "SHA-1", severity: "medium", category: "hash" }),
      makeFinding({ algorithm: "RSA" }),
    ];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(2);
  });

  it("respects deadline — skips future deadlines", () => {
    const policies: Policy[] = [
      { id: "future", algorithm: "RSA", action: "block", deadline: "2099-01-01" },
    ];
    const findings = [makeFinding({ algorithm: "RSA" })];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(0);
  });

  it("enforces past deadlines", () => {
    const policies: Policy[] = [
      { id: "past", algorithm: "RSA", action: "block", deadline: "2020-01-01" },
    ];
    const findings = [makeFinding({ algorithm: "RSA" })];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(1);
  });

  it("skips safe findings", () => {
    const policies: Policy[] = [
      { id: "all", action: "warn" },
    ];
    const findings = [
      makeFinding({ severity: "safe", algorithm: "ML-KEM" }),
    ];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(0);
  });

  it("filters by category", () => {
    const policies: Policy[] = [
      { id: "sig-only", category: "signature", action: "warn" },
    ];
    const findings = [
      makeFinding({ category: "signature", algorithm: "ECDSA" }),
      makeFinding({ category: "kem", algorithm: "RSA" }),
    ];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(1);
    expect(violations[0].finding.algorithm).toBe("ECDSA");
  });

  it("respects min_confidence threshold", () => {
    const policies: Policy[] = [
      { id: "high-conf", algorithm: "RSA", min_confidence: 0.95, action: "block" },
    ];
    const findings = [
      makeFinding({ algorithm: "RSA", confidence: 0.7 }),
      makeFinding({ algorithm: "RSA", confidence: 0.98 }),
    ];

    const violations = evaluatePolicies(policies, findings);
    expect(violations.length).toBe(1);
    expect(violations[0].finding.confidence).toBe(0.98);
  });

  it("preserves action type in violations", () => {
    const policies: Policy[] = [
      { id: "warn-rsa", algorithm: "RSA", action: "warn", message: "RSA is deprecated" },
      { id: "block-md5", algorithm: "MD5", action: "block" },
    ];
    const findings = [
      makeFinding({ algorithm: "RSA" }),
      makeFinding({ algorithm: "MD5", severity: "medium", category: "hash" }),
    ];

    const violations = evaluatePolicies(policies, findings);
    const warn = violations.find((v) => v.policyId === "warn-rsa");
    const block = violations.find((v) => v.policyId === "block-md5");
    expect(warn?.action).toBe("warn");
    expect(warn?.message).toBe("RSA is deprecated");
    expect(block?.action).toBe("block");
  });
});
