import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scan } from "./engine.js";
import type { ScanConfig } from "../types.js";

const FIXTURES = resolve(import.meta.dirname, "../__fixtures__");

function makeConfig(overrides?: Partial<ScanConfig>): ScanConfig {
  return {
    target: FIXTURES,
    format: "json",
    minSeverity: "safe",
    scanDependencies: false,
    ...overrides,
  };
}

describe("scan engine", () => {
  it("detects quantum-vulnerable crypto in sample file", async () => {
    const result = await scan(makeConfig());

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.filesScanned).toBeGreaterThan(0);

    // Should find Ed25519 (critical)
    const ed25519 = result.findings.filter(
      (f) => f.algorithm === "Ed25519" && f.severity === "critical",
    );
    expect(ed25519.length).toBeGreaterThan(0);

    // Should find RSA (critical)
    const rsa = result.findings.filter(
      (f) => f.algorithm === "RSA" && f.severity === "critical",
    );
    expect(rsa.length).toBeGreaterThan(0);
  });

  it("detects PQC-safe crypto", async () => {
    const result = await scan(makeConfig());

    const safe = result.findings.filter((f) => f.severity === "safe");
    expect(safe.length).toBeGreaterThan(0);

    // Should find ML-KEM
    const mlkem = safe.filter((f) => f.algorithm === "ML-KEM");
    expect(mlkem.length).toBeGreaterThan(0);

    // Should find ML-DSA
    const mldsa = safe.filter((f) => f.algorithm === "ML-DSA");
    expect(mldsa.length).toBeGreaterThan(0);
  });

  it("correctly classifies severity levels", async () => {
    const result = await scan(makeConfig());

    // MD5 should be medium
    const md5 = result.findings.filter((f) => f.algorithm === "MD5");
    expect(md5.length).toBeGreaterThan(0);
    expect(md5[0].severity).toBe("medium");

    // AES-128 should be high
    const aes128 = result.findings.filter((f) => f.algorithm === "AES-128");
    expect(aes128.length).toBeGreaterThan(0);
    expect(aes128[0].severity).toBe("high");
  });

  it("respects minimum severity filter", async () => {
    const result = await scan(makeConfig({ minSeverity: "critical" }));

    for (const f of result.findings) {
      expect(f.severity).toBe("critical");
    }
  });

  it("marks PQC readiness correctly", async () => {
    // Fixtures contain critical findings, so not PQC ready
    const result = await scan(makeConfig());
    expect(result.summary.pqcReady).toBe(false);
  });

  it("includes replacement recommendations for vulnerable findings", async () => {
    const result = await scan(makeConfig());

    const critical = result.findings.filter(
      (f) => f.severity === "critical",
    );
    for (const f of critical) {
      expect(f.replacement).toBeTruthy();
    }

    const safe = result.findings.filter((f) => f.severity === "safe");
    for (const f of safe) {
      expect(f.replacement).toBeNull();
    }
  });

  it("provides location information", async () => {
    const result = await scan(makeConfig());

    for (const f of result.findings) {
      expect(f.location.file).toBeTruthy();
      expect(f.location.line).toBeGreaterThan(0);
    }
  });
});
