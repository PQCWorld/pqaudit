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

  it("deduplicates findings with same ruleId and file", async () => {
    const all = await scan(makeConfig({ dedupe: false }));
    const deduped = await scan(makeConfig({ dedupe: true }));

    // Deduplication should produce fewer or equal findings
    expect(deduped.findings.length).toBeLessThanOrEqual(all.findings.length);

    // Any finding that was collapsed should have occurrences > 1
    const withOccurrences = deduped.findings.filter(
      (f) => f.occurrences && f.occurrences > 1,
    );

    // If there were duplicates in the full scan, we should see collapsed entries
    // Count duplicates in the full scan by ruleId + file
    const keys = all.findings.map((f) => `${f.ruleId}\0${f.location.file}`);
    const uniqueKeys = new Set(keys);
    const hasDuplicates = keys.length > uniqueKeys.size;

    if (hasDuplicates) {
      expect(withOccurrences.length).toBeGreaterThan(0);

      // The sum of all occurrences should equal the original count
      let totalOccurrences = 0;
      for (const f of deduped.findings) {
        totalOccurrences += f.occurrences ?? 1;
      }
      expect(totalOccurrences).toBe(all.findings.length);
    }

    // Each deduped finding should be unique by ruleId + file
    const dedupedKeys = deduped.findings.map(
      (f) => `${f.ruleId}\0${f.location.file}`,
    );
    expect(new Set(dedupedKeys).size).toBe(dedupedKeys.length);
  });
});
