import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scan } from "../scanner/engine.js";
import { formatCbom } from "./cbom.js";

const FIXTURES = resolve(import.meta.dirname, "../__fixtures__");

describe("CBOM reporter", () => {
  it("produces valid CycloneDX 1.6 structure", async () => {
    const result = await scan({
      target: FIXTURES,
      format: "cbom",
      minSeverity: "safe",
      scanDependencies: false,
    });

    const cbomStr = formatCbom(result);
    const cbom = JSON.parse(cbomStr);

    expect(cbom.bomFormat).toBe("CycloneDX");
    expect(cbom.specVersion).toBe("1.6");
    expect(cbom.serialNumber).toMatch(/^urn:uuid:/);
    expect(cbom.metadata.tools.components[0].name).toBe("pqaudit");
    expect(Array.isArray(cbom.components)).toBe(true);
    expect(cbom.components.length).toBeGreaterThan(0);
  });

  it("marks crypto-asset components with cryptoProperties", async () => {
    const result = await scan({
      target: FIXTURES,
      format: "cbom",
      minSeverity: "safe",
      scanDependencies: false,
    });

    const cbom = JSON.parse(formatCbom(result));

    for (const component of cbom.components) {
      expect(component.type).toBe("crypto-asset");
      expect(component.cryptoProperties).toBeTruthy();
      expect(component.cryptoProperties.assetType).toBeTruthy();
      expect(component.evidence.occurrences.length).toBeGreaterThan(0);
    }
  });

  it("includes severity and replacement in properties", async () => {
    const result = await scan({
      target: FIXTURES,
      format: "cbom",
      minSeverity: "critical",
      scanDependencies: false,
    });

    const cbom = JSON.parse(formatCbom(result));
    const criticalComponent = cbom.components.find(
      (c: any) =>
        c.properties?.some(
          (p: any) => p.name === "pqaudit:severity" && p.value === "critical",
        ),
    );

    expect(criticalComponent).toBeTruthy();
    const replacement = criticalComponent.properties.find(
      (p: any) => p.name === "pqaudit:replacement",
    );
    expect(replacement).toBeTruthy();
  });
});
