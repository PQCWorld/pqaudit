import { randomUUID } from "node:crypto";
import type { Finding, ScanResult } from "../types.js";

/**
 * Generate a CycloneDX 1.6 CBOM (Cryptographic Bill of Materials)
 *
 * Spec: https://cyclonedx.org/capabilities/cbom/
 */
export function formatCbom(result: ScanResult): string {
  const components = result.findings.map(findingToComponent);

  const cbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: result.timestamp,
      tools: {
        components: [
          {
            type: "application",
            name: "pqaudit",
            version: "0.1.0",
            description:
              "Post-quantum cryptography readiness scanner",
          },
        ],
      },
      component: {
        type: "application",
        name: result.target,
        "bom-ref": "target",
      },
    },
    components,
  };

  return JSON.stringify(cbom, null, 2);
}

function findingToComponent(finding: Finding): Record<string, unknown> {
  const bomRef = `crypto-${finding.ruleId}-${finding.location.file.replace(/[^a-zA-Z0-9]/g, "-")}-${finding.location.line ?? 0}`;

  return {
    type: "crypto-asset",
    "bom-ref": bomRef,
    name: finding.algorithm,
    description: finding.description,
    cryptoProperties: {
      assetType: categoryToAssetType(finding.category),
      algorithmProperties: {
        primitive: categoryToPrimitive(finding.category),
        variant: finding.algorithm,
        cryptoFunctions: [categoryToFunction(finding.category)],
      },
      classicalSecurityLevel: severityToSecurityLevel(finding.severity),
      nistQuantumSecurityLevel: severityToNistLevel(finding.severity),
    },
    evidence: {
      occurrences: [
        {
          location: finding.location.file,
          line: finding.location.line,
          offset: finding.location.column,
          symbol: finding.location.snippet,
          additionalContext: finding.replacement
            ? `Recommended replacement: ${finding.replacement}`
            : undefined,
        },
      ],
    },
    properties: [
      { name: "pqaudit:severity", value: finding.severity },
      { name: "pqaudit:confidence", value: String(finding.confidence) },
      { name: "pqaudit:effort", value: finding.effort },
      { name: "pqaudit:detectionMethod", value: finding.detectionMethod },
      ...(finding.replacement
        ? [{ name: "pqaudit:replacement", value: finding.replacement }]
        : []),
    ],
  };
}

function categoryToAssetType(
  category: Finding["category"],
): string {
  switch (category) {
    case "kem":
      return "algorithm";
    case "signature":
      return "algorithm";
    case "hash":
      return "algorithm";
    case "symmetric":
      return "algorithm";
    case "protocol":
      return "protocol";
    case "kdf":
      return "algorithm";
  }
}

function categoryToPrimitive(
  category: Finding["category"],
): string {
  switch (category) {
    case "kem":
      return "pke";
    case "signature":
      return "signature";
    case "hash":
      return "hash";
    case "symmetric":
      return "ae";
    case "protocol":
      return "other";
    case "kdf":
      return "kdf";
  }
}

function categoryToFunction(
  category: Finding["category"],
): string {
  switch (category) {
    case "kem":
      return "encapsulate";
    case "signature":
      return "sign";
    case "hash":
      return "digest";
    case "symmetric":
      return "encrypt";
    case "protocol":
      return "other";
    case "kdf":
      return "keygen";
  }
}

function severityToSecurityLevel(severity: Finding["severity"]): number {
  switch (severity) {
    case "critical":
      return 0; // Broken by quantum
    case "high":
      return 64; // Reduced by Grover
    case "medium":
      return 0; // Already broken classically
    case "low":
      return 128;
    case "safe":
      return 128; // Post-quantum safe
  }
}

function severityToNistLevel(severity: Finding["severity"]): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 0;
    case "low":
      return 3;
    case "safe":
      return 3;
  }
}
