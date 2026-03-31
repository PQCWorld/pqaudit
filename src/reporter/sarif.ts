import type { Finding, ScanResult, Severity } from "../types.js";

/**
 * Generate SARIF output for GitHub Code Scanning integration
 * Spec: https://sarifweb.azurewebsites.net/
 */
export function formatSarif(result: ScanResult): string {
  const rules = dedupeRules(result.findings);

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "pqaudit",
            version: "0.1.0",
            informationUri: "https://github.com/funktsioon/pqaudit",
            rules: rules.map((r) => ({
              id: r.ruleId,
              shortDescription: { text: r.algorithm },
              fullDescription: { text: r.description },
              defaultConfiguration: {
                level: severityToSarifLevel(r.severity),
              },
              help: {
                text: r.replacement
                  ? `Replace with: ${r.replacement}`
                  : "No migration needed",
              },
              properties: {
                tags: ["security", "cryptography", "post-quantum"],
              },
            })),
          },
        },
        results: result.findings
          .filter((f) => f.severity !== "safe")
          .map((f) => ({
            ruleId: f.ruleId,
            level: severityToSarifLevel(f.severity),
            message: {
              text: `${f.algorithm}: ${f.description}${f.replacement ? `. Replace with: ${f.replacement}` : ""}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: f.location.file,
                  },
                  region: {
                    startLine: f.location.line ?? 1,
                    startColumn: f.location.column ?? 1,
                  },
                },
              },
            ],
            properties: {
              confidence: f.confidence,
              effort: f.effort,
            },
          })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function severityToSarifLevel(
  severity: Severity,
): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    case "safe":
      return "note";
  }
}

function dedupeRules(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const f of findings) {
    if (!seen.has(f.ruleId)) {
      seen.add(f.ruleId);
      unique.push(f);
    }
  }

  return unique;
}
