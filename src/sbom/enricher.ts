import type { Finding, SbomDocument } from "../types.js";

/** Enrich an SBOM with cryptographic findings from the scan */
export function enrichSbom(
  sbom: SbomDocument,
  findings: Finding[],
): unknown {
  if (sbom.format === "cyclonedx") {
    return enrichCycloneDX(sbom.raw as Record<string, unknown>, findings);
  }
  return enrichSPDX(sbom.raw as Record<string, unknown>, findings);
}

function enrichCycloneDX(
  raw: Record<string, unknown>,
  findings: Finding[],
): Record<string, unknown> {
  const output = { ...raw };
  const components = [...((raw.components ?? []) as Array<Record<string, unknown>>)];
  const matched = new Set<number>();

  // Try to match findings to existing components
  for (const finding of findings) {
    let foundMatch = false;

    for (let i = 0; i < components.length; i++) {
      const comp = components[i];
      if (componentMatchesFinding(comp, finding)) {
        // Enrich existing component
        components[i] = addCryptoToComponent(comp, finding);
        matched.add(i);
        foundMatch = true;
        break;
      }
    }

    // If no match, add as new crypto-asset component
    if (!foundMatch) {
      components.push(makeCryptoComponent(finding));
    }
  }

  output.components = components;
  return output;
}

function enrichSPDX(
  raw: Record<string, unknown>,
  findings: Finding[],
): Record<string, unknown> {
  const output = { ...raw };
  const packages = [...((raw.packages ?? []) as Array<Record<string, unknown>>)];

  // Add crypto findings as annotations/external refs on matched packages
  for (const finding of findings) {
    let foundMatch = false;

    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const refs = (pkg.externalRefs ?? []) as Array<Record<string, string>>;
      const purlRef = refs.find((r) => r.referenceType === "purl");

      if (purlRef && findingMatchesPurl(purlRef.referenceLocator, finding)) {
        // Add pqaudit annotation
        packages[i] = addAnnotationToPackage(pkg, finding);
        foundMatch = true;
        break;
      }
    }

    if (!foundMatch) {
      packages.push(makeSpdxCryptoPackage(finding));
    }
  }

  output.packages = packages;
  return output;
}

function componentMatchesFinding(
  comp: Record<string, unknown>,
  finding: Finding,
): boolean {
  const purl = String(comp.purl ?? "").toLowerCase();
  const name = String(comp.name ?? "").toLowerCase();
  const algo = finding.algorithm.toLowerCase();

  // Match by PURL containing algorithm-related package name
  if (purl && findingMatchesPurl(purl, finding)) return true;

  // Match by component name containing algorithm
  if (name.includes(algo) || algo.includes(name)) return true;

  return false;
}

function findingMatchesPurl(purl: string, finding: Finding): boolean {
  const p = purl.toLowerCase();
  const algo = finding.algorithm.toLowerCase();

  // Check if the PURL package name relates to the finding
  if (p.includes(algo)) return true;
  if (algo === "rsa" && p.includes("rsa")) return true;
  if (algo.includes("ecdsa") && (p.includes("ecdsa") || p.includes("secp256"))) return true;
  if (algo.includes("ed25519") && p.includes("ed25519")) return true;

  return false;
}

function addCryptoToComponent(
  comp: Record<string, unknown>,
  finding: Finding,
): Record<string, unknown> {
  const props = ((comp.properties ?? []) as Array<Record<string, string>>).slice();
  props.push(
    { name: "pqaudit:severity", value: finding.severity },
    { name: "pqaudit:algorithm", value: finding.algorithm },
    { name: "pqaudit:confidence", value: String(finding.confidence) },
    { name: "pqaudit:replacement", value: finding.replacement ?? "none" },
  );

  return {
    ...comp,
    properties: props,
    cryptoProperties: {
      assetType: "algorithm",
      algorithmProperties: {
        variant: finding.algorithm,
      },
    },
  };
}

function makeCryptoComponent(finding: Finding): Record<string, unknown> {
  return {
    type: "crypto-asset",
    name: finding.algorithm,
    description: finding.description,
    cryptoProperties: {
      assetType: finding.category === "protocol" ? "protocol" : "algorithm",
      algorithmProperties: {
        variant: finding.algorithm,
      },
    },
    evidence: {
      occurrences: [
        {
          location: finding.location.file,
          line: finding.location.line,
          symbol: finding.location.snippet,
        },
      ],
    },
    properties: [
      { name: "pqaudit:severity", value: finding.severity },
      { name: "pqaudit:confidence", value: String(finding.confidence) },
      { name: "pqaudit:detectionMethod", value: finding.detectionMethod },
      { name: "pqaudit:replacement", value: finding.replacement ?? "none" },
    ],
  };
}

function addAnnotationToPackage(
  pkg: Record<string, unknown>,
  finding: Finding,
): Record<string, unknown> {
  const comment = String(pkg.comment ?? "");
  const annotation = `[pqaudit] ${finding.severity}: ${finding.algorithm} — ${finding.description}. Replace with: ${finding.replacement ?? "N/A"}`;

  return {
    ...pkg,
    comment: comment ? `${comment}\n${annotation}` : annotation,
  };
}

function makeSpdxCryptoPackage(finding: Finding): Record<string, unknown> {
  return {
    SPDXID: `SPDXRef-pqaudit-${finding.ruleId}-${Date.now()}`,
    name: `crypto:${finding.algorithm}`,
    versionInfo: "",
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    description: `[pqaudit] ${finding.description}`,
    comment: `Severity: ${finding.severity}. Confidence: ${finding.confidence}. Replace with: ${finding.replacement ?? "N/A"}`,
  };
}
