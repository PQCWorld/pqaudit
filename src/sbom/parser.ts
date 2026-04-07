import { readFileSync } from "node:fs";
import type { SbomComponent, SbomDocument } from "../types.js";

/** Parse a CycloneDX or SPDX JSON SBOM file */
export function parseSbom(
  filePath: string,
  format?: "cyclonedx" | "spdx",
): SbomDocument {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));

  const detected = format ?? detectFormat(raw);
  if (!detected) {
    throw new Error(`Cannot detect SBOM format. Use --sbom-format cyclonedx or spdx.`);
  }

  const components =
    detected === "cyclonedx"
      ? parseCycloneDX(raw)
      : parseSPDX(raw);

  return { format: detected, components, raw };
}

function detectFormat(raw: unknown): "cyclonedx" | "spdx" | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  if (obj.bomFormat === "CycloneDX") return "cyclonedx";
  if (typeof obj.spdxVersion === "string") return "spdx";
  return null;
}

function parseCycloneDX(raw: Record<string, unknown>): SbomComponent[] {
  const components = (raw.components ?? []) as Array<Record<string, unknown>>;
  return components.map((c) => ({
    name: String(c.name ?? ""),
    version: c.version ? String(c.version) : undefined,
    purl: c.purl ? String(c.purl) : undefined,
    type: String(c.type ?? "library"),
    original: c,
  }));
}

function parseSPDX(raw: Record<string, unknown>): SbomComponent[] {
  const packages = (raw.packages ?? []) as Array<Record<string, unknown>>;
  return packages.map((p) => {
    // Extract PURL from externalRefs
    const refs = (p.externalRefs ?? []) as Array<Record<string, string>>;
    const purlRef = refs.find((r) => r.referenceType === "purl");

    return {
      name: String(p.name ?? ""),
      version: p.versionInfo ? String(p.versionInfo) : undefined,
      purl: purlRef?.referenceLocator,
      type: "library",
      original: p,
    };
  });
}
