/** Severity of a cryptographic finding */
export type Severity = "critical" | "high" | "medium" | "low" | "safe";

/** Category of cryptographic operation */
export type CryptoCategory = "kem" | "signature" | "hash" | "symmetric" | "protocol" | "kdf";

/** How the finding was detected */
export type DetectionMethod = "regex" | "ast" | "dependency" | "network";

/** Migration effort required */
export type MigrationEffort = "trivial" | "moderate" | "complex" | "breaking";

/** A single cryptographic finding in a codebase */
export interface Finding {
  /** Unique rule ID that triggered this finding */
  ruleId: string;
  /** Human-readable description */
  description: string;
  /** Severity classification */
  severity: Severity;
  /** Cryptographic category */
  category: CryptoCategory;
  /** The algorithm or protocol identified */
  algorithm: string;
  /** Recommended PQC replacement */
  replacement: string | null;
  /** Migration effort estimate */
  effort: MigrationEffort;
  /** Source location */
  location: FindingLocation;
  /** How this was detected */
  detectionMethod: DetectionMethod;
  /** Confidence score 0.0-1.0 */
  confidence: number;
  /** Number of occurrences when deduplicated (1 if not set) */
  occurrences?: number;
}

export interface FindingLocation {
  /** File path relative to scan root */
  file: string;
  /** Line number (1-indexed), if known */
  line?: number;
  /** Column number (1-indexed), if known */
  column?: number;
  /** The matched source text snippet */
  snippet?: string;
}

/** A detection rule loaded from YAML */
export interface DetectionRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable description */
  description: string;
  /** Severity when matched */
  severity: Severity;
  /** Cryptographic category */
  category: CryptoCategory;
  /** Algorithm name for display */
  algorithm: string;
  /** Recommended replacement */
  replacement: string | null;
  /** Migration effort */
  effort: MigrationEffort;
  /** Languages this rule applies to (empty = all) */
  languages: string[];
  /** Regex patterns to match */
  patterns: string[];
}

/** Scan configuration */
export interface ScanConfig {
  /** Root directory to scan */
  target: string;
  /** Output format */
  format: "json" | "cbom" | "sarif" | "html" | "text";
  /** Output file path (stdout if not set) */
  output?: string;
  /** File patterns to include */
  include?: string[];
  /** File patterns to exclude */
  exclude?: string[];
  /** Minimum severity to report */
  minSeverity: Severity;
  /** Scan dependencies */
  scanDependencies: boolean;
  /** Custom rules directory */
  rulesDir?: string;
  /** Minimum confidence threshold 0-100 (findings below this are filtered out, default 50) */
  minConfidence?: number;
  /** Deduplicate findings with same ruleId + file (default: true) */
  dedupe: boolean;
  /** Network endpoints to probe for TLS/SSH crypto */
  endpoints?: EndpointSpec[];
  /** Network connection timeout in milliseconds */
  networkTimeout?: number;
  /** Path to existing SBOM file (CycloneDX or SPDX JSON) */
  sbomInput?: string;
  /** SBOM format hint (auto-detected if omitted) */
  sbomFormat?: "cyclonedx" | "spdx";
  /** Path to policy YAML file */
  policyFile?: string;
}

/** Scan result summary */
export interface ScanResult {
  /** Timestamp of scan */
  timestamp: string;
  /** Target that was scanned */
  target: string;
  /** All findings */
  findings: Finding[];
  /** Summary statistics */
  summary: ScanSummary;
  /** Policy violations (if --policy was used) */
  policyViolations?: PolicyViolation[];
  /** Enriched SBOM (if --sbom was used) */
  enrichedSbom?: unknown;
}

export interface ScanSummary {
  filesScanned: number;
  findingsTotal: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<CryptoCategory, number>;
  pqcReady: boolean;
}

/** A crypto policy rule for organizational compliance */
export interface Policy {
  id: string;
  description?: string;
  /** Algorithm name(s) to match (e.g. "RSA" or ["MD5", "SHA-1"]) */
  algorithm?: string | string[];
  /** Category to match */
  category?: CryptoCategory | CryptoCategory[];
  /** Severity levels to match */
  severity?: Severity | Severity[];
  /** Minimum confidence — findings below this are skipped */
  min_confidence?: number;
  /** What to do on violation */
  action: "warn" | "block";
  /** ISO date — policy only applies after this date */
  deadline?: string;
  /** Human-readable violation message */
  message?: string;
}

/** A policy violation tied to a specific finding */
export interface PolicyViolation {
  policyId: string;
  description: string;
  action: "warn" | "block";
  finding: Finding;
  message: string;
  deadline?: string;
}

/** A normalized SBOM component */
export interface SbomComponent {
  name: string;
  version?: string;
  purl?: string;
  type: string;
  original: unknown;
}

/** A parsed SBOM document */
export interface SbomDocument {
  format: "cyclonedx" | "spdx";
  components: SbomComponent[];
  raw: unknown;
}

/** An endpoint to probe for TLS/SSH crypto configuration */
export interface EndpointSpec {
  host: string;
  port: number;
  protocol: "tls" | "ssh";
}

/** Severity ordering for comparisons */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  safe: 4,
};
