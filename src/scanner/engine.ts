import { resolve, relative } from "node:path";
import { glob } from "glob";
import type {
  CryptoCategory,
  Finding,
  ScanConfig,
  ScanResult,
  ScanSummary,
  Severity,
  SEVERITY_ORDER,
} from "../types.js";
import { loadRules } from "./rules.js";
import { scanFile } from "./file-scanner.js";
import {
  scanNpmDependencies,
  scanCargoDependencies,
  scanGoDependencies,
  scanPipDependencies,
  scanGradleDependencies,
} from "./dependency-scanner.js";

const DEFAULT_EXCLUDE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/.git/**",
  "**/vendor/**",
  "**/target/**",
  "**/__pycache__/**",
  "**/.venv/**",
  "**/coverage/**",
  "**/*.min.js",
  "**/*.map",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml",
  "**/Cargo.lock",
];

const SOURCE_EXTENSIONS =
  "**/*.{js,mjs,cjs,jsx,ts,tsx,mts,cts,py,go,rs,java,kt,kts,cs,c,h,cpp,cc,hpp,swift,rb,php,toml,yaml,yml,json,xml,conf,cfg,ini,env,pem,crt,cer}";

/** Extensionless config files relevant to crypto/protocol detection */
const CONFIG_FILE_NAMES = [
  "**/Dockerfile",
  "**/Dockerfile.*",
  "**/sshd_config",
  "**/ssh_config",
  "**/nginx.conf",
  "**/haproxy.cfg",
  "**/.ssh/config",
];

export async function scan(config: ScanConfig): Promise<ScanResult> {
  const target = resolve(config.target);
  const rules = loadRules(config.rulesDir);

  // Discover files
  const excludePatterns = [...DEFAULT_EXCLUDE, ...(config.exclude ?? [])];
  const includePatterns = config.include ?? [SOURCE_EXTENSIONS, ...CONFIG_FILE_NAMES];

  const files: string[] = [];
  for (const pattern of includePatterns) {
    const matched = await glob(pattern, {
      cwd: target,
      absolute: true,
      ignore: excludePatterns,
      nodir: true,
    });
    files.push(...matched);
  }

  // Deduplicate
  const uniqueFiles = [...new Set(files)];

  // Scan files
  const allFindings: Finding[] = [];

  for (const file of uniqueFiles) {
    const rel = relative(target, file);
    const fileFindings = scanFile(file, rel, rules);
    allFindings.push(...fileFindings);
  }

  // Scan dependencies
  if (config.scanDependencies) {
    const depFindings = scanNpmDependencies(target);
    allFindings.push(...depFindings);
    allFindings.push(...scanCargoDependencies(target));
    allFindings.push(...scanGoDependencies(target));
    allFindings.push(...scanPipDependencies(target));
    allFindings.push(...scanGradleDependencies(target));
  }

  // Filter by minimum confidence
  const minConfidence = config.minConfidence ?? 50;
  const confidenceFiltered = allFindings.filter(
    (f) => f.confidence * 100 >= minConfidence,
  );

  // Filter by minimum severity
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    safe: 4,
  };

  const minLevel = severityOrder[config.minSeverity];
  const filtered = confidenceFiltered.filter(
    (f) => severityOrder[f.severity] <= minLevel,
  );

  // Sort: critical first, then by file
  filtered.sort((a, b) => {
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.location.file.localeCompare(b.location.file);
  });

  // Deduplicate findings with same ruleId + file
  const deduped = config.dedupe !== false ? deduplicateFindings(filtered) : filtered;

  // Build summary
  const summary = buildSummary(deduped, uniqueFiles.length);

  return {
    timestamp: new Date().toISOString(),
    target: config.target,
    findings: deduped,
    summary,
  };
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    const key = `${f.ruleId}\0${f.location.file}`;
    const group = groups.get(key);
    if (group) {
      group.push(f);
    } else {
      groups.set(key, [f]);
    }
  }

  const result: Finding[] = [];
  for (const group of groups.values()) {
    const first = { ...group[0] };
    if (group.length > 1) {
      first.occurrences = group.length;
    }
    result.push(first);
  }

  return result;
}

function buildSummary(findings: Finding[], filesScanned: number): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0,
  };

  const byCategory: Record<CryptoCategory, number> = {
    kem: 0,
    signature: 0,
    hash: 0,
    symmetric: 0,
    protocol: 0,
    kdf: 0,
  };

  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }

  const pqcReady =
    bySeverity.critical === 0 && bySeverity.high === 0;

  return {
    filesScanned,
    findingsTotal: findings.length,
    bySeverity,
    byCategory,
    pqcReady,
  };
}
