import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.yellow.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  safe: chalk.green,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "!!",
  high: "!",
  medium: "~",
  low: "-",
  safe: "ok",
};

export function formatText(result: ScanResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold("  pqaudit — Post-Quantum Cryptography Readiness Scanner"));
  lines.push(chalk.dim(`  Scanned: ${result.target}`));
  lines.push(chalk.dim(`  Date: ${result.timestamp}`));
  lines.push("");

  // Summary bar
  const s = result.summary;
  if (s.pqcReady) {
    lines.push(chalk.green.bold("  PQC READY — No critical or high-severity findings"));
  } else {
    lines.push(
      chalk.red.bold("  NOT PQC READY — Quantum-vulnerable cryptography detected"),
    );
  }
  lines.push("");

  // Stats
  lines.push(
    `  Files scanned: ${s.filesScanned}  |  Findings: ${s.findingsTotal}`,
  );
  lines.push(
    `  ${chalk.red(`Critical: ${s.bySeverity.critical}`)}  ` +
      `${chalk.yellow(`High: ${s.bySeverity.high}`)}  ` +
      `${chalk.yellow(`Medium: ${s.bySeverity.medium}`)}  ` +
      `${chalk.blue(`Low: ${s.bySeverity.low}`)}  ` +
      `${chalk.green(`Safe: ${s.bySeverity.safe}`)}`,
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("  No findings.");
    return lines.join("\n");
  }

  // Group by severity
  const grouped = groupBySeverity(result.findings);

  for (const [severity, findings] of grouped) {
    if (findings.length === 0) continue;

    const color = SEVERITY_COLORS[severity];
    lines.push(color(`  --- ${severity.toUpperCase()} (${findings.length}) ---`));
    lines.push("");

    for (const f of findings) {
      const icon = SEVERITY_ICONS[f.severity];
      const loc = f.location.line
        ? `${f.location.file}:${f.location.line}`
        : f.location.file;

      const occLabel = f.occurrences && f.occurrences > 1
        ? ` (${f.occurrences} occurrences)`
        : "";
      lines.push(color(`  [${icon}] ${f.algorithm} — ${f.description}${occLabel}`));
      lines.push(chalk.dim(`      ${loc}`));
      if (f.location.snippet) {
        lines.push(chalk.dim(`      > ${f.location.snippet}`));
      }
      if (f.replacement) {
        lines.push(chalk.cyan(`      Fix: ${f.replacement}`));
      }
      lines.push(
        chalk.dim(
          `      Confidence: ${Math.round(f.confidence * 100)}% | Effort: ${f.effort} | Via: ${f.detectionMethod}`,
        ),
      );
      lines.push("");
    }
  }

  return lines.join("\n");
}

function groupBySeverity(
  findings: Finding[],
): [Severity, Finding[]][] {
  const groups: Record<Severity, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    safe: [],
  };

  for (const f of findings) {
    groups[f.severity].push(f);
  }

  return Object.entries(groups) as [Severity, Finding[]][];
}
