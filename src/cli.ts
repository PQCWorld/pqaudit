#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { Command } from "commander";
import { scan } from "./scanner/engine.js";
import { formatText } from "./reporter/text.js";
import { formatJson } from "./reporter/json.js";
import { formatCbom } from "./reporter/cbom.js";
import { formatSarif } from "./reporter/sarif.js";
import { formatHtml } from "./reporter/html.js";
import type { EndpointSpec, ScanConfig, Severity } from "./types.js";

const program = new Command();

program
  .name("pqaudit")
  .description(
    "Scan codebases for quantum-vulnerable cryptography and generate a Cryptographic Bill of Materials (CBOM)",
  )
  .version("0.1.0")
  .argument("[target]", "Directory to scan", ".")
  .option(
    "-f, --format <format>",
    "Output format: text, json, cbom, sarif, html",
    "text",
  )
  .option("-o, --output <file>", "Write output to file instead of stdout")
  .option(
    "-s, --severity <level>",
    "Minimum severity to report: critical, high, medium, low, safe",
    "safe",
  )
  .option("--no-deps", "Skip dependency scanning")
  .option("--include <patterns...>", "File patterns to include")
  .option("--exclude <patterns...>", "Additional file patterns to exclude")
  .option("--rules <dir>", "Path to custom rules YAML file")
  .option("--min-confidence <number>", "Minimum confidence 0-100 (default 50)", "50")
  .option("--dedupe", "Collapse duplicate findings per file (default: true)")
  .option("--no-dedupe", "Show all occurrences instead of collapsing duplicates")
  .option("--sbom <file>", "Path to existing SBOM (CycloneDX or SPDX JSON) to enrich")
  .option("--sbom-format <format>", "SBOM format: cyclonedx, spdx (auto-detected if omitted)")
  .option("--policy <file>", "Path to policy YAML file for compliance checking")
  .option("--scan-endpoint <endpoints...>", "TLS/SSH endpoints to probe (host:port)")
  .option("--network-timeout <ms>", "Network connection timeout in ms", "5000")
  .option("--ci", "Exit with code 1 if critical/high findings exist")
  .action(async (target: string, opts) => {
    const endpoints: EndpointSpec[] | undefined = opts.scanEndpoint?.map(
      (ep: string): EndpointSpec => {
        // Support tls:// and ssh:// prefixes
        let protocol: "tls" | "ssh" = "tls";
        let addr = ep;
        if (ep.startsWith("ssh://")) {
          protocol = "ssh";
          addr = ep.slice(6);
        } else if (ep.startsWith("tls://")) {
          addr = ep.slice(6);
        }
        const [host, portStr] = addr.split(":");
        const port = portStr ? parseInt(portStr, 10) : protocol === "ssh" ? 22 : 443;
        // Auto-detect SSH from port 22
        if (port === 22 && !ep.startsWith("tls://")) protocol = "ssh";
        return { host, port, protocol };
      },
    );

    const config: ScanConfig = {
      target,
      format: opts.format,
      output: opts.output,
      minSeverity: opts.severity as Severity,
      scanDependencies: opts.deps !== false,
      include: opts.include,
      exclude: opts.exclude,
      rulesDir: opts.rules,
      minConfidence: Number(opts.minConfidence),
      dedupe: opts.dedupe !== false,
      endpoints,
      networkTimeout: Number(opts.networkTimeout),
      sbomInput: opts.sbom,
      sbomFormat: opts.sbomFormat,
      policyFile: opts.policy,
    };

    const result = await scan(config);

    // If SBOM enrichment was done, output the enriched SBOM instead of normal format
    if (result.enrichedSbom) {
      const sbomOutput = JSON.stringify(result.enrichedSbom, null, 2);
      if (config.output) {
        writeFileSync(config.output, sbomOutput, "utf-8");
        console.log(`Enriched SBOM written to ${config.output}`);
      } else {
        console.log(sbomOutput);
      }
    } else {

    let output: string;
    switch (config.format) {
      case "json":
        output = formatJson(result);
        break;
      case "cbom":
        output = formatCbom(result);
        break;
      case "sarif":
        output = formatSarif(result);
        break;
      case "html":
        output = formatHtml(result);
        break;
      case "text":
      default:
        output = formatText(result);
        break;
    }

    if (config.output) {
      writeFileSync(config.output, output, "utf-8");
      if (config.format === "text") {
        console.log(`Results written to ${config.output}`);
      }
    } else {
      console.log(output);
    }

    } // end else (no SBOM enrichment)

    // CI mode: exit 1 if critical/high findings, exit 2 if blocking policy violations
    if (opts.ci) {
      const blockingViolations = result.policyViolations?.filter(
        (v) => v.action === "block",
      );
      if (blockingViolations && blockingViolations.length > 0) {
        process.exit(2);
      }
      const { critical, high } = result.summary.bySeverity;
      if (critical > 0 || high > 0) {
        process.exit(1);
      }
    }
  });

program.parse();
