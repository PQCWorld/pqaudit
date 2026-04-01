#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { Command } from "commander";
import { scan } from "./scanner/engine.js";
import { formatText } from "./reporter/text.js";
import { formatJson } from "./reporter/json.js";
import { formatCbom } from "./reporter/cbom.js";
import { formatSarif } from "./reporter/sarif.js";
import type { ScanConfig, Severity } from "./types.js";

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
    "Output format: text, json, cbom, sarif",
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
  .option("--dedupe", "Collapse duplicate findings per file (default: true)")
  .option("--no-dedupe", "Show all occurrences instead of collapsing duplicates")
  .option("--ci", "Exit with code 1 if critical/high findings exist")
  .action(async (target: string, opts) => {
    const config: ScanConfig = {
      target,
      format: opts.format,
      output: opts.output,
      minSeverity: opts.severity as Severity,
      scanDependencies: opts.deps !== false,
      include: opts.include,
      exclude: opts.exclude,
      rulesDir: opts.rules,
      dedupe: opts.dedupe !== false,
    };

    const result = await scan(config);

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

    // CI mode: exit 1 if critical or high findings
    if (opts.ci) {
      const { critical, high } = result.summary.bySeverity;
      if (critical > 0 || high > 0) {
        process.exit(1);
      }
    }
  });

program.parse();
