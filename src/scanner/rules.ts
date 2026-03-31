import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { DetectionRule } from "../types.js";

const DEFAULT_RULES_PATH = resolve(
  import.meta.dirname,
  "../../rules/crypto-patterns.yaml",
);

export function loadRules(rulesPath?: string): DetectionRule[] {
  const path = rulesPath ?? DEFAULT_RULES_PATH;
  const raw = readFileSync(path, "utf-8");
  const parsed = parseYaml(raw) as DetectionRule[];

  // Validate and compile patterns
  for (const rule of parsed) {
    if (!rule.id || !rule.patterns?.length) {
      throw new Error(`Invalid rule: missing id or patterns in ${path}`);
    }
  }

  return parsed;
}

export function compilePatterns(
  rules: DetectionRule[],
): Map<DetectionRule, RegExp[]> {
  const compiled = new Map<DetectionRule, RegExp[]>();

  for (const rule of rules) {
    const regexes = rule.patterns.map((p) => new RegExp(p, "gi"));
    compiled.set(rule, regexes);
  }

  return compiled;
}
