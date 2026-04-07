import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import type { Policy } from "../types.js";

interface PolicyFile {
  policies: Policy[];
}

/** Load and validate policy definitions from a YAML file */
export function loadPolicies(filePath: string): Policy[] {
  const raw = readFileSync(filePath, "utf-8");
  const parsed = parseYaml(raw) as PolicyFile;

  if (!parsed?.policies || !Array.isArray(parsed.policies)) {
    throw new Error(`Invalid policy file: expected "policies" array in ${filePath}`);
  }

  for (const policy of parsed.policies) {
    if (!policy.id) throw new Error(`Policy missing "id" in ${filePath}`);
    if (!policy.action || !["warn", "block"].includes(policy.action)) {
      throw new Error(`Policy "${policy.id}" has invalid action (must be "warn" or "block")`);
    }
  }

  return parsed.policies;
}
