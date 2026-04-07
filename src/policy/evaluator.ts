import type { Finding, Policy, PolicyViolation } from "../types.js";

/** Check all findings against all policies, returning violations */
export function evaluatePolicies(
  policies: Policy[],
  findings: Finding[],
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const now = new Date();

  for (const finding of findings) {
    // Skip safe findings — policies target vulnerabilities
    if (finding.severity === "safe") continue;

    for (const policy of policies) {
      if (matches(policy, finding, now)) {
        violations.push({
          policyId: policy.id,
          description: policy.description ?? policy.id,
          action: policy.action,
          finding,
          message: policy.message ?? `Violates policy "${policy.id}"`,
          deadline: policy.deadline,
        });
      }
    }
  }

  return violations;
}

function matches(policy: Policy, finding: Finding, now: Date): boolean {
  // Deadline check — if deadline is in the future, skip (not yet enforced)
  if (policy.deadline) {
    const deadline = new Date(policy.deadline);
    if (now < deadline) return false;
  }

  // Confidence threshold — skip findings below the policy minimum
  if (policy.min_confidence !== undefined && finding.confidence < policy.min_confidence) {
    return false;
  }

  // Algorithm filter
  if (policy.algorithm) {
    const algos = Array.isArray(policy.algorithm) ? policy.algorithm : [policy.algorithm];
    if (!algos.some((a) => finding.algorithm.toLowerCase().includes(a.toLowerCase()))) {
      return false;
    }
  }

  // Category filter
  if (policy.category) {
    const cats = Array.isArray(policy.category) ? policy.category : [policy.category];
    if (!cats.includes(finding.category)) return false;
  }

  // Severity filter
  if (policy.severity) {
    const sevs = Array.isArray(policy.severity) ? policy.severity : [policy.severity];
    if (!sevs.includes(finding.severity)) return false;
  }

  // If no algorithm/category/severity filter was specified, match all non-safe findings
  if (!policy.algorithm && !policy.category && !policy.severity) {
    return true;
  }

  return true;
}
