import { readFileSync } from "node:fs";
import type {
  DetectionRule,
  Finding,
  FindingLocation,
  Severity,
} from "../types.js";
import { compilePatterns } from "./rules.js";

/** File extensions to language mapping */
const LANG_MAP: Record<string, string> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".hpp": "cpp",
  ".swift": "swift",
  ".rb": "ruby",
  ".php": "php",
  ".toml": "config",
  ".yaml": "config",
  ".yml": "config",
  ".json": "config",
  ".xml": "config",
  ".conf": "config",
  ".cfg": "config",
  ".ini": "config",
  ".env": "config",
  ".pem": "certificate",
  ".crt": "certificate",
  ".cer": "certificate",
};

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".zip",
  ".gz",
  ".tar",
  ".jar",
  ".class",
  ".so",
  ".dylib",
  ".dll",
  ".exe",
  ".o",
  ".a",
  ".wasm",
  ".mp3",
  ".mp4",
  ".pdf",
]);

/** Filename patterns that map to a language (for extensionless config files) */
const FILENAME_MAP: Record<string, string> = {
  "dockerfile": "config",
  "sshd_config": "config",
  "ssh_config": "config",
  "config": "config",
};

export function getLanguage(filePath: string): string | null {
  const ext = filePath.slice(filePath.lastIndexOf(".")).toLowerCase();
  if (LANG_MAP[ext]) return LANG_MAP[ext];

  // Check filename for extensionless config files
  const basename = filePath.slice(filePath.lastIndexOf("/") + 1).toLowerCase();
  // Handle "Dockerfile.prod" → "dockerfile"
  const rootName = basename.split(".")[0];
  return FILENAME_MAP[basename] ?? FILENAME_MAP[rootName] ?? null;
}

export function isBinary(filePath: string): boolean {
  const ext = filePath.slice(filePath.lastIndexOf(".")).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

export function scanFile(
  filePath: string,
  relativePath: string,
  rules: DetectionRule[],
  preloadedContent?: string,
): Finding[] {
  if (isBinary(filePath)) return [];

  const language = getLanguage(filePath);
  const compiledRules = compilePatterns(rules);
  const findings: Finding[] = [];

  let content: string;
  if (preloadedContent !== undefined) {
    content = preloadedContent;
  } else {
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      return [];
    }
  }

  // Skip very large files (likely generated/vendor)
  if (content.length > 1_000_000) return [];

  const lines = content.split("\n");

  for (const [rule, regexes] of compiledRules) {
    // Skip rules that don't apply to this language
    if (
      rule.languages.length > 0 &&
      language &&
      !rule.languages.includes(language)
    ) {
      continue;
    }

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const regex of regexes) {
        // Reset regex state (global flag)
        regex.lastIndex = 0;
        const match = regex.exec(line);

        if (match) {
          // Avoid duplicate findings for same rule on same line
          const isDupe = findings.some(
            (f) =>
              f.ruleId === rule.id &&
              f.location.file === relativePath &&
              f.location.line === lineIdx + 1,
          );

          if (!isDupe) {
            const location: FindingLocation = {
              file: relativePath,
              line: lineIdx + 1,
              column: match.index + 1,
              snippet: line.trim().slice(0, 120),
            };

            findings.push({
              ruleId: rule.id,
              description: rule.description,
              severity: rule.severity,
              category: rule.category,
              algorithm: rule.algorithm,
              replacement: rule.replacement,
              effort: rule.effort,
              location,
              detectionMethod: "regex",
              confidence: computeConfidence(rule, line, language),
            });
          }

          // Don't check more patterns from this rule on this line
          break;
        }
      }
    }
  }

  return findings;
}

/** Compute confidence based on context clues */
function computeConfidence(
  rule: DetectionRule,
  line: string,
  language: string | null,
): number {
  let confidence = 0.7; // Base confidence for regex match

  // Higher confidence if it looks like a code import
  if (/(?:import|require|from|include|use)\b/.test(line)) {
    confidence = 0.9;
  }

  // Higher confidence if it's a function call with the algorithm
  if (/\(.*['"].*['"]\)/.test(line)) {
    confidence = 0.85;
  }

  // Lower confidence in comments
  if (/^\s*(?:\/\/|#|\/\*|\*|--|;)/.test(line)) {
    confidence = 0.3;
  }

  // Lower confidence in strings that might be documentation
  if (language === null) {
    confidence *= 0.8;
  }

  // Safe findings get high confidence (we want to track them)
  if (rule.severity === "safe") {
    confidence = Math.max(confidence, 0.8);
  }

  return Math.round(confidence * 100) / 100;
}
