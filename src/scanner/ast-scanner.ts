import { resolve } from "node:path";
import type { Parser as ParserType, Language as LanguageType, Node as NodeType } from "web-tree-sitter";
import type { DetectionRule, Finding, FindingLocation } from "../types.js";
import {
  IMPORT_PATTERNS,
  CRYPTO_CALL_PATTERNS,
  METHOD_CALL_PATTERNS,
} from "./ast-patterns.js";

let initPromise: Promise<boolean> | null = null;
let jsParser: ParserType | null = null;
let tsParser: ParserType | null = null;
let tsxParser: ParserType | null = null;

/** In dev mode (tsx), resolve WASM grammar paths from node_modules */
async function resolveDevGrammarPaths(): Promise<{ js: string; ts: string; tsx: string }> {
  const { createRequire } = await import("node:module");
  const require = createRequire(import.meta.url);
  const { dirname } = await import("node:path");
  const jsDir = dirname(require.resolve("tree-sitter-javascript/package.json"));
  const tsDir = dirname(require.resolve("tree-sitter-typescript/package.json"));
  return {
    js: resolve(jsDir, "tree-sitter-javascript.wasm"),
    ts: resolve(tsDir, "tree-sitter-typescript.wasm"),
    tsx: resolve(tsDir, "tree-sitter-tsx.wasm"),
  };
}

async function initParsers(): Promise<boolean> {
  try {
    const mod = await import("web-tree-sitter");
    // web-tree-sitter exports Parser and Language as named exports
    const Parser = mod.Parser ?? mod.default;
    const Language = mod.Language ?? (Parser as unknown as { Language: typeof LanguageType }).Language;
    await Parser.init();

    // Resolve grammar paths: dist/grammars/ in production, node_modules in dev
    const distGrammars = resolve(import.meta.dirname, "grammars");
    const { existsSync } = await import("node:fs");
    let jsWasm: string, tsWasm: string, tsxWasm: string;
    if (existsSync(resolve(distGrammars, "tree-sitter-javascript.wasm"))) {
      jsWasm = resolve(distGrammars, "tree-sitter-javascript.wasm");
      tsWasm = resolve(distGrammars, "tree-sitter-typescript.wasm");
      tsxWasm = resolve(distGrammars, "tree-sitter-tsx.wasm");
    } else {
      const paths = await resolveDevGrammarPaths();
      jsWasm = paths.js;
      tsWasm = paths.ts;
      tsxWasm = paths.tsx;
    }

    const [jsLang, tsLang, tsxLang] = await Promise.all([
      Language.load(jsWasm),
      Language.load(tsWasm),
      Language.load(tsxWasm),
    ]);

    jsParser = new Parser();
    jsParser.setLanguage(jsLang);

    tsParser = new Parser();
    tsParser.setLanguage(tsLang);

    tsxParser = new Parser();
    tsxParser.setLanguage(tsxLang);

    return true;
  } catch {
    return false;
  }
}

function ensureParsers(): Promise<boolean> {
  if (!initPromise) {
    initPromise = initParsers();
  }
  return initPromise;
}

function getParser(language: string, filePath: string): ParserType | null {
  if (language === "javascript") {
    return filePath.endsWith(".jsx") ? tsxParser : jsParser;
  }
  if (language === "typescript") {
    return (filePath.endsWith(".tsx") || filePath.endsWith(".mts"))
      ? tsxParser
      : tsParser;
  }
  return null;
}

/** Build a rule lookup map from loaded rules */
function buildRuleMap(rules: DetectionRule[]): Map<string, DetectionRule> {
  const map = new Map<string, DetectionRule>();
  for (const rule of rules) {
    map.set(rule.id, rule);
  }
  return map;
}

/** Extract the string value from a tree-sitter string node (strips quotes) */
function extractString(node: NodeType): string | null {
  if (node.type === "string" || node.type === "template_string") {
    const text = node.text;
    // Remove surrounding quotes: "foo", 'foo', `foo`
    if (
      (text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'")) ||
      (text.startsWith("`") && text.endsWith("`"))
    ) {
      return text.slice(1, -1);
    }
    return text;
  }
  return null;
}

/** Create a Finding from a matched AST node */
function makeFinding(
  node: NodeType,
  relativePath: string,
  rule: DetectionRule,
  confidence: number,
  lines: string[],
): Finding {
  const line = node.startPosition.row + 1;
  const column = node.startPosition.column + 1;
  const snippet = (lines[node.startPosition.row] ?? "").trim().slice(0, 120);

  const location: FindingLocation = {
    file: relativePath,
    line,
    column,
    snippet,
  };

  return {
    ruleId: rule.id,
    description: rule.description,
    severity: rule.severity,
    category: rule.category,
    algorithm: rule.algorithm,
    replacement: rule.replacement,
    effort: rule.effort,
    location,
    detectionMethod: "ast",
    confidence,
  };
}

/** Check an import_statement or import expression */
function checkImport(
  node: NodeType,
  relativePath: string,
  ruleMap: Map<string, DetectionRule>,
  lines: string[],
  findings: Finding[],
): void {
  // import ... from "package"
  const source = node.childForFieldName("source");
  if (!source) return;

  const pkg = extractString(source);
  if (!pkg) return;

  for (const pattern of IMPORT_PATTERNS) {
    if (pattern.packages.some((p) => pkg === p || pkg.startsWith(p + "/"))) {
      const rule = ruleMap.get(pattern.ruleId);
      if (rule) {
        findings.push(makeFinding(node, relativePath, rule, pattern.confidence, lines));
      }
      return;
    }
  }
}

/** Check a call_expression node */
function checkCallExpression(
  node: NodeType,
  relativePath: string,
  ruleMap: Map<string, DetectionRule>,
  lines: string[],
  findings: Finding[],
): void {
  const fn = node.childForFieldName("function");
  if (!fn) return;

  const args = node.childForFieldName("arguments");

  // require("package") calls
  if (fn.type === "identifier" && fn.text === "require" && args) {
    const firstArg = args.namedChildren[0];
    if (firstArg) {
      const pkg = extractString(firstArg);
      if (pkg) {
        for (const pattern of IMPORT_PATTERNS) {
          if (pattern.packages.some((p) => pkg === p || pkg.startsWith(p + "/"))) {
            const rule = ruleMap.get(pattern.ruleId);
            if (rule) {
              findings.push(makeFinding(node, relativePath, rule, pattern.confidence, lines));
            }
            return;
          }
        }
      }
    }
    return;
  }

  // Member expression calls: obj.method(args) or method(args)
  if (fn.type === "member_expression") {
    const obj = fn.childForFieldName("object");
    const prop = fn.childForFieldName("property");
    if (!obj || !prop) return;

    const objName = obj.text;
    const methodName = prop.text;

    // Check crypto API call patterns (any object calling known methods)
    checkCryptoCall(node, methodName, args, relativePath, ruleMap, lines, findings);

    // Check method call patterns with option objects (e.g., jwt.sign)
    checkMethodCall(node, objName, methodName, args, relativePath, ruleMap, lines, findings);
    return;
  }

  // Standalone function calls: createHash("md5"), createDiffieHellman(...)
  if (fn.type === "identifier") {
    const methodName = fn.text;
    checkCryptoCall(node, methodName, args, relativePath, ruleMap, lines, findings);
  }
}

/** Match crypto API calls like createHash("md5"), generateKeyPairSync("rsa") */
function checkCryptoCall(
  node: NodeType,
  methodName: string,
  args: NodeType | null,
  relativePath: string,
  ruleMap: Map<string, DetectionRule>,
  lines: string[],
  findings: Finding[],
): void {
  for (const pattern of CRYPTO_CALL_PATTERNS) {
    if (pattern.methodName !== methodName) continue;

    // If pattern has no algorithmArgs, match any call to this method
    if (pattern.algorithmArgs.length === 0) {
      const rule = ruleMap.get(pattern.ruleId);
      if (rule) {
        findings.push(makeFinding(node, relativePath, rule, pattern.confidence, lines));
      }
      return;
    }

    // Check first string argument against known algorithm names
    if (!args) continue;
    const firstArg = args.namedChildren[0];
    if (!firstArg) continue;
    const argValue = extractString(firstArg);
    if (!argValue) continue;

    if (pattern.algorithmArgs.some((a) => argValue.toLowerCase().startsWith(a.toLowerCase()))) {
      const rule = ruleMap.get(pattern.ruleId);
      if (rule) {
        findings.push(makeFinding(node, relativePath, rule, pattern.confidence, lines));
      }
      return;
    }
  }
}

/** Match method calls with options like jwt.sign(payload, key, { algorithm: "RS256" }) */
function checkMethodCall(
  node: NodeType,
  objName: string,
  methodName: string,
  args: NodeType | null,
  relativePath: string,
  ruleMap: Map<string, DetectionRule>,
  lines: string[],
  findings: Finding[],
): void {
  for (const pattern of METHOD_CALL_PATTERNS) {
    if (pattern.objectName !== objName || pattern.methodName !== methodName) continue;
    if (!args) continue;

    // Look for an object argument containing the option property
    for (const arg of args.namedChildren) {
      if (arg.type !== "object") continue;

      for (const pair of arg.namedChildren) {
        if (pair.type !== "pair") continue;
        const key = pair.childForFieldName("key");
        const value = pair.childForFieldName("value");
        if (!key || !value) continue;

        if (key.text !== pattern.optionProperty) continue;

        // Value could be a string or an array of strings
        const values: string[] = [];
        if (value.type === "string") {
          const v = extractString(value);
          if (v) values.push(v);
        } else if (value.type === "array") {
          for (const elem of value.namedChildren) {
            const v = extractString(elem);
            if (v) values.push(v);
          }
        }

        if (values.some((v) => pattern.optionValues.includes(v))) {
          const rule = ruleMap.get(pattern.ruleId);
          if (rule) {
            findings.push(makeFinding(node, relativePath, rule, pattern.confidence, lines));
          }
          return;
        }
      }
    }
  }
}

/** Walk the AST recursively, collecting findings */
function walkTree(
  node: NodeType,
  relativePath: string,
  ruleMap: Map<string, DetectionRule>,
  lines: string[],
  findings: Finding[],
): void {
  switch (node.type) {
    case "import_statement":
      checkImport(node, relativePath, ruleMap, lines, findings);
      break;
    case "call_expression":
      checkCallExpression(node, relativePath, ruleMap, lines, findings);
      break;
  }

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      walkTree(child, relativePath, ruleMap, lines, findings);
    }
  }
}

/**
 * Scan a JavaScript/TypeScript file using AST parsing.
 * Returns findings with detectionMethod "ast" and high confidence.
 * Falls back gracefully: returns empty array if parsers fail to initialize.
 */
export async function scanFileAST(
  filePath: string,
  relativePath: string,
  content: string,
  language: string,
  rules: DetectionRule[],
): Promise<Finding[]> {
  const ready = await ensureParsers();
  if (!ready) return [];

  const parser = getParser(language, filePath);
  if (!parser) return [];

  const tree = parser.parse(content);
  if (!tree || !tree.rootNode) return [];

  const ruleMap = buildRuleMap(rules);
  const lines = content.split("\n");
  const findings: Finding[] = [];

  walkTree(tree.rootNode, relativePath, ruleMap, lines, findings);

  return findings;
}
