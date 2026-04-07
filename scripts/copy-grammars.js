import { cpSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const outDir = resolve(dirname(fileURLToPath(import.meta.url)), "../dist/grammars");
mkdirSync(outDir, { recursive: true });

const grammars = [
  ["tree-sitter-javascript", "tree-sitter-javascript.wasm"],
  ["tree-sitter-typescript", "tree-sitter-typescript.wasm"],
  ["tree-sitter-typescript", "tree-sitter-tsx.wasm"],
];

for (const [pkg, file] of grammars) {
  const src = resolve(dirname(require.resolve(`${pkg}/package.json`)), file);
  cpSync(src, resolve(outDir, file));
}

console.log("Copied grammar WASM files to dist/grammars/");
