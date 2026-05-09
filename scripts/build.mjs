import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { stripTypeScriptTypes } from "node:module";

const rootDir = process.cwd();
const outDir = join(rootDir, "dist");
const sourceDirs = ["core", "layers", "util", "worker"];
const sourceFiles = ["config.ts", "index.ts"];

function rewriteRelativeImports(code) {
  return code.replace(
    /((?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?|import\s*\()(["'])(\.{1,2}\/[^"']+)\.ts\2/g,
    (_, prefix, quote, specifier) => `${prefix}${quote}${specifier}.js${quote}`,
  );
}

function transpileTsFile(srcPath, destPath) {
  const source = readFileSync(srcPath, "utf8");
  const transpiled = stripTypeScriptTypes(source, {
    mode: "transform",
    sourceUrl: relative(rootDir, srcPath),
  });
  const rewritten = rewriteRelativeImports(transpiled);
  mkdirSync(dirname(destPath), { recursive: true });
  writeFileSync(destPath, rewritten);
}

function walkTsFiles(dirPath) {
  for (const entry of readdirSync(dirPath)) {
    const fullPath = join(dirPath, entry);
    const stats = statSync(fullPath);
    if (stats.isDirectory()) {
      walkTsFiles(fullPath);
      continue;
    }
    if (extname(fullPath) !== ".ts") continue;
    const relPath = relative(rootDir, fullPath);
    const destPath = join(outDir, relPath).replace(/\.ts$/, ".js");
    transpileTsFile(fullPath, destPath);
  }
}

rmSync(outDir, { recursive: true, force: true });

for (const file of sourceFiles) {
  const srcPath = join(rootDir, file);
  const destPath = join(outDir, file).replace(/\.ts$/, ".js");
  transpileTsFile(srcPath, destPath);
}

for (const dir of sourceDirs) {
  walkTsFiles(join(rootDir, dir));
}
