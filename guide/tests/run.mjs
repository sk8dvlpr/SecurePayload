#!/usr/bin/env node
/**
 * Parity check: id/ vs en/ page counts and slugs must match.
 * Writes guide/tests/reports/parity.json
 */
import { readdirSync, statSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const guideDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(guideDir, "dist");
const reportDir = path.join(guideDir, "tests", "reports");

function listHtml(dir, base = "") {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    if (statSync(full).isDirectory()) {
      out.push(...listHtml(full, rel));
    } else if (name.endsWith(".html")) {
      out.push(rel.replace(/\\/g, "/"));
    }
  }
  return out.sort();
}

const idPages = listHtml(path.join(dist, "id"));
const enPages = listHtml(path.join(dist, "en"));
const idSet = new Set(idPages);
const enSet = new Set(enPages);
const onlyId = idPages.filter((p) => !enSet.has(p));
const onlyEn = enPages.filter((p) => !idSet.has(p));
const ok = onlyId.length === 0 && onlyEn.length === 0 && idPages.length === enPages.length && idPages.length > 0;

const report = {
  ok,
  generatedAt: new Date().toISOString(),
  idCount: idPages.length,
  enCount: enPages.length,
  onlyId,
  onlyEn,
  slugs: idPages,
};

mkdirSync(reportDir, { recursive: true });
writeFileSync(path.join(reportDir, "parity.json"), JSON.stringify(report, null, 2) + "\n", "utf8");

if (!ok) {
  console.error("Parity check FAILED");
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}

console.log(`Parity OK: ${idPages.length} pages each (id/en)`);
console.log(`Report: tests/reports/parity.json`);
