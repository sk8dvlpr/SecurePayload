#!/usr/bin/env node
/**
 * Build SecurePayload User Guide into guide/dist/
 * Runs guide/tools/generate.py from the repo root.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const guideDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(guideDir, "..");
const script = path.join(guideDir, "tools", "generate.py");

if (!existsSync(script)) {
  console.error("Generator not found at guide/tools/generate.py");
  process.exit(1);
}

const result = spawnSync("python", [script], {
  cwd: repoRoot,
  stdio: "inherit",
  env: process.env,
  shell: process.platform === "win32",
});

process.exit(result.status ?? 1);
