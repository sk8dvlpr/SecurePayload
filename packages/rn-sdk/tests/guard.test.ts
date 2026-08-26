/**
 * GUARD STATIS — membuktikan runtime src/ bebas dependensi Node.
 *
 * Setiap file src/**\/*.ts discan via regex:
 * - TIDAK BOLEH import 'node:*' (fs, crypto, path, ...)
 * - TIDAK BOLEH import modul bawaan Node secara bare ('fs', 'http', 'crypto', dst)
 * - TIDAK BOLEH memakai global Node: Buffer, process
 *
 * File test ini sendiri berjalan di Node dan boleh memakai node:fs untuk
 * MEMBACA file yang discan.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC_DIR = fileURLToPath(new URL('../src', import.meta.url));

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listTsFiles(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

interface Violation {
  file: string;
  line: number;
  text: string;
  rule: string;
}

const RULES: Array<{ name: string; pattern: RegExp }> = [
  // import ... from 'node:xxx' | require('node:xxx') | import 'node:xxx'
  { name: "no-node-protocol", pattern: /(?:from\s*|require\s*\(\s*|import\s+)['"]node:/ },
  // Bare module bawaan Node (tanpa prefix node:) — termasuk bentuk `from 'crypto'` & `require('fs')`
  {
    name: "no-node-builtin-bare-import",
    pattern: /(?:from\s*|require\s*\(\s*|import\s+)['"](assert|async_hooks|buffer|child_process|cluster|console|constants|crypto|dgram|diagnostics_channel|dns|domain|events|fs|http|http2|https|inspector|module|net|os|path|perf_hooks|process|punycode|querystring|readline|repl|stream|string_decoder|sys|timers|tls|trace_events|tty|url|util|v8|vm|wasi|worker_threads|zlib)(?:\/[\w./-]+)?['"]/,
  },
  // Global khas Node yang tidak ada di Hermes/RN
  { name: "no-buffer-global", pattern: /(^|[^\w$.])Buffer[.\s]/ },
  { name: "no-process-global", pattern: /(^|[^\w$.'"])process\.(env|argv|exit|platform|version|cwd|nextTick)\b/ },
  // require() dinamis gaya CommonJS di source ESM portable
  { name: "no-require-call", pattern: /(^|[^\w$.])require\s*\(/ },
];

function scanFile(file: string): Violation[] {
  const rel = relative(SRC_DIR, file).replace(/\\/g, '/');
  const raw = readFileSync(file, 'utf8');
  // Hapus komentar blok /* */ TANPA menggeser nomor baris (ganti konten dengan spasi).
  const withoutBlocks = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ''));
  const lines = withoutBlocks.split(/\r?\n/);
  const found: Violation[] = [];
  lines.forEach((text, i) => {
    // Buang komentar baris agar contoh di komentar tidak salah terdeteksi.
    const code = text.replace(/\/\/.*$/, '');
    for (const rule of RULES) {
      if (rule.pattern.test(code)) found.push({ file: rel, line: i + 1, text: text.trim(), rule: rule.name });
    }
  });
  return found;
}

describe('guard statis: src/ portabel (bebas node:*)', () => {
  const files = listTsFiles(SRC_DIR);

  it('menemukan file source yang cukup (sanity check)', () => {
    expect(files.length).toBeGreaterThanOrEqual(7);
  });

  it('tidak ada import node:* / builtin Node / global Buffer-process di src/**', () => {
    const violations = files.flatMap(scanFile);
    const pretty = violations.map((v) => `${v.file}:${v.line} [${v.rule}] ${v.text}`).join('\n');
    expect(pretty).toBe('');
  });

  it('setiap rule benar-benar mendeteksi pelanggaran (self-test regex)', () => {
    const sample = [
      "import { createHash } from 'node:crypto';",
      "import fs from 'fs';",
      "const p = require('path');",
      "const b = Buffer.from('x');",
      "if (process.env.CI) {}",
      "import { join } from 'path/posix';",
    ];
    for (const line of sample) {
      const hit = RULES.some((r) => r.pattern.test(line));
      expect(hit, `rule harus menangkap: ${line}`).toBe(true);
    }
    // Baris legal tidak boleh tertangkap
    for (const line of ['import nacl from \'tweetnacl\';', 'const g = globalThis.crypto;', '// contoh: Buffer.from dilarang']) {
      const hit = RULES.some((r) => r.pattern.test(line.replace(/\/\/.*$/, '')));
      expect(hit, `baris legal tidak boleh tertangkap: ${line}`).toBe(false);
    }
  });
});
