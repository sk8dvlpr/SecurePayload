import { readFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test, expect } from 'vitest';
import { SecurePayloadNode } from '../../src/index.ts';

const repoRoot = path.resolve(process.cwd(), '../..');
const keys = JSON.parse(readFileSync(path.join(repoRoot, 'docs/fixtures/v3/keys/standard.json'), 'utf8'));

test('Node build -> PHP verify', async () => {
  const node = new SecurePayloadNode({
    mode: 'both',
    signAlg: 'hmac',
    version: '3',
    clientId: keys.clientId,
    keyId: keys.keyId,
    hmacSecretRaw: keys.hmacSecret,
    aeadKeyB64: keys.aeadKeyB64,
    clock: () => 1700000000,
    nonceGenerator: () => 'AQEBAQEBAQEBAQEBAQEBAQ==',
  });

  const [headers, body] = await node.buildHeadersAndBody('https://example.test/v1/pay?a=1&b=2', 'POST', { amount: 100 });
  const verify = spawnSync('php', [path.join(process.cwd(), 'tests/interop/php_verify.php')], {
    encoding: 'utf8',
    input: JSON.stringify({ headers, body }),
  });
  expect(verify.status).toBe(0);
  const out = JSON.parse(verify.stdout);
  expect(out.ok).toBe(true);
});

test('PHP build -> Node verify', () => {
  const built = spawnSync('php', [path.join(process.cwd(), 'tests/interop/php_build.php')], { encoding: 'utf8' });
  expect(built.status).toBe(0);
  const req = JSON.parse(built.stdout);

  const node = new SecurePayloadNode({
    mode: 'both',
    signAlg: 'hmac',
    version: '3',
    clock: () => 1700000000,
    replayStore: () => true,
    keyLoader: () => ({
      hmacSecret: keys.hmacSecret,
      aeadKeyB64: keys.aeadKeyB64,
    }),
  });

  const out = node.verify(req.headers, req.body, 'POST', '/v1/pay', { a: '1', b: '2' });
  expect(out.ok).toBe(true);
});
