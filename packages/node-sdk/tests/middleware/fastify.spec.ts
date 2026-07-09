import { describe, it, expect, vi } from 'vitest';
import Fastify from 'fastify';
import { SecurePayloadNode } from '../../src/sdk.js';
import { fastifySecurePayloadPlugin } from '../../src/middleware/fastify.js';
import { readVerifyResult } from '../../src/middleware/common.js';

const keys = {
  hmacSecret: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
};

describe('fastifySecurePayloadPlugin', () => {
  it('rejects unauthenticated webhook requests', async () => {
    const server = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
    });

    const app = Fastify();
    await app.register(fastifySecurePayloadPlugin(server));
    app.post('/hook', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'POST',
      url: '/hook',
      headers: { 'content-type': 'application/json' },
      payload: '{}',
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    await app.close();
  });

  it('allows verified requests', async () => {
    const client = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      clientId: 'c1',
      keyId: 'k1',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
      nonceGenerator: () => Buffer.from('nonce1234567891').toString('base64'),
    });
    const server = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
      replayStore: () => true,
    });

    const [headers, body] = await client.buildHeadersAndBody('https://api.test/hook', 'POST', { ok: true });

    const app = Fastify();
    let captured: unknown;
    await app.register(fastifySecurePayloadPlugin(server));
    app.post('/hook', async (request) => {
      captured = readVerifyResult(request);
      return { ok: true };
    });

    const res = await app.inject({
      method: 'POST',
      url: '/hook',
      headers: { ...headers, 'content-type': 'application/json' },
      payload: body,
    });

    expect(res.statusCode).toBe(200);
    expect((captured as { ok?: boolean })?.ok).toBe(true);
    await app.close();
  });
});
