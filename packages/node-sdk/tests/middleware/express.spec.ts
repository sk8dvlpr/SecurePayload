import { describe, it, expect, vi } from 'vitest';
import { SecurePayloadNode } from '../../src/sdk.js';
import { verifySecurePayload, readVerifyResult } from '../../src/middleware/express.js';

const keys = {
  hmacSecret: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
};

describe('verifySecurePayload (express)', () => {
  it('returns 401 when verification fails', () => {
    const server = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
    });

    const mw = verifySecurePayload(server);
    const req = {
      method: 'POST',
      path: '/hook',
      url: '/hook',
      headers: {},
      body: '{}',
    };
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    mw(req as never, res as never, next);

    expect(res.status).toHaveBeenCalled();
    expect((res.status as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]).toBeGreaterThanOrEqual(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches result and calls next on success', async () => {
    const client = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      clientId: 'c1',
      keyId: 'k1',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
      nonceGenerator: () => Buffer.from('nonce1234567890').toString('base64'),
    });
    const server = new SecurePayloadNode({
      mode: 'hmac',
      version: '3',
      hmacSecretRaw: keys.hmacSecret,
      clock: () => 1_700_000_000,
      replayStore: () => true,
    });

    const [headers, body] = await client.buildHeadersAndBody('https://api.test/hook', 'POST', { ok: true });

    const mw = verifySecurePayload(server, { resultProperty: 'securePayload' });
    const req = {
      method: 'POST',
      path: '/hook',
      url: '/hook',
      headers,
      body,
    };
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    mw(req as never, res as never, next);

    expect(next).toHaveBeenCalled();
    expect(readVerifyResult(req)?.ok).toBe(true);
    expect((req as { securePayload?: { ok: boolean } }).securePayload?.ok).toBe(true);
  });
});
