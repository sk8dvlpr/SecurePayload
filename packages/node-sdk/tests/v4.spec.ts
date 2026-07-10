import { describe, it, expect } from 'vitest';
import { SecurePayloadNode } from '../src/sdk.js';

const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('protocol v4', () => {
  it('DEFAULT_VERSION is 4', () => {
    expect(SecurePayloadNode.DEFAULT_VERSION).toBe('4');
  });

  it('json roundtrip with version 4', async () => {
    const client = new SecurePayloadNode({
      mode: 'hmac',
      version: '4',
      clientId: 'c1',
      keyId: 'k1',
      hmacSecretRaw: secret,
      clock: () => 1_700_000_000,
      nonceGenerator: () => Buffer.from('nonce1234567890').toString('base64'),
    });
    const server = new SecurePayloadNode({
      mode: 'hmac',
      version: '4',
      hmacSecretRaw: secret,
      clock: () => 1_700_000_000,
      replayStore: () => true,
    });

    const [headers, body] = await client.buildHeadersAndBody('https://api.test/v4', 'POST', { v: 4 });
    expect(headers['X-Signature-Version']).toBe('4');
    const res = server.verify(headers, body, 'POST', '/v4', '');
    expect(res.ok).toBe(true);
    expect(res.json).toEqual({ v: 4 });
  });
});
