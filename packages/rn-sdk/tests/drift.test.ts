/**
 * DRIFT TEST — kunci kebenaran rn-sdk.
 *
 * Untuk vektor deterministik yang sama, output rn-core HARUS byte-identik
 * dengan packages/node-sdk (core + client). Jika test ini merah, artinya port
 * portable menyimpang dari semantik node-sdk/PHP.
 *
 * File ini berjalan di Node dan BOLEH mengimpor node-sdk (yang memakai
 * node:crypto). Runtime src/rn-sdk tetap bebas node:* — dijaga guard.test.ts.
 */
import { createHash, createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, test } from 'vitest';

import * as nodeCore from '../../node-sdk/src/crypto/core';
import { SecurePayloadNode } from '../../node-sdk/src/sdk';
import {
  AEAD_ALG,
  ED25519_ALG,
  KDF_PURPOSE_AEAD_REQ,
  SecurePayloadClient,
  aeadNonceFrom,
  bodyDigestB64,
  buildRequestAeadAad,
  canonicalQuery,
  deriveSubkey,
  hmacMessage,
  normalizePath,
  respAeadNonceFrom,
  respMessage,
  safeB64Decode,
  signHmac,
} from '../src/index';

// ---------------------------------------------------------------------------
// Vektor deterministik (diambil dari docs/fixtures/v3)
// ---------------------------------------------------------------------------
const VEC = {
  hmacSecret: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  aeadKeyB64: 'ERERERERERERERERERERERERERERERERERERERERERE=',
  ed25519ClientSecretB64: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkIhUvjRm3kdJEUyQuFfLqtst8/6e2pe0wCXlg4GmIHbEg==',
  ed25519ServerPublicB64: 'Ivwpd5Lwtv/Av8/bftsMCqFOAlo2XsDjQuhuOCnLdLY=',
  clientId: 'conf-client',
  keyId: 'conf-key-v1',
  version: '3',
  ts: 1700000000,
  nonceB64: 'AQEBAQEBAQEBAQEBAQEBAQ==',
  respTs: 1700000060,
  respNonceB64: 'AgICAgICAgICAgICAgICAg==',
  method: 'POST',
  path: '/v1/pay',
  query: { a: '1', b: '2' },
  payload: { amount: 100 },
} as const;

function toHex(bytes: Uint8Array | Buffer): string {
  return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Konfigurasi identik untuk kedua SDK (clock & nonce ter-inject sama persis). */
function sharedOverrides(vector = VEC) {
  return {
    clientId: vector.clientId,
    keyId: vector.keyId,
    hmacSecretRaw: vector.hmacSecret,
    aeadKeyB64: vector.aeadKeyB64,
    ed25519SecretKeyB64: vector.ed25519ClientSecretB64,
    ed25519PublicKeyServerB64: vector.ed25519ServerPublicB64,
    clock: () => vector.ts,
    nonceGenerator: () => vector.nonceB64,
    respNonceGenerator: () => vector.respNonceB64,
  };
}

describe('drift primitives: rn-core vs node-sdk core', () => {
  test('normalizePath', () => {
    for (const input of ['', '/', '//', '/api/v1/resource', '/api/v1/', '///a///b///', 'api/v1']) {
      expect(normalizePath(input)).toBe(nodeCore.normalizePath(input));
    }
  });

  test('canonicalQuery', () => {
    for (const q of [{}, { z: 'last', a: 'first', m: 'middle' }, { key: 'a b', arr: ['x', 'y'] }, { u: 'http://x.io/?p=1&r=[2]' }, { n: null as unknown, e: '' }]) {
      expect(canonicalQuery(q)).toBe(nodeCore.canonicalQuery(q));
    }
  });

  test('bodyDigestB64 == node sha256+base64', () => {
    for (const body of ['{"amount":100}', '', 'unicode ✓ ünïcødé 🚀', 'a'.repeat(10_000)]) {
      const expected = createHash('sha256').update(body).digest('base64');
      expect(bodyDigestB64(body)).toBe(expected);
      expect(bodyDigestB64(body)).toBe(nodeCore.bodyDigestB64(body));
    }
  });

  test('hmacMessage / respMessage', () => {
    const d = bodyDigestB64('{"amount":100}');
    const reqMsg = hmacMessage(VEC.version, VEC.clientId, VEC.keyId, String(VEC.ts), VEC.nonceB64, VEC.method, VEC.path, canonicalQuery(VEC.query), d);
    expect(reqMsg).toBe(nodeCore.hmacMessage(VEC.version, VEC.clientId, VEC.keyId, String(VEC.ts), VEC.nonceB64, VEC.method, VEC.path, canonicalQuery(VEC.query), d));

    const respMsg = respMessage(VEC.version, VEC.nonceB64, String(VEC.respTs), VEC.respNonceB64, d);
    expect(respMsg).toBe(nodeCore.respMessage(VEC.version, VEC.nonceB64, String(VEC.respTs), VEC.respNonceB64, d));
  });

  test('buildRequestAeadAad', () => {
    const bound = { 'x-request-id': 'trace-abc-123' };
    const aad = buildRequestAeadAad(VEC.version, String(VEC.ts), bound);
    expect(aad).toBe(nodeCore.buildRequestAeadAad(VEC.version, String(VEC.ts), bound));
  });

  test('aeadNonceFrom / respAeadNonceFrom (byte-identik)', () => {
    const reqRn = aeadNonceFrom(VEC.nonceB64, VEC.method, VEC.path, canonicalQuery(VEC.query));
    const reqNode = nodeCore.aeadNonceFrom(VEC.nonceB64, VEC.method, VEC.path, canonicalQuery(VEC.query));
    expect(toHex(reqRn)).toBe(toHex(reqNode));

    const respRn = respAeadNonceFrom(VEC.respNonceB64, VEC.nonceB64);
    const respNode = nodeCore.respAeadNonceFrom(VEC.respNonceB64, VEC.nonceB64);
    expect(toHex(respRn)).toBe(toHex(respNode));
  });

  test('deriveSubkey == node hkdfSync', () => {
    for (const purpose of ['sp-sign-req', 'sp-aead-req', 'sp-aead-resp', 'sp-sign-resp']) {
      const masterRn = utf8(VEC.hmacSecret);
      const outRn = deriveSubkey(masterRn, purpose, VEC.version, true);
      const outNode = Buffer.from(hkdfSync('sha256', Buffer.from(VEC.hmacSecret, 'utf8'), Buffer.alloc(0), Buffer.from(`${purpose}|v${VEC.version}`), 32));
      expect(toHex(outRn)).toBe(outNode.toString('hex'));
      // disabled → kunci master dipakai langsung (byte identik dengan input)
      expect(toHex(deriveSubkey(masterRn, purpose, VEC.version, false))).toBe(toHex(masterRn));
    }
  });

  test('signHmac == node createHmac', () => {
    const key = deriveSubkey(utf8(VEC.hmacSecret), KDF_PURPOSE_AEAD_REQ, VEC.version, true);
    const msg = 'arbitrary\nmessage\nwith unicode ✓';
    const expected = createHmac('sha256', Buffer.from(key)).update(msg).digest('base64');
    expect(signHmac(msg, key)).toBe(expected);
    expect(signHmac(msg, new Uint8Array(Buffer.from(VEC.hmacSecret, 'utf8')))).toBe(nodeCore.signHmac(msg, Buffer.from(VEC.hmacSecret, 'utf8')));
  });

  test('safeB64Decode roundtrip', () => {
    const decoded = safeB64Decode(VEC.aeadKeyB64)!;
    expect(decoded.length).toBe(32);
    expect(Array.from(decoded)).toEqual(Array.from(nodeCore.safeB64Decode(VEC.aeadKeyB64)!));
    expect(safeB64Decode('!!!bukan-base64!!!')).toBeNull();
  });
});

describe('drift wire: rn client vs node-sdk client (header & body byte-identik)', () => {
  type CaseConfig = { mode: 'hmac' | 'aead' | 'both'; signAlg?: 'hmac' | 'ed25519'; deriveKeys?: boolean; bindHeaders?: string[]; extraHeaders?: Record<string, string> };

  const cases: Array<[string, CaseConfig]> = [
    ['hmac', { mode: 'hmac' }],
    ['aead', { mode: 'aead' }],
    ['both', { mode: 'both' }],
    ['both+deriveKeys', { mode: 'both', deriveKeys: true }],
    ['aead+bindHeaders', { mode: 'aead', bindHeaders: ['X-Request-Id'], extraHeaders: { 'X-Request-Id': 'trace-abc-123' } }],
    ['both+ed25519', { mode: 'both', signAlg: 'ed25519' }],
  ];

  // CATATAN: URL relatif ("/v1/pay?...") sengaja tidak masuk matriks drift —
  // node-sdk menolaknya via new URL(), sedangkan rn-sdk menerimanya (semantik
  // parse_url PHP). Perilaku superset itu diuji terpisah di fixture.test.ts
  // dan drift-relative-url di bawah.
  const urls = [
    'https://example.test/v1/pay?a=1&b=2',
    'https://example.test/v1/pay',
    'https://example.test/v1/pay?z=last&a=first',
  ];

  for (const [label, cfg] of cases) {
    for (const url of urls) {
      test(`${label} ${url}`, async () => {
        const overrides = sharedOverrides();

        const node = new SecurePayloadNode({
          ...overrides,
          mode: cfg.mode,
          signAlg: cfg.signAlg ?? 'hmac',
          version: VEC.version,
          deriveKeys: Boolean(cfg.deriveKeys),
          bindHeaders: cfg.bindHeaders ?? [],
        });
        const rn = new SecurePayloadClient({
          ...overrides,
          mode: cfg.mode,
          signAlg: cfg.signAlg ?? 'hmac',
          version: VEC.version,
          deriveKeys: Boolean(cfg.deriveKeys),
          bindHeaders: cfg.bindHeaders ?? [],
        });

        const [nodeHeaders, nodeBody] = await node.buildHeadersAndBody(url, VEC.method, VEC.payload, cfg.extraHeaders ?? {});
        const [rnHeaders, rnBody] = await rn.buildHeadersAndBody(url, VEC.method, VEC.payload, cfg.extraHeaders ?? {});

        // Byte-identik: header map sama persis, body string sama persis.
        expect(JSON.stringify(rnHeaders)).toBe(JSON.stringify(nodeHeaders));
        expect(rnBody).toBe(nodeBody);
        if (cfg.mode !== 'hmac') expect(rnHeaders['X-AEAD-Algorithm']).toBe(AEAD_ALG);
        if (cfg.signAlg === 'ed25519') expect(rnHeaders['X-Signature-Algorithm']).toBe(ED25519_ALG);
      });
    }
  }
});

describe('drift verifyResponse: rn vs node-sdk', () => {
  test('hasil verifikasi response identik (ok/mode/bodyPlain/json)', async () => {
    // Bangun response "server" dengan node-sdk (sisi server lengkap ada di sana).
    const server = new SecurePayloadNode({
      ...sharedOverrides(),
      mode: 'both',
      signAlg: 'hmac',
      version: VEC.version,
      deriveKeys: false,
    });
    const requestHeaders: Record<string, string> = { 'X-Nonce': VEC.nonceB64 };
    const [respHeaders, respBody] = await server.buildResponse(requestHeaders, { status: 'ok', data: [1, 2, 3] });

    const nodeVerify = server.verifyResponse(respHeaders, respBody, VEC.nonceB64);
    const rnClient = new SecurePayloadClient({
      mode: 'both',
      signAlg: 'hmac',
      version: VEC.version,
      deriveKeys: false,
      hmacSecretRaw: VEC.hmacSecret,
      aeadKeyB64: VEC.aeadKeyB64,
      clock: () => VEC.respTs,
    });
    const rnVerify = rnClient.verifyResponse(respHeaders, respBody, VEC.nonceB64);

    expect(rnVerify.ok).toBe(true);
    expect(rnVerify.ok).toBe(nodeVerify.ok);
    expect(rnVerify.mode).toBe(nodeVerify.mode);
    expect(rnVerify.bodyPlain).toBe(nodeVerify.bodyPlain);
    expect(JSON.stringify(rnVerify.json)).toBe(JSON.stringify(nodeVerify.json));
  });

  test('response AEAD-only: plaintext hasil dekripsi identik', async () => {
    const server = new SecurePayloadNode({
      ...sharedOverrides(),
      mode: 'aead',
      signAlg: 'hmac',
      version: VEC.version,
      deriveKeys: true,
    });
    const [respHeaders, respBody] = await server.buildResponse({ 'X-Nonce': VEC.nonceB64 }, { nested: { ok: true } });

    const rnClient = new SecurePayloadClient({
      mode: 'aead',
      version: VEC.version,
      deriveKeys: true,
      aeadKeyB64: VEC.aeadKeyB64,
      clock: () => VEC.respTs,
    });
    const rnVerify = rnClient.verifyResponseOrThrow(respHeaders, respBody, VEC.nonceB64);
    expect(rnVerify.mode).toBe('AEAD');
    expect(rnVerify.bodyPlain).toBe('{"nested":{"ok":true}}');
  });

  test('signature HMAC salah → status & pesan identik dengan node-sdk', async () => {
    const server = new SecurePayloadNode({
      ...sharedOverrides(),
      mode: 'hmac',
      signAlg: 'hmac',
      version: VEC.version,
    });
    const [respHeaders, respBody] = await server.buildResponse({ 'X-Nonce': VEC.nonceB64 }, { status: 'ok' });
    const tampered = { ...respHeaders, 'X-Resp-Signature': respHeaders['X-Resp-Signature'].slice(0, -4) + 'AAAA' };

    const nodeVerify = server.verifyResponse(tampered, respBody, VEC.nonceB64);
    const rnVerify = new SecurePayloadClient({
      mode: 'hmac',
      version: VEC.version,
      hmacSecretRaw: VEC.hmacSecret,
      clock: () => VEC.respTs,
    }).verifyResponse(tampered, respBody, VEC.nonceB64);

    expect(rnVerify.ok).toBe(false);
    expect(rnVerify.ok).toBe(nodeVerify.ok);
    expect(rnVerify.status).toBe(nodeVerify.status);
    expect(rnVerify.error).toBe(nodeVerify.error);
  });
});
