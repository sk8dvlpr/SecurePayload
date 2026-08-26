/**
 * Conformance terhadap fixture protokol v3 (sumber kebenaran lintas SDK).
 * Fixture dibaca dari ../../docs/fixtures/v3 — path relatif naik 2 level.
 *
 * CATATAN: file test ini berjalan di Node (vitest) sehingga boleh memakai
 * node:fs untuk MEMBACA fixture. Runtime src/ tetap bebas node:* —
 * dibuktikan terpisah oleh guard.test.ts.
 */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

import {
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
} from '../src/index';
import { utf8ToBytes } from '../src/crypto';

const fixturesRoot = path.resolve(process.cwd(), '../../docs/fixtures/v3');
const keys = JSON.parse(readFileSync(path.join(fixturesRoot, 'keys/standard.json'), 'utf8')) as Record<string, string>;

function loadJson(relPath: string): any {
  return JSON.parse(readFileSync(path.join(fixturesRoot, relPath), 'utf8'));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function extraHeaders(v: any): Record<string, string> {
  if (!v || Array.isArray(v)) return {};
  return v as Record<string, string>;
}

function makeUrl(req: any): string {
  const qs = Object.entries(req.query as Record<string, string>).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  return `https://example.test${req.path}${qs ? `?${qs}` : ''}`;
}

/** Client dengan kredensial standar + clock/nonce ter-inject (deterministik). */
function makeClient(vector: any): SecurePayloadClient {
  return new SecurePayloadClient({
    mode: vector.config.mode,
    signAlg: vector.config.signAlg ?? 'hmac',
    version: vector.protocol_version,
    deriveKeys: Boolean(vector.config.deriveKeys),
    bindHeaders: vector.config.bindHeaders ?? [],
    clientId: keys.clientId,
    keyId: keys.keyId,
    hmacSecretRaw: keys.hmacSecret,
    aeadKeyB64: keys.aeadKeyB64,
    ed25519SecretKeyB64: keys.ed25519ClientSecretB64,
    ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
    clock: () => vector.fixed.timestamp,
    nonceGenerator: () => vector.fixed.nonce_b64,
  });
}

/** Client untuk verifikasi response di sisi klien (clock = waktu response). */
function makeRespVerifyClient(vector: any): SecurePayloadClient {
  return new SecurePayloadClient({
    mode: vector.config.mode,
    signAlg: vector.config.signAlg ?? 'hmac',
    version: vector.protocol_version,
    deriveKeys: Boolean(vector.config.deriveKeys),
    clientId: keys.clientId,
    keyId: keys.keyId,
    hmacSecretRaw: keys.hmacSecret,
    aeadKeyB64: keys.aeadKeyB64,
    ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
    clock: () => vector.fixed.resp_timestamp,
  });
}

describe('primitive vectors', () => {
  test('normalize-path', () => {
    const vector = loadJson('primitive/normalize-path.json');
    for (const c of vector.cases) expect(normalizePath(c.input)).toBe(c.expected);
  });

  test('canonical-query', () => {
    const vector = loadJson('primitive/canonical-query.json');
    for (const c of vector.cases) {
      // Fixture menyimpan map kosong sebagai [] — konversi balik ke object.
      const input = Array.isArray(c.input) ? {} : c.input;
      expect(canonicalQuery(input)).toBe(c.expected);
    }
  });

  test('body-digest', () => {
    const vector = loadJson('primitive/body-digest.json');
    expect(bodyDigestB64(vector.input.json)).toBe(vector.expected.digest_b64);
    expect(`sha256=${bodyDigestB64(vector.input.json)}`).toBe(vector.expected.header_value);
  });

  test('hmac-message & resp-message', () => {
    const req = loadJson('primitive/hmac-message.json');
    expect(hmacMessage(req.input.version, req.input.clientId, req.input.keyId, req.input.timestamp, req.input.nonce_b64, req.input.method, req.input.path, canonicalQuery(req.input.query), req.input.body_digest_b64)).toBe(req.expected.message);

    const res = loadJson('primitive/resp-message.json');
    expect(respMessage(res.input.version, res.input.req_nonce_b64, res.input.resp_timestamp, res.input.resp_nonce_b64, res.input.body_digest_b64)).toBe(res.expected.message);
  });

  test('aead nonce derivation (request & response)', () => {
    const nonceReq = loadJson('primitive/aead-nonce-request.json');
    expect(toHex(aeadNonceFrom(nonceReq.input.nonce_b64, nonceReq.input.method, nonceReq.input.path, nonceReq.input.query_string))).toBe(nonceReq.expected.nonce_hex);

    const nonceResp = loadJson('primitive/resp-aead-nonce.json');
    expect(toHex(respAeadNonceFrom(nonceResp.input.resp_nonce_b64, nonceResp.input.req_nonce_b64))).toBe(nonceResp.expected.nonce_hex);
  });

  test('aead-aad-request', () => {
    const vector = loadJson('primitive/aead-aad-request.json');
    expect(buildRequestAeadAad(vector.input.version, vector.input.timestamp, vector.input.bound_headers)).toBe(vector.expected.aad);
  });

  test('hkdf-derive', () => {
    const vector = loadJson('primitive/hkdf-derive.json');
    for (const c of vector.cases) {
      const out = deriveSubkey(utf8ToBytes(c.master), c.purpose.split('|')[0], '3', true);
      expect(toHex(out)).toBe(c.expected_hex);
    }
  });
});

describe('wire conformance (client-side build)', () => {
  test.each(wireFileNames())('%s', async (file: string) => {
    const vector = loadJson(`wire/${file}`);
    const client = makeClient(vector);

    const [headers, body] = await client.buildHeadersAndBody(makeUrl(vector.request), vector.request.method, vector.request.payload, extraHeaders(vector.request.extra_headers));
    expect(headers).toEqual(vector.expected.headers);
    expect(body).toBe(vector.expected.body);
  });
});

describe('response verification against fixture responses', () => {
  test.each(wireFilesWithResponse())('%s', (file: string) => {
    const vector = loadJson(`wire/${file}`);
    const expected = vector.expected.response;
    const client = makeRespVerifyClient(vector);

    const result = client.verifyResponse(expected.headers, expected.body, vector.fixed.nonce_b64);
    expect(result.ok).toBe(true);
    expect(result.mode).toBe(vector.config.mode === 'both' ? 'BOTH' : vector.config.mode === 'aead' ? 'AEAD' : 'HMAC');
    expect(result.json).toEqual(expected.payload);
    expect(result.bodyPlain).not.toBeNull();
  });
});

describe('negative paths (tamper detection)', () => {
  const base = loadJson('wire/roundtrip-both-hmac-v3.json');
  const client = makeRespVerifyClient(base);
  const respHeaders = () => ({ ...base.expected.response.headers });
  const respBody = base.expected.response.body;
  const reqNonce = base.fixed.nonce_b64;

  test('signature yang dimodifikasi ditolak (401)', () => {
    const h = respHeaders();
    h['X-Resp-Signature'] = h['X-Resp-Signature'].slice(0, -2) + (h['X-Resp-Signature'].endsWith('AA') ? 'BB' : 'AA');
    const r = client.verifyResponse(h, respBody, reqNonce);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(401);
  });

  test('body digest yang dimodifikasi ditolak (422)', () => {
    const h = respHeaders();
    h['X-Resp-Body-Digest'] = 'sha256=0000000000000000000000000000000000000000000=';
    const r = client.verifyResponse(h, respBody, reqNonce);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(422);
  });

  test('header response tidak lengkap ditolak (400)', () => {
    const h = respHeaders();
    delete h['X-Resp-Nonce'];
    const r = client.verifyResponse(h, respBody, reqNonce);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
  });

  test('versi protokol asing ditolak (400)', () => {
    const h = respHeaders();
    h['X-Resp-Signature-Version'] = '9';
    const r = client.verifyResponse(h, respBody, reqNonce);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
  });

  test('timestamp response kadaluarsa ditolak (401)', () => {
    // Jam klien digeser jauh ke depan dari X-Resp-Timestamp fixture → di luar replayTtl+clockSkew.
    const futureFixed = { ...base.fixed, resp_timestamp: base.fixed.resp_timestamp + 10_000 };
    const staleClockClient = makeRespVerifyClient({ ...base, fixed: futureFixed });
    const r = staleClockClient.verifyResponse(respHeaders(), respBody, reqNonce);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(401);
  });

  test('reqNonce kosong ditolak (400)', () => {
    const r = client.verifyResponse(respHeaders(), respBody, '');
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
  });

  test('clientId/keyId wajib diisi', async () => {
    const anon = new SecurePayloadClient({ hmacSecretRaw: keys.hmacSecret });
    await expect(anon.buildHeadersAndBody('https://example.test/x', 'POST', {})).rejects.toMatchObject({ status: 400 });
  });
});

// --- helper pembaca direktori (fungsi terpisah agar hoisting vitest aman) ---
function wireFileNames(): string[] {
  return readdirSync(path.join(fixturesRoot, 'wire')).filter((f) => f.endsWith('.json')).sort();
}

function wireFilesWithResponse(): string[] {
  return wireFileNames().filter((f) => {
    try {
      return Boolean(loadJson(`wire/${f}`).expected.response);
    } catch {
      return false;
    }
  });
}
