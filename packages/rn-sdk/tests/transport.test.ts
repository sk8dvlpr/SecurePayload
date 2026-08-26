/**
 * Unit test transport (fetch) dengan fetch yang di-mock.
 *
 * "Server" disimulasikan memakai primitif rn-core itu sendiri (deriveSubkey,
 * respAeadNonceFrom, buildResponseAeadAad, respMessage, signHmac, XChaCha)
 * — semantik sama dengan src/Response/Builder.php di sisi PHP.
 */
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import nacl from 'tweetnacl';
import { describe, expect, test, vi } from 'vitest';

import {
  AEAD_ALG,
  ED25519_ALG,
  HMAC_ALG,
  KDF_PURPOSE_AEAD_RESP,
  KDF_PURPOSE_SIGN_RESP,
  SecurePayloadClient,
  bodyDigestB64,
  buildResponseAeadAad,
  deriveSubkey,
  respAeadNonceFrom,
  respMessage,
  sendSecureRequest,
  signHmac,
} from '../src/index';
import type { FetchLike, RequestInitLike, ResponseLike } from '../src/transport';
import { b64Encode, safeB64Decode, utf8ToBytes } from '../src/crypto';

const KEYS = {
  hmacSecret: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  aeadKeyB64: 'ERERERERERERERERERERERERERERERERERERERERERE=',
  ed25519ClientSecretB64: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkIhUvjRm3kdJEUyQuFfLqtst8/6e2pe0wCXlg4GmIHbEg==',
  ed25519ServerSecretB64: 'Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0Mi/Cl3kvC2/8C/z9t+2wwKoU4CWjZewONC6G44Kct0tg==',
  ed25519ServerPublicB64: 'Ivwpd5Lwtv/Av8/bftsMCqFOAlo2XsDjQuhuOCnLdLY=',
};

const NOW = 1_700_000_060;
const REQ_NONCE = 'AQEBAQEBAQEBAQEBAQEBAQ==';

function makeClient(mode: 'hmac' | 'aead' | 'both', deriveKeys = false): SecurePayloadClient {
  return new SecurePayloadClient({
    mode,
    version: '3',
    clientId: 'conf-client',
    keyId: 'conf-key-v1',
    hmacSecretRaw: KEYS.hmacSecret,
    aeadKeyB64: KEYS.aeadKeyB64,
    ed25519PublicKeyServerB64: KEYS.ed25519ServerPublicB64,
    deriveKeys,
    clock: () => 1_700_000_000,
    nonceGenerator: () => REQ_NONCE,
  });
}

/** Simulasi server: bangun header+body response terproteksi (semantik Response/Builder.php). */
function buildServerResponse(opts: { mode: 'hmac' | 'aead' | 'both'; signAlg?: 'hmac' | 'ed25519'; version?: string; deriveKeys?: boolean; payload: Record<string, unknown>; reqNonce?: string; respNonce?: string }): { headers: Record<string, string>; body: string } {
  const mode = opts.mode;
  const signAlg = opts.signAlg ?? 'hmac';
  const version = opts.version ?? '3';
  const deriveKeys = Boolean(opts.deriveKeys);
  const reqNonce = opts.reqNonce ?? REQ_NONCE;
  const respNonce = opts.respNonce ?? 'AgICAgICAgICAgICAgICAg==';
  const ts = String(NOW);

  const plain = JSON.stringify(opts.payload);
  const headers: Record<string, string> = {
    'X-Resp-Timestamp': ts,
    'X-Resp-Nonce': respNonce,
    'X-Resp-Signature-Version': version,
  };
  let bodyOut = plain;

  if (mode === 'aead' || mode === 'both') {
    const key = deriveSubkey(safeB64Decode(KEYS.aeadKeyB64)!, KDF_PURPOSE_AEAD_RESP, version, deriveKeys);
    const nonce = respAeadNonceFrom(respNonce, reqNonce);
    const aad = buildResponseAeadAad(version, reqNonce, ts);
    const ct = new XChaCha20Poly1305(new Uint8Array(key)).seal(new Uint8Array(nonce), utf8ToBytes(plain), utf8ToBytes(aad));
    headers['X-Resp-AEAD-Algorithm'] = AEAD_ALG;
    headers['X-Resp-AEAD-Nonce'] = b64Encode(nonce);
    bodyOut = JSON.stringify({ __aead_b64: b64Encode(ct) });
  }

  if (mode === 'hmac' || mode === 'both') {
    // Digest & signature dihitung atas PLAINTEXT pra-AEAD (sama seperti klien verifikasi).
    const digest = bodyDigestB64(plain);
    const msg = respMessage(version, reqNonce, ts, respNonce, digest);
    if (signAlg === 'ed25519') {
      headers['X-Resp-Signature-Algorithm'] = ED25519_ALG;
      headers['X-Resp-Signature'] = b64Encode(nacl.sign.detached(utf8ToBytes(msg), safeB64Decode(KEYS.ed25519ServerSecretB64)!));
    } else {
      const signKey = deriveSubkey(utf8ToBytes(KEYS.hmacSecret), KDF_PURPOSE_SIGN_RESP, version, deriveKeys);
      headers['X-Resp-Signature-Algorithm'] = HMAC_ALG;
      headers['X-Resp-Signature'] = signHmac(msg, signKey);
    }
    headers['X-Resp-Body-Digest'] = `sha256=${digest}`;
  }

  return { headers, body: bodyOut };
}

/** Fetch mock: mencatat request, menjawab dengan response yang disiapkan. */
function mockFetch(response: { status?: number; headers?: Record<string, string>; body?: string }): { fetch: FetchLike; calls: Array<{ url: string; init: RequestInitLike }> } {
  const calls: Array<{ url: string; init: RequestInitLike }> = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init: init ?? {} });
    const res: ResponseLike = {
      status: response.status ?? 200,
      ok: (response.status ?? 200) >= 200 && (response.status ?? 200) < 300,
      headers: response.headers ?? {},
      text: async () => response.body ?? '',
    };
    return res;
  };
  return { fetch, calls };
}

describe('sendSecureRequest', () => {
  test('mode both: request terenkripsi+ditandatangani, response diverifikasi otomatis', async () => {
    const client = makeClient('both');
    const sim = buildServerResponse({ mode: 'both', payload: { status: 'ok', id: 7 } });
    const { fetch, calls } = mockFetch({ status: 200, headers: sim.headers, body: sim.body });

    const result = await sendSecureRequest(client, 'https://example.test/v1/pay?a=1&b=2', { amount: 100 }, {
      extraHeaders: { 'X-Request-Id': 'trace-x' },
      fetchImpl: fetch,
    });

    // Request keluar
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toBe('https://example.test/v1/pay?a=1&b=2');
    expect(calls[0]!.init.method).toBe('POST');
    const sentHeaders = calls[0]!.init.headers!;
    expect(sentHeaders['X-Client-Id']).toBe('conf-client');
    expect(sentHeaders['X-AEAD-Algorithm']).toBe(AEAD_ALG);
    expect(sentHeaders['X-Signature']).toBeTruthy();
    expect(JSON.parse(calls[0]!.init.body!)).toEqual({ __aead_b64: expect.any(String) });

    // Response masuk terverifikasi
    expect(result.status).toBe(200);
    expect(result.verification).not.toBeNull();
    expect(result.verification!.ok).toBe(true);
    expect(result.verification!.mode).toBe('BOTH');
    expect(result.verification!.json).toEqual({ status: 'ok', id: 7 });
  });

  test('response tanpa header SecurePayload → verification null (passthrough)', async () => {
    const client = makeClient('both');
    const { fetch, calls } = mockFetch({ status: 404, headers: { 'Content-Type': 'text/plain' }, body: 'not found' });

    const result = await sendSecureRequest(client, 'https://example.test/v1/pay', {}, { fetchImpl: fetch });

    expect(calls.length).toBe(1);
    expect(result.status).toBe(404);
    expect(result.httpOk).toBe(false);
    expect(result.bodyRaw).toBe('not found');
    expect(result.verification).toBeNull();
  });

  test('verifikasi bisa dimatikan via verifyResponse:false', async () => {
    const client = makeClient('both');
    const sim = buildServerResponse({ mode: 'both', payload: { ok: true } });
    const { fetch } = mockFetch({ status: 200, headers: sim.headers, body: sim.body });

    const result = await sendSecureRequest(client, 'https://example.test/v1/pay', {}, { fetchImpl: fetch, verifyResponse: false });
    expect(result.verification).toBeNull();
  });

  test('mode hmac + ed25519 response: diverifikasi dengan public key server', async () => {
    const client = new SecurePayloadClient({
      mode: 'hmac',
      signAlg: 'ed25519',
      version: '3',
      clientId: 'conf-client',
      keyId: 'conf-key-v1',
      hmacSecretRaw: KEYS.hmacSecret,
      ed25519SecretKeyB64: KEYS.ed25519ClientSecretB64,
      ed25519PublicKeyServerB64: KEYS.ed25519ServerPublicB64,
      clock: () => 1_700_000_000,
      nonceGenerator: () => REQ_NONCE,
    });
    const sim = buildServerResponse({ mode: 'hmac', signAlg: 'ed25519', payload: { hello: 'world' } });
    const { fetch } = mockFetch({ status: 200, headers: sim.headers, body: sim.body });

    const result = await sendSecureRequest(client, 'https://example.test/v1/pay', { hi: 1 }, { fetchImpl: fetch });
    expect(result.verification!.ok).toBe(true);
    expect(result.verification!.json).toEqual({ hello: 'world' });
  });

  test('signature server dibobol → verification.ok false (request tetap sukses HTTP)', async () => {
    const client = makeClient('both', true);
    const goodSim = buildServerResponse({ mode: 'both', deriveKeys: true, payload: { status: 'ok' } });
    // Rusak nonce AEAD di header → dekripsi gagal / mismatch.
    const tampered = { ...goodSim.headers, 'X-Resp-AEAD-Nonce': goodSim.headers['X-Resp-AEAD-Nonce']!.slice(0, -4) + 'AAAA' };
    const { fetch } = mockFetch({ status: 200, headers: tampered, body: goodSim.body });

    const result = await sendSecureRequest(client, 'https://example.test/v1/pay', {}, { fetchImpl: fetch });
    expect(result.status).toBe(200);
    expect(result.verification!.ok).toBe(false);
    expect([400, 401]).toContain(result.verification!.status);
  });

  test('fetch error dibungkus jadi verification null & exception dilempar', async () => {
    const client = makeClient('both');
    const failing: FetchLike = vi.fn(async () => {
      throw new TypeError('Network request failed');
    });
    await expect(sendSecureRequest(client, 'https://example.test/v1/pay', {}, { fetchImpl: failing })).rejects.toThrow(TypeError);
  });
});
