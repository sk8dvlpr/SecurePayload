import { createHash, randomBytes } from 'node:crypto';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import nacl from 'tweetnacl';
import {
  AEAD_ALG,
  ED25519_ALG,
  HMAC_ALG,
  KDF_PURPOSE_AEAD_REQ,
  KDF_PURPOSE_AEAD_RESP,
  KDF_PURPOSE_SIGN_REQ,
  KDF_PURPOSE_SIGN_RESP,
  aeadNonceFrom,
  bodyDigestB64,
  buildRequestAeadAad,
  buildResponseAeadAad,
  canonicalQuery,
  deriveSubkey,
  hmacMessage,
  normalizePath,
  respAeadNonceFrom,
  respMessage,
  safeB64Decode,
  signHmac,
} from './crypto/core.js';
import { SecurePayloadError, SecurePayloadNodeOptions, VerifyResult } from './types.js';

const BAD_REQUEST = 400;
const UNAUTHORIZED = 401;
const UNPROCESSABLE = 422;
const SERVER_ERROR = 500;

function jsonEncode(v: unknown): string {
  return JSON.stringify(v);
}

function parseQueryInput(q: string | Record<string, unknown>): Record<string, unknown> {
  if (typeof q !== 'string') return q;
  const sp = new URLSearchParams(q);
  const out: Record<string, unknown> = {};
  for (const [k, v] of sp.entries()) out[k] = v;
  return out;
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toUpperCase()] = String(v);
  return out;
}

function collectBoundHeaders(all: Record<string, string>, bindHeaders: string[]): Record<string, string> {
  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(all)) norm[k.toLowerCase()] = String(v);
  const out: Record<string, string> = {};
  for (const h of bindHeaders) out[h.toLowerCase()] = norm[h.toLowerCase()] ?? '';
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

export class SecurePayloadNode {
  static readonly DEFAULT_VERSION = '4';

  private readonly mode: 'hmac' | 'aead' | 'both';
  private readonly signAlg: 'hmac' | 'ed25519';
  private readonly version: string;
  private readonly deriveKeys: boolean;
  private readonly bindHeaders: string[];
  private readonly replayTtl: number;
  private readonly clockSkew: number;
  private readonly clock: () => number;
  private readonly nonceGenerator: () => string;
  private readonly respNonceGenerator: () => string;
  private readonly keyLoader: SecurePayloadNodeOptions['keyLoader'];
  private readonly replayStore: SecurePayloadNodeOptions['replayStore'];
  private readonly opts: SecurePayloadNodeOptions;

  constructor(opts: SecurePayloadNodeOptions = {}) {
    this.opts = opts;
    this.mode = opts.mode ?? 'both';
    this.signAlg = opts.signAlg ?? 'hmac';
    this.version = opts.version ?? SecurePayloadNode.DEFAULT_VERSION;
    this.deriveKeys = Boolean(opts.deriveKeys);
    this.bindHeaders = opts.bindHeaders ?? [];
    this.replayTtl = opts.replayTtl ?? 120;
    this.clockSkew = opts.clockSkew ?? 60;
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.nonceGenerator = opts.nonceGenerator ?? (() => randomBytes(16).toString('base64'));
    this.respNonceGenerator = opts.respNonceGenerator ?? (() => randomBytes(16).toString('base64'));
    this.keyLoader = opts.keyLoader ?? null;
    this.replayStore = opts.replayStore ?? null;
  }

  async buildHeadersAndBody(url: string, method: string, payload: Record<string, unknown>, extraHeaders: Record<string, string> = {}): Promise<[Record<string, string>, string]> {
    const clientId = this.opts.clientId ?? '';
    const keyId = this.opts.keyId ?? '';
    if (!clientId || !keyId) throw new SecurePayloadError(BAD_REQUEST, 'clientId & keyId wajib diisi untuk mode client');

    const parsed = new URL(url);
    const m = method.toUpperCase();
    const path = normalizePath(parsed.pathname || '/');
    const qObj = Object.fromEntries(parsed.searchParams.entries());
    const qStr = canonicalQuery(qObj);
    const ts = String(this.clock());
    const nonceB64 = this.nonceGenerator();

    const headers: Record<string, string> = {
      ...extraHeaders,
      'X-Client-Id': clientId,
      'X-Key-Id': keyId,
      'X-Timestamp': ts,
      'X-Nonce': nonceB64,
      'X-Signature-Version': this.version,
      'X-Canonical-Request': Buffer.from(`${m}\n${path}\n${qStr}`).toString('base64'),
    };

    const bound = collectBoundHeaders(extraHeaders, this.bindHeaders);
    if (this.mode === 'aead' || this.mode === 'both') {
      const plain = jsonEncode(payload);
      const rawKey = safeB64Decode(this.opts.aeadKeyB64 ?? '') ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'AEAD key tidak valid'); })();
      const key = deriveSubkey(rawKey, KDF_PURPOSE_AEAD_REQ, this.version, this.deriveKeys);
      const nonce = aeadNonceFrom(nonceB64, m, path, qStr);
      const aad = buildRequestAeadAad(this.version, ts, bound);
      const aead = new XChaCha20Poly1305(new Uint8Array(key));
      const ct = aead.seal(new Uint8Array(nonce), Buffer.from(plain, 'utf8'), Buffer.from(aad, 'utf8'));
      headers['X-AEAD-Algorithm'] = AEAD_ALG;
      headers['X-AEAD-Nonce'] = Buffer.from(nonce).toString('base64');
      const wrapped = jsonEncode({ __aead_b64: Buffer.from(ct).toString('base64') });
      if (this.mode === 'aead') return [headers, wrapped];

      const digest = bodyDigestB64(plain);
      const msg = hmacMessage(this.version, clientId, keyId, ts, nonceB64, m, path, qStr, digest);
      const [sig, alg] = this.signCanonical(msg, 'req');
      headers['X-Signature-Algorithm'] = alg;
      headers['X-Body-Digest'] = `sha256=${digest}`;
      headers['X-Signature'] = sig;
      return [headers, wrapped];
    }

    const plain = jsonEncode(payload);
    const digest = bodyDigestB64(plain);
    const msg = hmacMessage(this.version, clientId, keyId, ts, nonceB64, m, path, qStr, digest);
    const [sig, alg] = this.signCanonical(msg, 'req');
    headers['X-Signature-Algorithm'] = alg;
    headers['X-Body-Digest'] = `sha256=${digest}`;
    headers['X-Signature'] = sig;
    return [headers, plain];
  }

  verify(headers: Record<string, string>, rawBody: string, method: string, path: string, query: string | Record<string, unknown>): VerifyResult {
    try {
      const data = this.verifyOrThrow(headers, rawBody, method, path, query);
      return { ok: true, ...data };
    } catch (e) {
      const err = e as SecurePayloadError;
      return { ok: false, status: err.status ?? BAD_REQUEST, error: err.message, debug: err.context ?? {}, mode: '', bodyPlain: '', json: null };
    }
  }

  verifyOrThrow(headers: Record<string, string>, rawBody: string, method: string, path: string, query: string | Record<string, unknown>): { mode: string; bodyPlain: string | null; json: unknown } {
    const H = normalizeHeaders(headers);
    const ver = H['X-SIGNATURE-VERSION'] ?? '';
    const cid = H['X-CLIENT-ID'] ?? '';
    const kid = H['X-KEY-ID'] ?? '';
    const tsStr = H['X-TIMESTAMP'] ?? '';
    const nonceB64 = H['X-NONCE'] ?? '';
    if (!ver || !cid || !kid || !tsStr || !nonceB64) throw new SecurePayloadError(BAD_REQUEST, 'Header keamanan tidak lengkap');
    if (ver !== this.version) throw new SecurePayloadError(BAD_REQUEST, 'Versi protokol tidak didukung');
    if (!/^\d+$/.test(tsStr)) throw new SecurePayloadError(BAD_REQUEST, 'Format timestamp salah');
    const ts = Number(tsStr);
    const now = this.clock();
    if (ts > now + this.clockSkew || ts < now - (this.replayTtl + this.clockSkew)) throw new SecurePayloadError(UNAUTHORIZED, 'Timestamp di luar batas wajar (kadaluarsa atau jam salah)');
    if (this.replayStore) {
      const key = createHash('sha256').update(`${cid}|${kid}|${nonceB64}`).digest('hex');
      if (!this.replayStore(key, this.replayTtl + this.clockSkew)) throw new SecurePayloadError(UNAUTHORIZED, 'Replay detected');
    }

    const m = method.toUpperCase();
    const p = normalizePath(path || '/');
    const qStr = canonicalQuery(parseQueryInput(query));

    const keys = this.resolveKeys(cid, kid);
    let bodyForSign = rawBody;
    if ((this.mode === 'aead' || this.mode === 'both')) {
      if ((H['X-AEAD-ALGORITHM'] ?? '') !== AEAD_ALG) throw new SecurePayloadError(UNAUTHORIZED, `Mode ${this.mode} mewajibkan enkripsi AEAD, namun header AEAD tidak ada atau algoritmanya tidak dikenal`);
      const parsed = JSON.parse(rawBody) as { __aead_b64?: string };
      if (!parsed.__aead_b64) throw new SecurePayloadError(BAD_REQUEST, 'Payload AEAD tidak ditemukan');
      const keyRaw = safeB64Decode(keys.aeadKeyB64 ?? '') ?? (() => { throw new SecurePayloadError(SERVER_ERROR, 'Kunci AEAD server tidak valid/tersedia'); })();
      const key = deriveSubkey(keyRaw, KDF_PURPOSE_AEAD_REQ, this.version, this.deriveKeys);
      const nonce = aeadNonceFrom(nonceB64, m, p, qStr);
      const nonceHdr = safeB64Decode(H['X-AEAD-NONCE'] ?? '') ?? Buffer.alloc(0);
      if (!Buffer.from(nonceHdr).equals(Buffer.from(nonce))) throw new SecurePayloadError(UNAUTHORIZED, 'Nonce mismatch (Integritas request invalid)');
      const ct = safeB64Decode(parsed.__aead_b64) ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Format base64 body rusak'); })();
      const aad = buildRequestAeadAad(this.version, tsStr, collectBoundHeaders(headers, this.bindHeaders));
      const aead = new XChaCha20Poly1305(new Uint8Array(key));
      const plain = aead.open(new Uint8Array(nonce), new Uint8Array(ct), Buffer.from(aad, 'utf8'));
      if (!plain) throw new SecurePayloadError(UNAUTHORIZED, 'Gagal mendekripsi (Kunci salah atau data rusak)');
      bodyForSign = Buffer.from(plain).toString('utf8');
      if (this.mode === 'aead') return { mode: 'AEAD', bodyPlain: bodyForSign, json: JSON.parse(bodyForSign) };
      const dig = H['X-BODY-DIGEST'] ?? '';
      const calc = 'sha256=' + bodyDigestB64(bodyForSign);
      if (dig !== calc) throw new SecurePayloadError(UNPROCESSABLE, 'Integritas Body Digest gagal');
    }

    if (this.mode === 'hmac' || this.mode === 'both') {
      const expectedAlg = this.signAlg === 'ed25519' ? ED25519_ALG : HMAC_ALG;
      const alg = H['X-SIGNATURE-ALGORITHM'] ?? '';
      const sigIn = H['X-SIGNATURE'] ?? '';
      const dig = H['X-BODY-DIGEST'] ?? '';
      if (alg !== expectedAlg || !sigIn || !dig) throw new SecurePayloadError(BAD_REQUEST, 'Header tanda tangan tidak lengkap/salah algoritma');
      const digVal = dig.startsWith('sha256=') ? dig.slice(7) : '';
      if (!digVal) throw new SecurePayloadError(BAD_REQUEST, 'Format digest salah (harus sha256=...)');
      const calcDig = bodyDigestB64(bodyForSign);
      if (digVal !== calcDig) throw new SecurePayloadError(UNPROCESSABLE, 'Integritas Body Digest HMAC gagal');
      const msg = hmacMessage(this.version, cid, kid, tsStr, nonceB64, m, p, qStr, calcDig);
      if (this.signAlg === 'ed25519') {
        const pub = safeB64Decode(keys.ed25519PublicKeyB64 ?? '') ?? (() => { throw new SecurePayloadError(SERVER_ERROR, 'Public key Ed25519 server tidak valid/tersedia'); })();
        const sig = safeB64Decode(sigIn) ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Format signature Ed25519 rusak'); })();
        if (!nacl.sign.detached.verify(Buffer.from(msg, 'utf8'), new Uint8Array(sig), new Uint8Array(pub))) throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan (Ed25519) tidak valid');
      } else {
        if (!keys.hmacSecret || keys.hmacSecret.length < 32) throw new SecurePayloadError(SERVER_ERROR, 'Secret Key HMAC tidak ditemukan di server');
        const signKey = deriveSubkey(Buffer.from(keys.hmacSecret, 'utf8'), KDF_PURPOSE_SIGN_REQ, this.version, this.deriveKeys);
        if (signHmac(msg, signKey) !== sigIn) throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan (Signature) tidak valid');
      }
      return { mode: this.mode === 'both' ? 'BOTH' : 'HMAC', bodyPlain: bodyForSign, json: JSON.parse(bodyForSign) };
    }

    throw new SecurePayloadError(BAD_REQUEST, 'Tidak ditemukan header keamanan yang valid');
  }

  async buildResponse(requestHeaders: Record<string, string>, payload: Record<string, unknown>): Promise<[Record<string, string>, string]> {
    const H = normalizeHeaders(requestHeaders);
    const cid = H['X-CLIENT-ID'] ?? '';
    const kid = H['X-KEY-ID'] ?? '';
    const reqNonceB64 = H['X-NONCE'] ?? '';
    if (!reqNonceB64) throw new SecurePayloadError(BAD_REQUEST, 'Nonce request tidak ditemukan untuk binding response');
    const keys = this.resolveKeys(cid, kid);
    const ver = this.version;
    const respTs = String(this.clock());
    const respNonceB64 = this.respNonceGenerator();
    const headers: Record<string, string> = {
      'X-Resp-Timestamp': respTs,
      'X-Resp-Nonce': respNonceB64,
      'X-Resp-Signature-Version': ver,
    };

    const plain = jsonEncode(payload);
    let bodyOut = plain;
    if (this.mode === 'aead' || this.mode === 'both') {
      const raw = safeB64Decode(keys.aeadKeyB64 ?? '') ?? (() => { throw new SecurePayloadError(SERVER_ERROR, 'Kunci AEAD response tidak valid/tersedia'); })();
      const key = deriveSubkey(raw, KDF_PURPOSE_AEAD_RESP, this.version, this.deriveKeys);
      const nonce = respAeadNonceFrom(respNonceB64, reqNonceB64);
      const aad = buildResponseAeadAad(ver, reqNonceB64, respTs);
      const aead = new XChaCha20Poly1305(new Uint8Array(key));
      const ct = aead.seal(new Uint8Array(nonce), Buffer.from(plain, 'utf8'), Buffer.from(aad, 'utf8'));
      bodyOut = jsonEncode({ __aead_b64: Buffer.from(ct).toString('base64') });
      headers['X-Resp-AEAD-Algorithm'] = AEAD_ALG;
      headers['X-Resp-AEAD-Nonce'] = Buffer.from(nonce).toString('base64');
    }

    if (this.mode === 'hmac' || this.mode === 'both') {
      const digest = bodyDigestB64(plain);
      const msg = respMessage(ver, reqNonceB64, respTs, respNonceB64, digest);
      if (this.signAlg === 'ed25519') {
        const sk = safeB64Decode(keys.ed25519SecretKeyServerB64 ?? '') ?? (() => { throw new SecurePayloadError(SERVER_ERROR, 'Secret key Ed25519 server tidak tersedia'); })();
        headers['X-Resp-Signature-Algorithm'] = ED25519_ALG;
        headers['X-Resp-Signature'] = Buffer.from(nacl.sign.detached(Buffer.from(msg, 'utf8'), new Uint8Array(sk))).toString('base64');
      } else {
        if (!keys.hmacSecret || keys.hmacSecret.length < 32) throw new SecurePayloadError(SERVER_ERROR, 'Secret Key HMAC response tidak tersedia di server');
        const signKey = deriveSubkey(Buffer.from(keys.hmacSecret, 'utf8'), KDF_PURPOSE_SIGN_RESP, this.version, this.deriveKeys);
        headers['X-Resp-Signature-Algorithm'] = HMAC_ALG;
        headers['X-Resp-Signature'] = signHmac(msg, signKey);
      }
      headers['X-Resp-Body-Digest'] = `sha256=${digest}`;
    }

    return [headers, bodyOut];
  }

  verifyResponse(headers: Record<string, string>, rawBody: string, reqNonceB64: string): VerifyResult {
    try {
      const data = this.verifyResponseOrThrow(headers, rawBody, reqNonceB64);
      return { ok: true, ...data };
    } catch (e) {
      const err = e as SecurePayloadError;
      return { ok: false, status: err.status ?? BAD_REQUEST, error: err.message, debug: err.context ?? {}, mode: '', bodyPlain: '', json: null };
    }
  }

  verifyResponseOrThrow(headers: Record<string, string>, rawBody: string, reqNonceB64: string): { mode: string; bodyPlain: string | null; json: unknown } {
    const H = normalizeHeaders(headers);
    if (!reqNonceB64) throw new SecurePayloadError(BAD_REQUEST, 'Nonce request asal wajib diisi untuk verifikasi response');
    const ver = H['X-RESP-SIGNATURE-VERSION'] ?? '';
    const respTs = H['X-RESP-TIMESTAMP'] ?? '';
    const respNonceB64 = H['X-RESP-NONCE'] ?? '';
    if (!ver || !respTs || !respNonceB64) throw new SecurePayloadError(BAD_REQUEST, 'Header response tidak lengkap');
    if (ver !== this.version) throw new SecurePayloadError(BAD_REQUEST, 'Versi protokol response tidak didukung');

    const ts = Number(respTs);
    const now = this.clock();
    if (!/^\d+$/.test(respTs)) throw new SecurePayloadError(BAD_REQUEST, 'Format timestamp response salah');
    if (ts > now + this.clockSkew || ts < now - (this.replayTtl + this.clockSkew)) throw new SecurePayloadError(UNAUTHORIZED, 'Timestamp response di luar batas wajar');

    let bodyForSig = rawBody;
    if (this.mode === 'aead' || this.mode === 'both') {
      if ((H['X-RESP-AEAD-ALGORITHM'] ?? '') !== AEAD_ALG) throw new SecurePayloadError(UNAUTHORIZED, `Mode ${this.mode} mewajibkan enkripsi AEAD pada response, namun header AEAD tidak ada/tidak dikenal`);
      const parsed = JSON.parse(rawBody) as { __aead_b64?: string };
      if (!parsed.__aead_b64) throw new SecurePayloadError(BAD_REQUEST, 'Payload AEAD response tidak ditemukan');
      const raw = safeB64Decode(this.opts.aeadKeyB64 ?? '') ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Kunci AEAD client tidak valid/tersedia'); })();
      const key = deriveSubkey(raw, KDF_PURPOSE_AEAD_RESP, this.version, this.deriveKeys);
      const nonce = respAeadNonceFrom(respNonceB64, reqNonceB64);
      const nonceHdr = safeB64Decode(H['X-RESP-AEAD-NONCE'] ?? '') ?? Buffer.alloc(0);
      if (!Buffer.from(nonceHdr).equals(Buffer.from(nonce))) throw new SecurePayloadError(UNAUTHORIZED, 'Nonce response mismatch (integritas invalid)');
      const ct = safeB64Decode(parsed.__aead_b64) ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Format base64 body response rusak'); })();
      const aad = buildResponseAeadAad(ver, reqNonceB64, respTs);
      const aead = new XChaCha20Poly1305(new Uint8Array(key));
      const plain = aead.open(new Uint8Array(nonce), new Uint8Array(ct), Buffer.from(aad, 'utf8'));
      if (!plain) throw new SecurePayloadError(UNAUTHORIZED, 'Gagal mendekripsi response (kunci salah atau data rusak)');
      bodyForSig = Buffer.from(plain).toString('utf8');
      if (this.mode === 'aead') return { mode: 'AEAD', bodyPlain: bodyForSig, json: JSON.parse(bodyForSig) };
    }

    if (this.mode === 'hmac' || this.mode === 'both') {
      const expectedAlg = this.signAlg === 'ed25519' ? ED25519_ALG : HMAC_ALG;
      const alg = H['X-RESP-SIGNATURE-ALGORITHM'] ?? '';
      const sigIn = H['X-RESP-SIGNATURE'] ?? '';
      const dig = H['X-RESP-BODY-DIGEST'] ?? '';
      if (alg !== expectedAlg || !sigIn || !dig) throw new SecurePayloadError(BAD_REQUEST, 'Header tanda tangan response tidak lengkap/salah algoritma');
      const digVal = dig.startsWith('sha256=') ? dig.slice(7) : '';
      if (!digVal) throw new SecurePayloadError(BAD_REQUEST, 'Format digest response salah (harus sha256=...)');
      const calc = bodyDigestB64(bodyForSig);
      if (digVal !== calc) throw new SecurePayloadError(UNPROCESSABLE, 'Integritas Body Digest response gagal');
      const msg = respMessage(this.version, reqNonceB64, respTs, respNonceB64, calc);
      if (this.signAlg === 'ed25519') {
        const pub = safeB64Decode(this.opts.ed25519PublicKeyServerB64 ?? '') ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Public key Ed25519 server tidak valid/tersedia di client'); })();
        const sig = safeB64Decode(sigIn) ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Format signature Ed25519 response rusak'); })();
        if (!nacl.sign.detached.verify(Buffer.from(msg, 'utf8'), new Uint8Array(sig), new Uint8Array(pub))) throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan response (Ed25519) tidak valid');
      } else {
        if (!this.opts.hmacSecretRaw || this.opts.hmacSecretRaw.length < 32) throw new SecurePayloadError(BAD_REQUEST, 'HMAC secret client tidak valid/tersedia');
        const signKey = deriveSubkey(Buffer.from(this.opts.hmacSecretRaw, 'utf8'), KDF_PURPOSE_SIGN_RESP, this.version, this.deriveKeys);
        if (signHmac(msg, signKey) !== sigIn) throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan response (HMAC) tidak valid');
      }
      return { mode: this.mode === 'both' ? 'BOTH' : 'HMAC', bodyPlain: bodyForSig, json: JSON.parse(bodyForSig) };
    }

    throw new SecurePayloadError(BAD_REQUEST, 'Header response tidak lengkap');
  }

  private resolveKeys(cid: string, kid: string) {
    const loaded = this.keyLoader ? this.keyLoader(cid, kid) : {};
    return {
      hmacSecret: loaded?.hmacSecret ?? this.opts.hmacSecretRaw ?? null,
      aeadKeyB64: loaded?.aeadKeyB64 ?? this.opts.aeadKeyB64 ?? null,
      ed25519PublicKeyB64: loaded?.ed25519PublicKeyB64 ?? this.opts.ed25519PublicKeyB64 ?? null,
      ed25519SecretKeyServerB64: loaded?.ed25519SecretKeyServerB64 ?? this.opts.ed25519SecretKeyServerB64 ?? null,
      ed25519PublicKeyServerB64: loaded?.ed25519PublicKeyServerB64 ?? this.opts.ed25519PublicKeyServerB64 ?? null,
    };
  }

  private signCanonical(message: string, scope: 'req' | 'resp'): [string, string] {
    if (this.signAlg === 'ed25519') {
      const b64 = scope === 'req' ? this.opts.ed25519SecretKeyB64 : this.opts.ed25519SecretKeyServerB64;
      const sk = safeB64Decode(b64 ?? '') ?? (() => { throw new SecurePayloadError(BAD_REQUEST, 'Secret key Ed25519 tidak valid'); })();
      return [Buffer.from(nacl.sign.detached(Buffer.from(message, 'utf8'), new Uint8Array(sk))).toString('base64'), ED25519_ALG];
    }
    const master = this.opts.hmacSecretRaw ?? '';
    if (master.length < 32) throw new SecurePayloadError(BAD_REQUEST, 'HMAC Secret terlalu pendek. Minimum 32 karakter.');
    const purpose = scope === 'req' ? KDF_PURPOSE_SIGN_REQ : KDF_PURPOSE_SIGN_RESP;
    const key = deriveSubkey(Buffer.from(master, 'utf8'), purpose, this.version, this.deriveKeys);
    return [signHmac(message, key), HMAC_ALG];
  }
}
