/**
 * Pembangunan header & body request aman + verifikasi response (Client-Side).
 *
 * Port semantik dari src/Client/RequestBuilder.php via node-sdk client:
 * - JSON compact (JSON.stringify tanpa spasi, unicode & slash tidak di-escape —
 *   setara JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES untuk payload umum).
 * - Base64 STANDAR (berpadding) untuk semua header.
 * - Timestamp berupa string integer.
 * - Kompresi payload SENGAJA TIDAK diporting (fitur PHP-only).
 */
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import nacl from 'tweetnacl';

import {
  AEAD_ALG,
  ED25519_ALG,
  HMAC_ALG,
  KDF_PURPOSE_AEAD_REQ,
  KDF_PURPOSE_SIGN_REQ,
  aeadNonceFrom,
  bodyDigestB64,
  buildRequestAeadAad,
  canonicalQuery,
  deriveSubkey,
  hmacMessage,
  normalizePath,
  signHmac,
} from './canonical';
import { b64Encode, randomBytes, safeB64Decode, utf8ToBytes } from './crypto';
import { verifyResponseOrThrow } from './responseVerifier';
import { Mode, SecurePayloadClientOptions, SecurePayloadError, VerifyResult } from './types';

export { SecurePayloadError };
export type { Mode, SignAlg, SecurePayloadClientOptions, VerifyResult } from './types';

const BAD_REQUEST = 400;
/** Default mengikuti protokol v4. */
const DEFAULT_VERSION = '4';

function jsonEncode(v: unknown): string {
  return JSON.stringify(v);
}

/** Decode komponen query dengan semantik URLSearchParams: '+' → spasi, %XX → karakter. */
function decodeQueryComponent(part: string): string {
  const normalized = part.replace(/\+/g, '%20');
  try {
    return decodeURIComponent(normalized);
  } catch {
    return part;
  }
}

/**
 * Parse URL sederhana TANPA global URL (tidak selalu tersedia/dapat dipercaya di
 * Hermes). Menghasilkan path dan map query (kunci duplikat → nilai terakhir,
 * semantik Object.fromEntries(searchParams.entries()) pada node-sdk).
 */
function parseUrlParts(url: string): { path: string; qObj: Record<string, unknown> } {
  let rest = url.trim();
  const schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.exec(rest);
  if (schemeMatch) {
    rest = rest.slice(schemeMatch[0].length);
    const slashIdx = rest.indexOf('/');
    rest = slashIdx === -1 ? '/' : rest.slice(slashIdx);
  }
  if (rest.length > 1) rest = rest.replace(/#.*$/, '');
  const qIdx = rest.indexOf('?');
  const rawPath = qIdx === -1 ? rest : rest.slice(0, qIdx);

  const qObj: Record<string, unknown> = {};
  if (qIdx !== -1 && qIdx + 1 < rest.length) {
    for (const pair of rest.slice(qIdx + 1).split('&')) {
      if (pair === '') continue;
      const eq = pair.indexOf('=');
      const key = decodeQueryComponent(eq === -1 ? pair : pair.slice(0, eq));
      const value = eq === -1 ? '' : decodeQueryComponent(pair.slice(eq + 1));
      qObj[key] = value; // kunci duplikat: nilai terakhir menang
    }
  }
  return { path: rawPath || '/', qObj };
}

/** Query string mentah → map (dipakai saat memverifikasi ulang canonical request). */
export function parseQueryInput(q: string | Record<string, unknown>): Record<string, unknown> {
  if (typeof q !== 'string') return q;
  return parseUrlParts('/?' + q).qObj;
}

/** Semua nama header ke uppercase. */
export { normalizeHeaders } from './responseVerifier';

/** Header tambahan mana saja yang diikat ke AAD (sorted ordinal, lowercase). */
export function collectBoundHeaders(all: Record<string, string>, bindHeaders: string[]): Record<string, string> {
  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(all)) norm[k.toLowerCase()] = String(v);
  const out: Record<string, string> = {};
  // Urutan ORDINAL (< >), bukan localeCompare — Intl Hermes terbatas sehingga
  // hasil sort harus identik lintas engine.
  for (const h of bindHeaders) out[h.toLowerCase()] = norm[h.toLowerCase()] ?? '';
  return Object.fromEntries(
    Object.entries(out).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

export class SecurePayloadClient {
  readonly mode: Mode;
  readonly signAlg: 'hmac' | 'ed25519';
  readonly version: string;
  readonly deriveKeys: boolean;

  private readonly clientId: string;
  private readonly keyId: string;
  private readonly hmacSecretRaw: string | null;
  private readonly aeadKeyB64: string | null;
  private readonly ed25519SecretKeyB64: string | null;
  private readonly ed25519PublicKeyServerB64: string | null;
  private readonly bindHeaders: string[];
  private readonly replayTtl: number;
  private readonly clockSkew: number;
  private readonly clock: () => number;
  private readonly nonceGenerator: () => string;

  constructor(opts: SecurePayloadClientOptions = {}) {
    this.mode = opts.mode ?? 'both';
    this.signAlg = opts.signAlg ?? 'hmac';
    this.version = opts.version ?? DEFAULT_VERSION;
    this.deriveKeys = Boolean(opts.deriveKeys);
    this.clientId = opts.clientId ?? '';
    this.keyId = opts.keyId ?? '';
    this.hmacSecretRaw = opts.hmacSecretRaw ?? null;
    this.aeadKeyB64 = opts.aeadKeyB64 ?? null;
    this.ed25519SecretKeyB64 = opts.ed25519SecretKeyB64 ?? null;
    this.ed25519PublicKeyServerB64 = opts.ed25519PublicKeyServerB64 ?? null;
    this.bindHeaders = opts.bindHeaders ?? [];
    this.replayTtl = opts.replayTtl ?? 120;
    this.clockSkew = opts.clockSkew ?? 60;
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    // Nonce default 16 byte CSPRNG → base64 standar (lihat crypto.randomBytes
    // untuk urutan prioritas sumber randomness di perangkat).
    this.nonceGenerator = opts.nonceGenerator ?? (() => b64Encode(randomBytes(16)));
  }

  /**
   * Membangun header keamanan dan body request (Client-Side).
   *
   * @returns Tuple [headers, body]
   * @throws SecurePayloadError Jika parameter salah atau enkripsi gagal
   */
  async buildHeadersAndBody(url: string, method: string, payload: Record<string, unknown>, extraHeaders: Record<string, string> = {}): Promise<[Record<string, string>, string]> {
    if (this.clientId === '' || this.keyId === '') {
      throw new SecurePayloadError(BAD_REQUEST, 'clientId & keyId wajib diisi untuk mode client');
    }
    if (!url) {
      throw new SecurePayloadError(BAD_REQUEST, 'Format URL tidak valid');
    }

    const m = method.toUpperCase();
    const { path, qObj } = parseUrlParts(url);
    const p = normalizePath(path || '/');
    const qStr = canonicalQuery(qObj);
    const ts = String(this.clock());
    const nonceB64 = this.nonceGenerator();
    const ver = this.version;

    // Header dasar yang selalu ada. Header tambahan digabung lebih dahulu agar
    // header keamanan tidak bisa ditimpa oleh caller.
    const headers: Record<string, string> = {
      ...extraHeaders,
      'X-Client-Id': this.clientId,
      'X-Key-Id': this.keyId,
      'X-Timestamp': ts,
      'X-Nonce': nonceB64,
      'X-Signature-Version': ver,
      // Debugging hint saja — server TIDAK menjadikannya source of truth.
      'X-Canonical-Request': b64Encode(utf8ToBytes(`${m}\n${p}\n${qStr}`)),
    };

    // Nilai header kritikal yang diikat ke AAD diambil dari header tambahan
    // yang benar-benar dikirim, agar AAD identik di kedua sisi.
    const bound = collectBoundHeaders(extraHeaders, this.bindHeaders);

    if (this.mode === 'aead' || this.mode === 'both') {
      const plain = jsonEncode(payload);
      const rawKey = safeB64Decode(this.aeadKeyB64 ?? '');
      if (!rawKey || rawKey.length !== 32) throw new SecurePayloadError(BAD_REQUEST, 'AEAD key tidak valid');

      const key = deriveSubkey(rawKey, KDF_PURPOSE_AEAD_REQ, ver, this.deriveKeys);
      const nonce = aeadNonceFrom(nonceB64, m, p, qStr);
      const aad = buildRequestAeadAad(ver, ts, bound);
      const ct = new XChaCha20Poly1305(new Uint8Array(key)).seal(new Uint8Array(nonce), utf8ToBytes(plain), utf8ToBytes(aad));

      headers['X-AEAD-Algorithm'] = AEAD_ALG;
      headers['X-AEAD-Nonce'] = b64Encode(nonce);
      const wrapped = jsonEncode({ __aead_b64: b64Encode(ct) });

      if (this.mode === 'aead') return [headers, wrapped];

      // Digest & HMAC dihitung atas plaintext pra-AEAD — byte inilah yang
      // diverifikasi server, bukan ciphertext.
      const digest = bodyDigestB64(plain);
      const msg = hmacMessage(ver, this.clientId, this.keyId, ts, nonceB64, m, p, qStr, digest);
      const [sig, alg] = this.signCanonical(msg);
      headers['X-Signature-Algorithm'] = alg;
      headers['X-Body-Digest'] = `sha256=${digest}`;
      headers['X-Signature'] = sig;
      return [headers, wrapped];
    }

    // --- MODE: HMAC (Tanda Tangan Saja) ---
    const plain = jsonEncode(payload);
    const digest = bodyDigestB64(plain);
    const msg = hmacMessage(ver, this.clientId, this.keyId, ts, nonceB64, m, p, qStr, digest);
    const [sig, alg] = this.signCanonical(msg);
    headers['X-Signature-Algorithm'] = alg;
    headers['X-Body-Digest'] = `sha256=${digest}`;
    headers['X-Signature'] = sig;
    return [headers, plain];
  }

  /**
   * Verifikasi response dari server. Mengembalikan hasil tanpa melempar exception
   * (ok=false beserta status & pesan error bila gagal).
   */
  verifyResponse(headers: Record<string, string>, rawBody: string, reqNonceB64: string): VerifyResult {
    try {
      const data = this.verifyResponseOrThrow(headers, rawBody, reqNonceB64);
      return { ok: true, ...data };
    } catch (e) {
      const err = e as SecurePayloadError;
      return { ok: false, status: err.status ?? BAD_REQUEST, error: err.message, debug: err.context ?? {}, mode: '', bodyPlain: '', json: null };
    }
  }

  /**
   * Verifikasi response dengan exception jika tidak valid (semantik ResponseVerifier.php).
   */
  verifyResponseOrThrow(headers: Record<string, string>, rawBody: string, reqNonceB64: string): { mode: string; bodyPlain: string | null; json: unknown } {
    return verifyResponseOrThrow(
      {
        mode: this.mode,
        signAlg: this.signAlg,
        version: this.version,
        deriveKeys: this.deriveKeys,
        replayTtl: this.replayTtl,
        clockSkew: this.clockSkew,
        clock: this.clock,
        aeadKeyB64: this.aeadKeyB64,
        hmacSecretRaw: this.hmacSecretRaw,
        ed25519PublicKeyServerB64: this.ed25519PublicKeyServerB64,
      },
      headers,
      rawBody,
      reqNonceB64,
    );
  }

  /**
   * Tanda tangani canonical message sesuai signAlg.
   * v1 client-only: hanya penandatanganan request (purpose sp-sign-req);
   * pembuatan signature response adalah ranah server.
   */
  private signCanonical(message: string): [string, string] {
    if (this.signAlg === 'ed25519') {
      const sk = safeB64Decode(this.ed25519SecretKeyB64 ?? '');
      if (!sk) throw new SecurePayloadError(BAD_REQUEST, 'Secret key Ed25519 tidak valid');
      return [b64Encode(nacl.sign.detached(utf8ToBytes(message), sk)), ED25519_ALG];
    }
    const master = this.hmacSecretRaw ?? '';
    if (master.length < 32) throw new SecurePayloadError(BAD_REQUEST, 'HMAC Secret terlalu pendek. Minimum 32 karakter.');
    const key = deriveSubkey(utf8ToBytes(master), KDF_PURPOSE_SIGN_REQ, this.version, this.deriveKeys);
    return [signHmac(message, key), HMAC_ALG];
  }
}
