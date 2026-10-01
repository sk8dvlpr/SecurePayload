import { createHash, createHmac, hkdfSync, timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';

export const HMAC_ALG = 'HMAC-SHA256';
export const ED25519_ALG = 'ED25519';
export const AEAD_ALG = 'XCHACHA20-POLY1305-IETF';

export const KDF_PURPOSE_AEAD_REQ = 'sp-aead-req';
export const KDF_PURPOSE_SIGN_REQ = 'sp-sign-req';
export const KDF_PURPOSE_AEAD_RESP = 'sp-aead-resp';
export const KDF_PURPOSE_SIGN_RESP = 'sp-sign-resp';

export function normalizePath(path: string): string {
  if (path === '') return '/';
  const prefixed = '/' + path.replace(/^\/+/, '');
  return prefixed.length > 1 ? prefixed.replace(/\/+$/, '') : prefixed;
}

/**
 * RFC 3986 percent-encoding (PHP rawurlencode / Go QueryEscape + '+' -> '%20').
 * encodeURIComponent leaves !*\'() unescaped — not byte-exact with PHP.
 */
export function rawURLEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

export function canonicalQuery(q: Record<string, unknown>): string {
  const keys = Object.keys(q).sort();
  return keys
    .map((k) => {
      const v = q[k];
      const value = Array.isArray(v) ? v.map(String).join(',') : String(v ?? '');
      return `${rawURLEncode(k)}=${rawURLEncode(value)}`;
    })
    .join('&');
}

export function bodyDigestB64(body: string): string {
  return createHash('sha256').update(body).digest('base64');
}

export function hmacMessage(ver: string, clientId: string, keyId: string, ts: string, nonceB64: string, method: string, path: string, qStr: string, digestB64: string): string {
  return ['v' + ver, 'client=' + clientId, 'key=' + keyId, 'ts=' + ts, 'nonce=' + nonceB64, 'm=' + method, 'p=' + path, 'q=' + qStr, 'bd=sha256:' + digestB64, ''].join('\n');
}

export function respMessage(ver: string, reqNonceB64: string, respTs: string, respNonceB64: string, digestB64: string): string {
  return ['resp-v' + ver, 'req-nonce=' + reqNonceB64, 'resp-ts=' + respTs, 'resp-nonce=' + respNonceB64, 'bd=sha256:' + digestB64, ''].join('\n');
}

export function buildRequestAeadAad(version: string, ts: string, boundHeaders: Record<string, string>): string {
  const names = Object.keys(boundHeaders).sort();
  const parts = ['v' + version, 'ts=' + ts];
  for (const n of names) parts.push(`h:${n}=${boundHeaders[n]}`);
  return parts.join('\n');
}

export function buildResponseAeadAad(version: string, reqNonceB64: string, respTs: string): string {
  return `resp-v${version}|req=${reqNonceB64}|ts=${respTs}`;
}

export function aeadNonceFrom(nonceB64: string, method: string, path: string, qStr: string): Uint8Array {
  const seed = safeB64Decode(nonceB64) ?? Buffer.alloc(16, 0);
  const msg = Buffer.concat([Buffer.from(String(method).toUpperCase() + '\n' + normalizePath(path) + '\n' + qStr + '\n'), seed]);
  return createHash('sha256').update(msg).digest().subarray(0, 24);
}

export function respAeadNonceFrom(respNonceB64: string, reqNonceB64: string): Uint8Array {
  const seed = safeB64Decode(respNonceB64) ?? Buffer.alloc(16, 0);
  const msg = Buffer.concat([Buffer.from('response\n' + reqNonceB64 + '\n'), seed]);
  return createHash('sha256').update(msg).digest().subarray(0, 24);
}

export function deriveSubkey(master: Buffer, purpose: string, version: string, enabled: boolean): Buffer {
  if (!enabled) return master;
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), Buffer.from(`${purpose}|v${version}`), 32));
}

export function signHmac(msg: string, key: Buffer): string {
  return createHmac('sha256', key).update(msg).digest('base64');
}

/** Constant-time buffer compare; length mismatch => false. */
export function timingSafeEqualBuf(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return cryptoTimingSafeEqual(a, b);
}

/** Constant-time UTF-8 string compare. */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqualBuf(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export function safeB64Decode(v: string): Buffer | null {
  try {
    const b = Buffer.from(v, 'base64');
    return b.length > 0 ? b : null;
  } catch {
    return null;
  }
}
