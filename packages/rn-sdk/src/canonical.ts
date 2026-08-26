/**
 * Port portabel dari packages/node-sdk/src/crypto/core.ts (tanpa node:crypto).
 *
 * Kebenaran dijaga oleh tests/drift.test.ts: untuk vektor sama, output fungsi
 * di file ini HARUS byte-identik dengan versi node-sdk.
 */
import { b64Encode, concatBytes, hkdf, hmac, safeB64Decode, sha256, utf8ToBytes } from './crypto';

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

export function canonicalQuery(q: Record<string, unknown>): string {
  // Object.keys().sort() memakai urutan ordinal UTF-16 (deterministik lintas engine,
  // termasuk Hermes yang Intl-nya terbatas).
  const keys = Object.keys(q).sort();
  return keys
    .map((k) => {
      const v = q[k];
      const value = Array.isArray(v) ? v.map(String).join(',') : String(v ?? '');
      return `${encodeURIComponent(k)}=${encodeURIComponent(value)}`;
    })
    .join('&');
}

export function bodyDigestB64(body: string): string {
  return b64Encode(sha256(utf8ToBytes(body)));
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

/** Nonce AEAD request: sha256("METHOD\npath\nquery\n" + seed)[0..24]. */
export function aeadNonceFrom(nonceB64: string, method: string, path: string, qStr: string): Uint8Array {
  const seed = safeB64Decode(nonceB64) ?? new Uint8Array(16);
  const msg = utf8ToBytes(String(method).toUpperCase() + '\n' + normalizePath(path) + '\n' + qStr + '\n');
  return sha256(concatBytes(msg, seed)).slice(0, 24);
}

/** Nonce AEAD response: sha256("response\nreq-nonce\n" + seed)[0..24]. */
export function respAeadNonceFrom(respNonceB64: string, reqNonceB64: string): Uint8Array {
  const seed = safeB64Decode(respNonceB64) ?? new Uint8Array(16);
  const msg = utf8ToBytes('response\n' + reqNonceB64 + '\n');
  return sha256(concatBytes(msg, seed)).slice(0, 24);
}

/**
 * Subkey HKDF-SHA256 (salt kosong, info "<purpose>|v<version>", 32 byte).
 * Bila deriveKeys=false, kunci master dipakai langsung (identik node-sdk/PHP).
 */
export function deriveSubkey(master: Uint8Array, purpose: string, version: string, enabled: boolean): Uint8Array {
  if (!enabled) return master;
  return hkdf(sha256, master, new Uint8Array(0), utf8ToBytes(`${purpose}|v${version}`), 32);
}

/** HMAC-SHA256 → base64 standar. */
export function signHmac(msg: string, key: Uint8Array): string {
  return b64Encode(hmac(sha256, key, utf8ToBytes(msg)));
}
