/**
 * Primitif kriptografi & encoding PORTABEL untuk React Native (Hermes).
 *
 * Tidak ada satuan pun import `node:*`, `Buffer`, atau `process` di file ini.
 * Semua byte direpresentasikan sebagai Uint8Array murni JavaScript:
 * - SHA-256 / HMAC / HKDF  : @noble/hashes (pure TypeScript)
 * - XChaCha20-Poly1305     : @stablelib/xchacha20poly1305 (pure JS)
 * - Ed25519 + random bytes : tweetnacl (pure JS)
 * - Base64 / UTF-8         : implementasi internal murni JS
 */
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import nacl from 'tweetnacl';

export { sha256, hmac, hkdf };

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Tabel reverse lookup untuk dekode base64 (dibangun sekali saat modul dimuat). */
const B64_REV: Record<string, number> = {};
for (let i = 0; i < B64_ALPHABET.length; i++) B64_REV[B64_ALPHABET[i]!] = i;

/**
 * Encode string UTF-8 menjadi byte. Implementasi manual agar aman di runtime
 * Hermes yang belum selalu menyediakan TextEncoder.
 */
export function utf8ToBytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let cp = text.charCodeAt(i);
    // Gabungkan surrogate pair (emoji/karakter non-BMP) menjadi satu code point.
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < text.length) {
      const lo = text.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        i++;
      }
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return Uint8Array.from(out);
}

/**
 * Dekode byte UTF-8 menjadi string. Implementasi manual pasangan untuk
 * utf8ToBytes (menghindari ketergantungan TextDecoder).
 */
export function bytesToUtf8(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const x = bytes[i]!;
    let cp: number;
    if (x < 0x80) {
      cp = x;
      i += 1;
    } else if (x < 0xe0) {
      cp = ((x & 0x1f) << 6) | (bytes[i + 1]! & 63);
      i += 2;
    } else if (x < 0xf0) {
      cp = ((x & 0x0f) << 12) | ((bytes[i + 1]! & 63) << 6) | (bytes[i + 2]! & 63);
      i += 3;
    } else {
      cp = ((x & 0x07) << 18) | ((bytes[i + 1]! & 63) << 12) | ((bytes[i + 2]! & 63) << 6) | (bytes[i + 3]! & 63);
      i += 4;
    }
    if (cp > 0xffff) {
      // Tulis ulang sebagai surrogate pair agar String.fromCharCode benar.
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else {
      out += String.fromCharCode(cp);
    }
  }
  return out;
}

/** Gabungkan beberapa Uint8Array menjadi satu buffer baru. */
export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/** Base64 encode standar (RFC 4648, dengan padding) — pengganti Buffer.toString('base64'). */
export function b64Encode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    const b1 = has1 ? bytes[i + 1]! : 0;
    const b2 = has2 ? bytes[i + 2]! : 0;
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    out += has1 ? B64_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += has2 ? B64_ALPHABET[b2 & 63] : '=';
  }
  return out;
}

/**
 * Base64 decode mode KETAT — setara `base64_decode($v, true)` di PHP:
 * whitespace diabaikan, karakter di luar alfabet/padding salah → null.
 * Pengganti aman untuk Buffer.from(v, 'base64') yang terlalu longgar.
 */
export function b64DecodeStrict(value: string): Uint8Array | null {
  const clean = value.replace(/[\t\n\f\r ]/g, '');
  if (clean.length === 0 || clean.length % 4 !== 0) return null;
  let padCount = 0;
  for (let i = clean.length - 1; i >= 0 && clean[i] === '='; i--) padCount++;
  const dataLen = clean.length - padCount;
  if (padCount > 2) return null;
  const out = new Uint8Array(Math.floor((dataLen * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < dataLen; i++) {
    const idx = B64_REV[clean[i]!];
    if (idx === undefined) return null;
    acc = (acc << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Karakter sisa setelah padding tidak boleh ada (sudah dicek panjang % 4).
  return o === out.length ? out : null;
}

/** Decode base64 toleran; mengembalikan null bila input kosong/invalid (semantik safeB64Decode node-sdk). */
export function safeB64Decode(value: string): Uint8Array | null {
  try {
    return b64DecodeStrict(value);
  } catch {
    return null;
  }
}

/**
 * Perbandingan konstan-waktu (loop XOR tanpa early-exit pada isi byte).
 * Panjang berbeda langsung gagal — pola umum hash_equals PHP juga begitu
 * (panjang signature/digest bukan rahasia).
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Bandingkan dua string secara konstan-waktu (untuk digest/signature base64). */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqual(utf8ToBytes(a), utf8ToBytes(b));
}

/**
 * Random bytes 16+ untuk nonce. Urutan prioritas:
 * 1. globalThis.crypto.getRandomValues (tersedia via react-native-get-random-values,
 *    expo-crypto, atau Hermes versi baru),
 * 2. fallback PRNG internal tweetnacl (`nacl.randomBytes`) yang sendirinya mencari
 *    crypto.getRandomValues / node crypto.
 *
 * Di aplikasi nyata pastikan salah satu sumber CSPRNG tersedia sebelum request pertama.
 */
export function randomBytes(length: number): Uint8Array {
  const g = globalThis as { crypto?: { getRandomValues?: (arr: Uint8Array) => Uint8Array } };
  if (g.crypto && typeof g.crypto.getRandomValues === 'function') {
    return g.crypto.getRandomValues(new Uint8Array(length));
  }
  return nacl.randomBytes(length);
}
