/**
 * Verifikasi response aman (Client-Side).
 *
 * Port semantik dari src/Response/Verifier.php (via node-sdk client path):
 * urutan pengecekan, pesan error, dan status code dijaga identik.
 */
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import nacl from 'tweetnacl';

import {
  AEAD_ALG,
  ED25519_ALG,
  HMAC_ALG,
  KDF_PURPOSE_AEAD_RESP,
  KDF_PURPOSE_SIGN_RESP,
  bodyDigestB64,
  buildResponseAeadAad,
  deriveSubkey,
  respAeadNonceFrom,
  respMessage,
  signHmac,
} from './canonical';
import { bytesToUtf8, safeB64Decode, timingSafeEqual, timingSafeEqualString, utf8ToBytes } from './crypto';
import { SecurePayloadError, ResponseVerifyConfig } from './types';

const BAD_REQUEST = 400;
const UNAUTHORIZED = 401;
const UNPROCESSABLE = 422;

/** Normalisasi nama header ke uppercase (semantik PHP `strtoupper`). */
export function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toUpperCase()] = String(v);
  return out;
}

export interface VerifyResponseData {
  mode: string;
  bodyPlain: string | null;
  json: unknown;
}

/**
 * Verifikasi response dengan Exception jika tidak valid (Client-Side).
 * `reqNonceB64` adalah nonce request asal (X-Nonce yang dikirim klien).
 */
export function verifyResponseOrThrow(config: ResponseVerifyConfig, headers: Record<string, string>, rawBody: string, reqNonceB64: string): VerifyResponseData {
  if (!reqNonceB64) {
    throw new SecurePayloadError(BAD_REQUEST, 'Nonce request asal wajib diisi untuk verifikasi response');
  }

  const H = normalizeHeaders(headers);
  const ver = H['X-RESP-SIGNATURE-VERSION'] ?? '';
  const respTs = H['X-RESP-TIMESTAMP'] ?? '';
  const respNonceB64 = H['X-RESP-NONCE'] ?? '';

  if (ver === '' || respTs === '' || respNonceB64 === '') {
    throw new SecurePayloadError(BAD_REQUEST, 'Header response tidak lengkap');
  }
  if (ver !== config.version) {
    throw new SecurePayloadError(BAD_REQUEST, 'Versi protokol response tidak didukung', { terima: ver, ekspektasi: config.version });
  }

  // Validasi kesegaran timestamp response (mencegah response usang diputar ulang).
  if (!/^\d+$/.test(respTs)) {
    throw new SecurePayloadError(BAD_REQUEST, 'Format timestamp response salah', { nilai: respTs });
  }
  const ts = Number(respTs);
  const now = config.clock();
  if (ts > now + config.clockSkew || ts < now - (config.replayTtl + config.clockSkew)) {
    throw new SecurePayloadError(UNAUTHORIZED, 'Timestamp response di luar batas wajar', { ts, now });
  }

  let bodyForSig = rawBody;

  // Mode aead/both: response WAJIB terenkripsi (anti-downgrade, sama seperti request).
  if ((config.mode === 'aead' || config.mode === 'both') && (H['X-RESP-AEAD-ALGORITHM'] ?? '') !== AEAD_ALG) {
    throw new SecurePayloadError(
      UNAUTHORIZED,
      `Mode ${config.mode} mewajibkan enkripsi AEAD pada response, namun header AEAD tidak ada/tidak dikenal`,
    );
  }

  if ((config.mode === 'aead' || config.mode === 'both') && (H['X-RESP-AEAD-ALGORITHM'] ?? '') === AEAD_ALG) {
    let blobB64 = '';
    try {
      const parsed = JSON.parse(rawBody) as { __aead_b64?: string };
      if (parsed && typeof parsed === 'object') blobB64 = parsed.__aead_b64 ?? '';
    } catch {
      // Body bukan JSON valid → dianggap payload AEAD tidak ditemukan.
    }
    if (blobB64 === '') {
      throw new SecurePayloadError(BAD_REQUEST, 'Payload AEAD response tidak ditemukan');
    }

    const keyRaw = safeB64Decode(config.aeadKeyB64 ?? '');
    if (!keyRaw || keyRaw.length !== 32) {
      throw new SecurePayloadError(BAD_REQUEST, 'Kunci AEAD client tidak valid/tersedia');
    }
    const key = deriveSubkey(keyRaw, KDF_PURPOSE_AEAD_RESP, config.version, config.deriveKeys);

    const nonceCalc = respAeadNonceFrom(respNonceB64, reqNonceB64);
    const nonceHdr = safeB64Decode(H['X-RESP-AEAD-NONCE'] ?? '');
    if (!nonceHdr || !timingSafeEqual(nonceHdr, nonceCalc)) {
      throw new SecurePayloadError(UNAUTHORIZED, 'Nonce response mismatch (integritas invalid)');
    }

    const ct = safeB64Decode(blobB64);
    if (!ct) {
      throw new SecurePayloadError(BAD_REQUEST, 'Format base64 body response rusak');
    }

    const aad = buildResponseAeadAad(ver, reqNonceB64, respTs);
    let plainBytes: Uint8Array | null = null;
    try {
      plainBytes = new XChaCha20Poly1305(new Uint8Array(key)).open(new Uint8Array(nonceCalc), ct, utf8ToBytes(aad));
    } catch {
      plainBytes = null;
    }
    if (!plainBytes) {
      throw new SecurePayloadError(UNAUTHORIZED, 'Gagal mendekripsi response (kunci salah atau data rusak)');
    }

    const plain = bytesToUtf8(plainBytes);
    if (config.mode === 'aead') {
      return { mode: 'AEAD', bodyPlain: plain, json: parseJsonOrNull(plain) };
    }
    // Mode both: plaintext hasil dekripsi dipakai untuk verifikasi signature.
    bodyForSig = plain;
  }

  // --- Verifikasi Tanda Tangan (mode hmac / both) — algoritma mengikuti signAlg ---
  if (config.mode === 'hmac' || config.mode === 'both') {
    const alg = H['X-RESP-SIGNATURE-ALGORITHM'] ?? '';
    const sigIn = H['X-RESP-SIGNATURE'] ?? '';
    const digH = H['X-RESP-BODY-DIGEST'] ?? '';

    const expectedAlg = config.signAlg === 'ed25519' ? ED25519_ALG : HMAC_ALG;
    if (alg !== expectedAlg || sigIn === '' || digH === '') {
      throw new SecurePayloadError(BAD_REQUEST, 'Header tanda tangan response tidak lengkap/salah algoritma', { terima: alg, ekspektasi: expectedAlg });
    }

    const digHVal = digH.startsWith('sha256=') ? digH.slice(7) : '';
    if (digHVal === '') {
      throw new SecurePayloadError(BAD_REQUEST, 'Format digest response salah (harus sha256=...)');
    }

    const calcDig = bodyDigestB64(bodyForSig);
    if (!timingSafeEqualString(digHVal, calcDig)) {
      throw new SecurePayloadError(UNPROCESSABLE, 'Integritas Body Digest response gagal');
    }

    const msg = respMessage(config.version, reqNonceB64, respTs, respNonceB64, calcDig);

    if (config.signAlg === 'ed25519') {
      const pub = safeB64Decode(config.ed25519PublicKeyServerB64 ?? '');
      if (!pub || pub.length !== 32) {
        throw new SecurePayloadError(BAD_REQUEST, 'Public key Ed25519 server tidak valid/tersedia di client');
      }
      const sigRaw = safeB64Decode(sigIn);
      if (!sigRaw || sigRaw.length !== nacl.sign.signatureLength) {
        throw new SecurePayloadError(BAD_REQUEST, 'Format signature Ed25519 response rusak');
      }
      let valid = false;
      try {
        valid = nacl.sign.detached.verify(utf8ToBytes(msg), sigRaw, pub);
      } catch {
        valid = false;
      }
      if (!valid) {
        throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan response (Ed25519) tidak valid');
      }
    } else {
      const hmacRaw = config.hmacSecretRaw;
      if (!hmacRaw || hmacRaw.length < 32) {
        throw new SecurePayloadError(BAD_REQUEST, 'HMAC secret client tidak valid/tersedia');
      }
      const signKey = deriveSubkey(utf8ToBytes(hmacRaw), KDF_PURPOSE_SIGN_RESP, config.version, config.deriveKeys);
      const sigB64 = signHmac(msg, signKey);
      if (!timingSafeEqualString(sigB64, sigIn)) {
        // Wording mengikuti node-sdk agar drift test dapat membandingkan pesan error apa adanya.
        throw new SecurePayloadError(UNAUTHORIZED, 'Tanda Tangan response (HMAC) tidak valid');
      }
    }

    return {
      mode: config.mode === 'both' ? 'BOTH' : 'HMAC',
      bodyPlain: bodyForSig,
      json: parseJsonOrNull(bodyForSig),
    };
  }

  throw new SecurePayloadError(BAD_REQUEST, 'Header response tidak lengkap');
}

function parseJsonOrNull(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
