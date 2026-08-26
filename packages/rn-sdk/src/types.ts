/** Tipe & error bersama untuk rn-sdk. File ini dipisah agar `client.ts` dan
 * `responseVerifier.ts` tidak saling import (siklus rawan di Metro). */

export type Mode = 'hmac' | 'aead' | 'both';
export type SignAlg = 'hmac' | 'ed25519';

export interface VerifyResult {
  ok: boolean;
  status?: number;
  error?: string;
  debug?: Record<string, unknown>;
  mode?: string;
  bodyPlain?: string | null;
  json?: unknown;
}

export interface SecurePayloadClientOptions {
  mode?: Mode;
  signAlg?: SignAlg;
  /** Versi protokol ("3" atau "4"). Default "4". */
  version?: string;
  clientId?: string;
  keyId?: string;
  /** Secret HMAC mentah (UTF-8), minimal 32 karakter. */
  hmacSecretRaw?: string | null;
  /** Kunci AEAD base64 standar, harus 32 byte setelah decode. */
  aeadKeyB64?: string | null;
  /** Secret key Ed25519 CLIENT (base64) — dipakai menandatangani request bila signAlg='ed25519'. */
  ed25519SecretKeyB64?: string | null;
  /** Public key Ed25519 SERVER (base64) — dipakai memverifikasi signature response. */
  ed25519PublicKeyServerB64?: string | null;
  deriveKeys?: boolean;
  bindHeaders?: string[];
  replayTtl?: number;
  clockSkew?: number;
  clock?: () => number;
  nonceGenerator?: () => string;
}

/** Subset konfigurasi yang dibutuhkan verifier response (dipisah agar bisa diuji mandiri). */
export interface ResponseVerifyConfig {
  mode: Mode;
  signAlg: SignAlg;
  version: string;
  deriveKeys: boolean;
  replayTtl: number;
  clockSkew: number;
  clock: () => number;
  aeadKeyB64?: string | null;
  hmacSecretRaw?: string | null;
  ed25519PublicKeyServerB64?: string | null;
}

export class SecurePayloadError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly context: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'SecurePayloadError';
  }
}
