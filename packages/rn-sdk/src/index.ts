/**
 * @sk8dvlpr/securepayload-rn — client-only portable core.
 * Semua modul bebas node:* / Buffer (dibuktikan oleh tests/guard.test.ts).
 */
export {
  SecurePayloadClient,
  collectBoundHeaders,
  parseQueryInput,
} from './client';
export type { Mode, SignAlg, SecurePayloadClientOptions, VerifyResult } from './types';
export { SecurePayloadError } from './types';

// Primitif kanonik (port node-sdk core)
export {
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
  signHmac,
} from './canonical';

// Kripto portabel & encoding
export {
  b64DecodeStrict,
  b64Encode,
  bytesToUtf8,
  concatBytes,
  randomBytes,
  safeB64Decode,
  timingSafeEqual,
  timingSafeEqualString,
  utf8ToBytes,
} from './crypto';

// Verifikasi response & utilitas pendukung
export { normalizeHeaders, verifyResponseOrThrow } from './responseVerifier';
export type { VerifyResponseData } from './responseVerifier';

// Transport & replay
export { sendSecureRequest } from './transport';
export type {
  FetchLike,
  HeaderSource,
  RequestInitLike,
  ResponseLike,
  SecureTransportResult,
  SendSecureOptions,
} from './transport';
export { createInMemoryReplayStore } from './replayStore';
export type { InMemoryReplayStoreOptions, ReplayStoreFn } from './replayStore';
