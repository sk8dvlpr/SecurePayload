/**
 * Transport fetch opsional: satu panggilan = build request aman + kirim +
 * verifikasi response (bila server mengirim header SecurePayload response).
 *
 * Memakai struktur tipe minimal (bukan lib.dom) supaya tidak menuntut DOM
 * types dan tetap kompatibel dengan runtime React Native.
 */
import { SecurePayloadClient } from './client';
import { VerifyResult } from './types';

/** Fetch minimal yang dibutuhkan — cocok dengan signature globalThis.fetch. */
export type FetchLike = (url: string, init?: RequestInitLike) => Promise<ResponseLike>;

export interface RequestInitLike {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/** Kolektor headers dari implementasi fetch mana pun (Headers-like atau objek polos). */
export interface HeaderSource {
  forEach?(callback: (value: string, key: string) => void): void;
}

export interface ResponseLike {
  status: number;
  ok: boolean;
  headers: HeaderSource | Record<string, string>;
  text(): Promise<string>;
}

export interface SendSecureOptions {
  /** Default 'POST'. */
  method?: string;
  /** Header tambahan (ikut diikat ke AAD bila masuk daftar bindHeaders). */
  extraHeaders?: Record<string, string>;
  /** Inject fetch untuk testing / polyfill. Default: globalThis.fetch. */
  fetchImpl?: FetchLike;
  /** Verifikasi response otomatis. Default true. */
  verifyResponse?: boolean;
}

export interface SecureTransportResult {
  status: number;
  httpOk: boolean;
  /** Headers response dalam bentuk map (nama asli dipertahankan). */
  headers: Record<string, string>;
  bodyRaw: string;
  /** Hasil verifikasi response; null bila response tidak ber-header SecurePayload. */
  verification: VerifyResult | null;
}

function defaultFetch(): FetchLike {
  const g = globalThis as { fetch?: FetchLike };
  if (typeof g.fetch !== 'function') {
    throw new Error('globalThis.fetch tidak tersedia — berikan fetchImpl atau install polyfill');
  }
  return g.fetch.bind(globalThis);
}

/** Kumpulkan headers response menjadi map sederhana. */
function collectHeaders(source: HeaderSource | Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  if (source && typeof source.forEach === 'function') {
    source.forEach((value: string, key: string) => {
      out[key] = value;
    });
    return out;
  }
  for (const [k, v] of Object.entries(source as Record<string, string>)) out[k] = v;
  return out;
}

/**
 * Kirim request terproteksi dan (opsional) verifikasi response.
 *
 * @param client Instance SecurePayloadClient yang sudah dikonfigurasi.
 * @param url URL tujuan (absolute atau path absolut).
 * @param payload Body JSON yang akan dikirim.
 */
export async function sendSecureRequest(client: SecurePayloadClient, url: string, payload: Record<string, unknown>, options: SendSecureOptions = {}): Promise<SecureTransportResult> {
  const doFetch = options.fetchImpl ?? defaultFetch();
  const method = (options.method ?? 'POST').toUpperCase();

  const [headers, body] = await client.buildHeadersAndBody(url, method, payload, options.extraHeaders ?? {});
  const reqNonceB64 = headers['X-Nonce'] ?? '';

  const res = await doFetch(url, { method, headers, body });
  const resHeaders = collectHeaders(res.headers);
  const bodyRaw = await res.text();

  const lowerName = (name: string): string => name.toLowerCase();
  const hasRespSig = Object.keys(resHeaders).some((k) => lowerName(k) === 'x-resp-signature-version');

  let verification: VerifyResult | null = null;
  if (options.verifyResponse !== false && hasRespSig) {
    verification = client.verifyResponse(resHeaders, bodyRaw, reqNonceB64);
  }

  return { status: res.status, httpOk: Boolean(res.ok), headers: resHeaders, bodyRaw, verification };
}
