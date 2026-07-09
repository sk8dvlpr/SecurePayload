import type { VerifyResult } from '../types.js';

/** Symbol key untuk hasil verifikasi di request object. */
export const SECURE_PAYLOAD_RESULT = Symbol.for('securepayload.verifyResult');

export function normalizeHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    out[k.toUpperCase()] = Array.isArray(v) ? String(v[0] ?? '') : String(v);
  }
  return out;
}

export function rawBodyToString(body: unknown): string {
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  if (body === undefined || body === null) return '';
  return String(body);
}

export function attachVerifyResult<T extends object>(req: T, result: VerifyResult): void {
  (req as Record<symbol, VerifyResult>)[SECURE_PAYLOAD_RESULT] = result;
}

export function readVerifyResult<T extends object>(req: T): VerifyResult | undefined {
  return (req as Record<symbol, VerifyResult>)[SECURE_PAYLOAD_RESULT];
}

export interface MiddlewareVerifyOptions {
  /** Property name alternatif selain Symbol (mis. 'securePayload'). */
  resultProperty?: string;
}

export function applyVerifySuccess<T extends object>(
  req: T,
  result: VerifyResult,
  opts?: MiddlewareVerifyOptions,
): void {
  attachVerifyResult(req, result);
  if (opts?.resultProperty) {
    (req as Record<string, VerifyResult>)[opts.resultProperty] = result;
  }
}
