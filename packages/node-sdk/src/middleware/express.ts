import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { SecurePayloadNode } from '../sdk.js';
import type { MiddlewareVerifyOptions } from './common.js';
import {
  applyVerifySuccess,
  normalizeHeaders,
  rawBodyToString,
} from './common.js';

export type { MiddlewareVerifyOptions } from './common.js';
export { readVerifyResult, SECURE_PAYLOAD_RESULT } from './common.js';

/**
 * Middleware Express untuk verifikasi request SecurePayload (server-side).
 *
 * Wajib pasang parser raw body SEBELUM middleware ini (mis. express.raw).
 */
export function verifySecurePayload(
  server: SecurePayloadNode,
  opts?: MiddlewareVerifyOptions,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const rawBody = rawBodyToString((req as Request & { rawBody?: unknown }).rawBody ?? req.body);
    const headers = normalizeHeaders(req.headers as Record<string, string | string[] | undefined>);
    const path = req.path || '/';
    const query = req.url?.includes('?') ? req.url.split('?')[1] ?? '' : '';

    const result = server.verify(headers, rawBody, req.method, path, query);
    if (!result.ok) {
      res.status(result.status ?? 401).json({ error: result.error ?? 'unauthorized' });
      return;
    }

    applyVerifySuccess(req, result, opts);
    next();
  };
}
