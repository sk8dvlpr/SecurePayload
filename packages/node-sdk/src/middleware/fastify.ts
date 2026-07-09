import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { SecurePayloadNode } from '../sdk.js';
import type { MiddlewareVerifyOptions } from './common.js';
import {
  applyVerifySuccess,
  normalizeHeaders,
  rawBodyToString,
} from './common.js';

export type { MiddlewareVerifyOptions } from './common.js';
export { readVerifyResult, SECURE_PAYLOAD_RESULT } from './common.js';

export interface FastifySecurePayloadOptions extends MiddlewareVerifyOptions {
  /** Prefix route yang dilindungi (default: semua route di scope plugin). */
  prefix?: string;
}

/**
 * Plugin Fastify untuk verifikasi request SecurePayload.
 *
 * Pastikan body parser tidak mengubah raw bytes sebelum verifikasi
 * (gunakan `addContentTypeParser` raw atau `preParsing` hook).
 */
export function fastifySecurePayloadPlugin(
  server: SecurePayloadNode,
  pluginOpts: FastifySecurePayloadOptions = {},
): FastifyPluginAsync {
  const plugin = async function securePayloadPlugin(fastify: FastifyInstance): Promise<void> {
    fastify.addContentTypeParser(
      'application/json',
      { parseAs: 'string' },
      (_req: FastifyRequest, body: string, done: (err: Error | null, body?: string) => void) => {
        done(null, body);
      },
    );

    fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
      const rawBody = rawBodyToString((request as FastifyRequest & { rawBody?: unknown }).rawBody ?? request.body);
      const headers = normalizeHeaders(request.headers as Record<string, string | string[] | undefined>);
      const url = request.url.split('?')[0] ?? '/';
      const query = request.url.includes('?') ? request.url.split('?')[1] ?? '' : '';

      const result = server.verify(headers, rawBody, request.method, url, query);
      if (!result.ok) {
        return reply.status(result.status ?? 401).send({ error: result.error ?? 'unauthorized' });
      }

      applyVerifySuccess(request, result, pluginOpts);
    });
  };

  return fp(plugin, { name: 'securepayload-verify' });
}
