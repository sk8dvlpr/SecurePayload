import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { SecurePayloadNode, aeadNonceFrom, bodyDigestB64, buildRequestAeadAad, canonicalQuery, hmacMessage, normalizePath, respAeadNonceFrom, respMessage, deriveSubkey } from '../../src/index.ts';

const fixturesRoot = path.resolve(process.cwd(), '../../docs/fixtures/v3');
const keys = JSON.parse(readFileSync(path.join(fixturesRoot, 'keys/standard.json'), 'utf8')) as Record<string, string>;

function loadJson(file: string): any {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function makeUrl(req: any): string {
  return `https://example.test${req.path}?${new URLSearchParams(req.query).toString()}`;
}

function extraHeaders(v: any): Record<string, string> {
  if (!v) return {};
  return Array.isArray(v) ? {} : v;
}

describe('primitive vectors', () => {
  test('normalize-path', () => {
    const vector = loadJson(path.join(fixturesRoot, 'primitive/normalize-path.json'));
    for (const c of vector.cases) expect(normalizePath(c.input)).toBe(c.expected);
  });

  test('canonical-query', () => {
    const vector = loadJson(path.join(fixturesRoot, 'primitive/canonical-query.json'));
    for (const c of vector.cases) expect(canonicalQuery(c.input)).toBe(c.expected);
  });

  test('body-digest', () => {
    const vector = loadJson(path.join(fixturesRoot, 'primitive/body-digest.json'));
    expect(bodyDigestB64(vector.input.json)).toBe(vector.expected.digest_b64);
  });

  test('messages and nonce derivation', () => {
    const req = loadJson(path.join(fixturesRoot, 'primitive/hmac-message.json'));
    expect(hmacMessage(req.input.version, req.input.clientId, req.input.keyId, req.input.timestamp, req.input.nonce_b64, req.input.method, req.input.path, canonicalQuery(req.input.query), req.input.body_digest_b64)).toBe(req.expected.message);

    const res = loadJson(path.join(fixturesRoot, 'primitive/resp-message.json'));
    expect(respMessage(res.input.version, res.input.req_nonce_b64, res.input.resp_timestamp, res.input.resp_nonce_b64, res.input.body_digest_b64)).toBe(res.expected.message);

    const nonceReq = loadJson(path.join(fixturesRoot, 'primitive/aead-nonce-request.json'));
    expect(Buffer.from(aeadNonceFrom(nonceReq.input.nonce_b64, nonceReq.input.method, nonceReq.input.path, nonceReq.input.query_string)).toString('hex')).toBe(nonceReq.expected.nonce_hex);

    const nonceResp = loadJson(path.join(fixturesRoot, 'primitive/resp-aead-nonce.json'));
    expect(Buffer.from(respAeadNonceFrom(nonceResp.input.resp_nonce_b64, nonceResp.input.req_nonce_b64)).toString('hex')).toBe(nonceResp.expected.nonce_hex);
  });

  test('aad and hkdf', () => {
    const aadReq = loadJson(path.join(fixturesRoot, 'primitive/aead-aad-request.json'));
    expect(buildRequestAeadAad(aadReq.input.version, aadReq.input.timestamp, aadReq.input.bound_headers)).toBe(aadReq.expected.aad);

    const hkdf = loadJson(path.join(fixturesRoot, 'primitive/hkdf-derive.json'));
    for (const c of hkdf.cases) {
      const out = deriveSubkey(Buffer.from(c.master, 'utf8'), c.purpose.split('|')[0], '3', true);
      expect(out.toString('hex')).toBe(c.expected_hex);
    }
  });
});

describe('wire conformance', () => {
  const files = readdirSync(path.join(fixturesRoot, 'wire')).filter((f) => f.endsWith('.json')).sort();

  for (const file of files) {
    test(file, async () => {
      const vector = loadJson(path.join(fixturesRoot, 'wire', file));
      const node = new SecurePayloadNode({
        mode: vector.config.mode,
        signAlg: vector.config.signAlg,
        version: vector.protocol_version,
        deriveKeys: Boolean(vector.config.deriveKeys),
        bindHeaders: vector.config.bindHeaders ?? [],
        clientId: keys.clientId,
        keyId: keys.keyId,
        hmacSecretRaw: keys.hmacSecret,
        aeadKeyB64: keys.aeadKeyB64,
        ed25519SecretKeyB64: keys.ed25519ClientSecretB64,
        ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
        clock: () => vector.fixed.timestamp,
        nonceGenerator: () => vector.fixed.nonce_b64,
        respNonceGenerator: () => vector.fixed.resp_nonce_b64,
        replayStore: () => true,
        keyLoader: () => ({
          hmacSecret: keys.hmacSecret,
          aeadKeyB64: keys.aeadKeyB64,
          ed25519PublicKeyB64: keys.ed25519ClientPublicB64,
          ed25519SecretKeyServerB64: keys.ed25519ServerSecretB64,
          ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
        }),
      });

      const [headers, body] = await node.buildHeadersAndBody(makeUrl(vector.request), vector.request.method, vector.request.payload, extraHeaders(vector.request.extra_headers));
      expect(headers).toEqual(vector.expected.headers);
      expect(body).toBe(vector.expected.body);

      const verifyServer = new SecurePayloadNode({
        mode: vector.config.mode,
        signAlg: (vector.server_config?.signAlg ?? vector.config.signAlg),
        version: vector.protocol_version,
        deriveKeys: Boolean(vector.config.deriveKeys),
        bindHeaders: vector.config.bindHeaders ?? [],
        clock: () => vector.fixed.timestamp,
        replayStore: () => true,
        keyLoader: () => ({
          hmacSecret: keys.hmacSecret,
          aeadKeyB64: keys.aeadKeyB64,
          ed25519PublicKeyB64: keys.ed25519ClientPublicB64,
          ed25519SecretKeyServerB64: keys.ed25519ServerSecretB64,
        }),
      });

      const verified = verifyServer.verify(vector.expected.headers, vector.expected.body, vector.request.method, vector.request.path, vector.request.query);
      expect(verified.ok).toBe(true);

      if (vector.expected.response) {
        const responseNode = new SecurePayloadNode({
          mode: vector.config.mode,
          signAlg: vector.config.signAlg,
          version: vector.protocol_version,
          deriveKeys: Boolean(vector.config.deriveKeys),
          clientId: keys.clientId,
          keyId: keys.keyId,
          hmacSecretRaw: keys.hmacSecret,
          aeadKeyB64: keys.aeadKeyB64,
          ed25519SecretKeyServerB64: keys.ed25519ServerSecretB64,
          ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
          clock: () => vector.fixed.resp_timestamp,
          respNonceGenerator: () => vector.fixed.resp_nonce_b64,
          keyLoader: () => ({
            hmacSecret: keys.hmacSecret,
            aeadKeyB64: keys.aeadKeyB64,
            ed25519PublicKeyB64: keys.ed25519ClientPublicB64,
            ed25519SecretKeyServerB64: keys.ed25519ServerSecretB64,
            ed25519PublicKeyServerB64: keys.ed25519ServerPublicB64,
          }),
        });

        const [respHeaders, respBody] = await responseNode.buildResponse(vector.expected.headers, vector.expected.response.payload);
        expect(respHeaders).toEqual(vector.expected.response.headers);
        expect(respBody).toBe(vector.expected.response.body);

        const clientVerify = responseNode.verifyResponse(vector.expected.response.headers, vector.expected.response.body, vector.fixed.nonce_b64);
        expect(clientVerify.ok).toBe(true);
        expect(clientVerify.json).toEqual(vector.expected.response.payload);
      }
    });
  }
});

describe('negative vectors', () => {
  const files = readdirSync(path.join(fixturesRoot, 'negative')).filter((f) => f.endsWith('.json')).sort();

  for (const file of files) {
    test(file, () => {
      const vector = loadJson(path.join(fixturesRoot, 'negative', file));
      const server = new SecurePayloadNode({
        mode: vector.config.mode,
        signAlg: vector.server_config?.signAlg ?? vector.config.signAlg,
        version: vector.protocol_version,
        deriveKeys: Boolean(vector.config.deriveKeys),
        bindHeaders: vector.config.bindHeaders ?? [],
        clock: () => vector.fixed.timestamp,
        replayStore: () => true,
        keyLoader: () => ({
          hmacSecret: keys.hmacSecret,
          aeadKeyB64: keys.aeadKeyB64,
          ed25519PublicKeyB64: keys.ed25519ClientPublicB64,
          ed25519SecretKeyServerB64: keys.ed25519ServerSecretB64,
        }),
      });

      const out = server.verify(vector.expected.headers, vector.expected.body, vector.request.method, vector.request.path, vector.request.query);
      expect(out.ok).toBe(false);
      expect([400, 401]).toContain(out.status);
    });
  }
});
