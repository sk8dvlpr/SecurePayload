# @sk8dvlpr/securepayload-node

Node.js/TypeScript SDK (protocol v3) for SecurePayload.

## Install

```bash
npm i @sk8dvlpr/securepayload-node
```

## API

- `buildHeadersAndBody(url, method, payload, extraHeaders?)`
- `verify(headers, rawBody, method, path, query)`
- `buildResponse(requestHeaders, payload)`
- `verifyResponse(headers, rawBody, reqNonceB64)`

## Express middleware (Phase 17)

```bash
npm i express
```

```ts
import express from 'express';
import { SecurePayloadNode, verifySecurePayload, readVerifyResult } from '@sk8dvlpr/securepayload-node/express';

const server = new SecurePayloadNode({ mode: 'both', version: '3', keyLoader: ... });
const app = express();

// Wajib: raw body agar signature cocok dengan bytes asli
app.post('/webhook', express.raw({ type: '*/*' }), verifySecurePayload(server), (req, res) => {
  const vr = readVerifyResult(req);
  res.json({ ok: true, data: vr?.json });
});
```

## Fastify plugin

```bash
npm i fastify
```

```ts
import Fastify from 'fastify';
import { SecurePayloadNode } from '@sk8dvlpr/securepayload-node';
import { fastifySecurePayloadPlugin, readVerifyResult } from '@sk8dvlpr/securepayload-node/fastify';

const server = new SecurePayloadNode({ mode: 'both', version: '3', keyLoader: ... });
const app = Fastify();
await app.register(fastifySecurePayloadPlugin(server));

app.post('/webhook', async (request) => {
  const vr = readVerifyResult(request);
  return { ok: true, data: vr?.json };
});
```

## Test

```bash
npm test
```
