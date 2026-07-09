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

## Test

```bash
npm test
```
