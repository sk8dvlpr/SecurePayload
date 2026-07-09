# securepayload-go

Go SDK for SecurePayload protocol v3 (byte-exact interoperability with PHP core and Node SDK).

## Install

```bash
go get github.com/sk8dvlpr/securepayload-go/securepayload
```

## API

- `BuildHeadersAndBody(url, method, payload, extraHeaders)`
- `Verify(headers, rawBody, method, path, query)`
- `BuildResponse(requestHeaders, payload)`
- `VerifyResponse(headers, rawBody, reqNonceB64)`

## Test

From repository root (requires Go 1.22+ and PHP with `ext-sodium` for interop):

```bash
cd packages/go-sdk
go test ./...
```
