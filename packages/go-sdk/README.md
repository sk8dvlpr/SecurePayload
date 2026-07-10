# securepayload-go

Go SDK for SecurePayload protocol v4 (byte-exact interoperability with PHP core and Node SDK; use `Version: "3"` for legacy).

## Install

```bash
go get github.com/sk8dvlpr/securepayload-go/securepayload
```

## API

- `BuildHeadersAndBody(url, method, payload, extraHeaders)`
- `Verify(headers, rawBody, method, path, query)`
- `BuildResponse(requestHeaders, payload)`
- `VerifyResponse(headers, rawBody, reqNonceB64)`

## Middleware (Phase 18a)

Package `github.com/sk8dvlpr/securepayload-go/middleware` provides Gin, Echo, and Fiber helpers that call `Client.Verify`, abort with JSON on failure, and store the result in request context.

### Gin

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/sk8dvlpr/securepayload-go/middleware"
    "github.com/sk8dvlpr/securepayload-go/securepayload"
)

server := securepayload.New(securepayload.Options{ /* mode, keys, replayStore */ })
r := gin.New()
r.POST("/api", middleware.GinVerify(server), func(c *gin.Context) {
    res, _ := middleware.GinVerifyResult(c)
    c.JSON(200, res.JSON)
})
```

### Echo

```go
e.Use(middleware.EchoVerify(server))
// or per-route: e.POST("/api", handler, middleware.EchoVerify(server))
```

### Fiber

```go
app.Post("/api", middleware.FiberVerify(server), handler)
```

Shared helpers: `NormalizeHeaders`, `WriteJSONError`, `VerifyResultKey`.

## Test

From repository root (requires Go 1.22+ and PHP with `ext-sodium` for interop):

```bash
cd packages/go-sdk
go test ./...
```
