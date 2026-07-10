package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/sk8dvlpr/securepayload-go/securepayload"
	"io"
)

// EchoVerify mengembalikan middleware Echo yang memverifikasi request SecurePayload.
func EchoVerify(client *securepayload.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			rawBody, err := io.ReadAll(req.Body)
			if err != nil {
				return c.JSON(400, map[string]string{"error": "gagal membaca body"})
			}
			headers := HeadersFromHTTP(req.Header)
			path := req.URL.Path
			if path == "" {
				path = "/"
			}
			query := req.URL.RawQuery

			result := client.Verify(headers, string(rawBody), req.Method, path, query)
			if !result.OK {
				return c.JSON(FailStatus(result), map[string]string{"error": FailMessage(result)})
			}

			c.Set(string(VerifyResultKey), result)
			return next(c)
		}
	}
}

// EchoVerifyResult mengambil hasil verifikasi dari konteks Echo (jika ada).
func EchoVerifyResult(c echo.Context) (securepayload.VerifyResult, bool) {
	v := c.Get(string(VerifyResultKey))
	if v == nil {
		return securepayload.VerifyResult{}, false
	}
	r, ok := v.(securepayload.VerifyResult)
	return r, ok
}
