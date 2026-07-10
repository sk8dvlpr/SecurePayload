package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/sk8dvlpr/securepayload-go/securepayload"
)

// FiberVerify mengembalikan middleware Fiber yang memverifikasi request SecurePayload.
func FiberVerify(client *securepayload.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		rawBody := c.Body()
		headers := map[string]string{}
		c.Request().Header.VisitAll(func(k, v []byte) {
			headers[string(k)] = string(v)
		})
		path := string(c.Request().URI().Path())
		if path == "" {
			path = "/"
		}
		query := string(c.Request().URI().QueryString())

		result := client.Verify(headers, string(rawBody), c.Method(), path, query)
		if !result.OK {
			return c.Status(FailStatus(result)).JSON(fiber.Map{"error": FailMessage(result)})
		}

		c.Locals(string(VerifyResultKey), result)
		return c.Next()
	}
}

// FiberVerifyResult mengambil hasil verifikasi dari Locals Fiber (jika ada).
func FiberVerifyResult(c *fiber.Ctx) (securepayload.VerifyResult, bool) {
	v := c.Locals(string(VerifyResultKey))
	if v == nil {
		return securepayload.VerifyResult{}, false
	}
	r, ok := v.(securepayload.VerifyResult)
	return r, ok
}
