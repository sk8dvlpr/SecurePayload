package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/sk8dvlpr/securepayload-go/securepayload"
)

// GinVerify mengembalikan middleware Gin yang memverifikasi request SecurePayload.
// Body mentah dibaca via c.GetRawData(); path dari URL.Path; query dari RawQuery.
func GinVerify(client *securepayload.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawBody, err := c.GetRawData()
		if err != nil {
			c.AbortWithStatusJSON(400, gin.H{"error": "gagal membaca body"})
			return
		}
		headers := HeadersFromHTTP(c.Request.Header)
		path := c.Request.URL.Path
		if path == "" {
			path = "/"
		}
		query := c.Request.URL.RawQuery

		result := client.Verify(headers, string(rawBody), c.Request.Method, path, query)
		if !result.OK {
			c.AbortWithStatusJSON(FailStatus(result), gin.H{"error": FailMessage(result)})
			return
		}

		c.Set(string(VerifyResultKey), result)
		c.Next()
	}
}

// GinVerifyResult mengambil hasil verifikasi dari konteks Gin (jika ada).
func GinVerifyResult(c *gin.Context) (securepayload.VerifyResult, bool) {
	v, ok := c.Get(string(VerifyResultKey))
	if !ok {
		return securepayload.VerifyResult{}, false
	}
	r, ok := v.(securepayload.VerifyResult)
	return r, ok
}
