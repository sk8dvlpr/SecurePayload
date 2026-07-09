package securepayload

const (
	DefaultVersion = "3"

	HMACAlg   = "HMAC-SHA256"
	Ed25519Alg = "ED25519"
	AEADAlg   = "XCHACHA20-POLY1305-IETF"

	KDFPurposeAeadReq  = "sp-aead-req"
	KDFPurposeSignReq  = "sp-sign-req"
	KDFPurposeAeadResp = "sp-aead-resp"
	KDFPurposeSignResp = "sp-sign-resp"

	StatusBadRequest    = 400
	StatusUnauthorized  = 401
	StatusUnprocessable = 422
	StatusServerError   = 500
)
