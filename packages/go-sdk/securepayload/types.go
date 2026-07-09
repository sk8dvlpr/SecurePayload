package securepayload

type Mode string

const (
	ModeHMAC Mode = "hmac"
	ModeAEAD Mode = "aead"
	ModeBoth Mode = "both"
)

type SignAlg string

const (
	SignAlgHMAC    SignAlg = "hmac"
	SignAlgEd25519 SignAlg = "ed25519"
)

type VerifyResult struct {
	OK        bool                   `json:"ok"`
	Status    int                    `json:"status,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Debug     map[string]interface{} `json:"debug,omitempty"`
	Mode      string                 `json:"mode,omitempty"`
	BodyPlain string                 `json:"bodyPlain,omitempty"`
	JSON      interface{}            `json:"json"`
}

type VerifyData struct {
	Mode      string
	BodyPlain string
	JSON      interface{}
}

type LoadedKeys struct {
	HMACSecret                string
	AEADKeyB64                string
	Ed25519PublicKeyB64       string
	Ed25519SecretKeyServerB64 string
	Ed25519PublicKeyServerB64 string
}
