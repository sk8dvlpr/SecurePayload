package securepayload

type KeyLoader func(clientID, keyID string) LoadedKeys

type ReplayStore func(cacheKey string, ttl int) bool

type Options struct {
	Mode     Mode
	SignAlg  SignAlg
	Version  string
	ClientID string
	KeyID    string

	HMACSecretRaw             string
	AEADKeyB64                string
	Ed25519SecretKeyB64       string
	Ed25519PublicKeyB64       string
	Ed25519SecretKeyServerB64 string
	Ed25519PublicKeyServerB64 string

	DeriveKeys   bool
	BindHeaders  []string
	ReplayTTL    int
	ClockSkew    int
	KeyLoader    KeyLoader
	ReplayStore  ReplayStore
	Clock        func() int64
	NonceGen     func() string
	RespNonceGen func() string
}

func (o Options) withDefaults() Options {
	if o.Mode == "" {
		o.Mode = ModeBoth
	}
	if o.SignAlg == "" {
		o.SignAlg = SignAlgHMAC
	}
	if o.Version == "" {
		o.Version = DefaultVersion
	}
	if o.ReplayTTL == 0 {
		o.ReplayTTL = 120
	}
	if o.ClockSkew == 0 {
		o.ClockSkew = 60
	}
	if o.Clock == nil {
		o.Clock = func() int64 { return unixNow() }
	}
	if o.NonceGen == nil {
		o.NonceGen = genNonceB64
	}
	if o.RespNonceGen == nil {
		o.RespNonceGen = genNonceB64
	}
	return o
}
