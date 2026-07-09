package spcrypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	HMACAlg    = "HMAC-SHA256"
	Ed25519Alg = "ED25519"
	AEADAlg    = "XCHACHA20-POLY1305-IETF"
)

func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	prefixed := "/" + strings.TrimLeft(path, "/")
	if len(prefixed) > 1 {
		return strings.TrimRight(prefixed, "/")
	}
	return prefixed
}

func CanonicalQuery(q map[string]interface{}) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, rawURLEncode(k)+"="+rawURLEncode(formatQueryValue(q[k])))
	}
	return strings.Join(parts, "&")
}

func formatQueryValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case []interface{}:
		ss := make([]string, len(t))
		for i, item := range t {
			ss[i] = formatQueryValue(item)
		}
		return strings.Join(ss, ",")
	case []string:
		return strings.Join(t, ",")
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func rawURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func HMACMessage(ver, clientID, keyID, ts, nonceB64, method, path, qStr, digestB64 string) string {
	lines := []string{
		"v" + ver,
		"client=" + clientID,
		"key=" + keyID,
		"ts=" + ts,
		"nonce=" + nonceB64,
		"m=" + method,
		"p=" + path,
		"q=" + qStr,
		"bd=sha256:" + digestB64,
		"",
	}
	return strings.Join(lines, "\n")
}

func RespMessage(ver, reqNonceB64, respTs, respNonceB64, digestB64 string) string {
	lines := []string{
		"resp-v" + ver,
		"req-nonce=" + reqNonceB64,
		"resp-ts=" + respTs,
		"resp-nonce=" + respNonceB64,
		"bd=sha256:" + digestB64,
		"",
	}
	return strings.Join(lines, "\n")
}

func BuildRequestAeadAad(version, ts string, boundHeaders map[string]string) string {
	names := make([]string, 0, len(boundHeaders))
	for n := range boundHeaders {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := []string{"v" + version, "ts=" + ts}
	for _, n := range names {
		parts = append(parts, "h:"+n+"="+boundHeaders[n])
	}
	return strings.Join(parts, "\n")
}

func BuildResponseAeadAad(version, reqNonceB64, respTs string) string {
	return "resp-v" + version + "|req=" + reqNonceB64 + "|ts=" + respTs
}

func AeadNonceFrom(nonceB64, method, path, qStr string) []byte {
	seed := SafeB64Decode(nonceB64)
	if seed == nil {
		seed = make([]byte, 16)
	}
	msg := append([]byte(strings.ToUpper(method)+"\n"+NormalizePath(path)+"\n"+qStr+"\n"), seed...)
	sum := sha256.Sum256(msg)
	return sum[:24]
}

func RespAeadNonceFrom(respNonceB64, reqNonceB64 string) []byte {
	seed := SafeB64Decode(respNonceB64)
	if seed == nil {
		seed = make([]byte, 16)
	}
	msg := append([]byte("response\n"+reqNonceB64+"\n"), seed...)
	sum := sha256.Sum256(msg)
	return sum[:24]
}

func SafeB64Decode(v string) []byte {
	if v == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}
