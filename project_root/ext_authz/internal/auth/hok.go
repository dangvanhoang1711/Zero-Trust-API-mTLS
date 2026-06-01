package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ValidateHoKBinding verifies a Holder-of-Key proof using RFC 9421-style HTTP signatures.
// The token must carry a cnf.jwk claim; the request is considered valid only when:
// 1) signature input is present and parseable
// 2) request components can be canonicalized deterministically
// 3) the signature validates against the key in cnf.jwk
func ValidateHoKBinding(expectedCNFJWK map[string]any, requestMethod, requestPath, requestHost string, requestHeaders map[string]string, signatureHeader string) error {
	if len(expectedCNFJWK) == 0 {
		return unauthorized("missing cnf.jwk")
	}

	publicKey, err := parseJWKPublicKey(expectedCNFJWK)
	if err != nil {
		return err
	}

	params, err := parseSignatureHeader(signatureHeader)
	if err != nil {
		return unauthorized(err.Error())
	}

	algorithm, err := resolveHoKAlgorithm(params["algorithm"])
	if err != nil {
		return unauthorized(err.Error())
	}

	rawSig, ok := params["signature"]
	if !ok || strings.TrimSpace(rawSig) == "" {
		return unauthorized("missing signature")
	}

	sig, err := decodeSignature(rawSig)
	if err != nil {
		return unauthorized("invalid signature encoding")
	}

	headerList := parseSignedHeaderList(params["headers"])
	if len(headerList) == 0 {
		headerList = []string{"(request-target)"}
	}

	signedText, err := buildHoKSigningString(requestMethod, requestPath, requestHost, requestHeaders, headerList)
	if err != nil {
		return err
	}

	digest := hashSigningText(algorithm.Hash, signedText)

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if algorithm.KeyType != "rsa" {
			return unauthorized("invalid signature algorithm for RSA key")
		}
		if err := rsa.VerifyPKCS1v15(pub, algorithm.Hash, digest, sig); err != nil {
			return unauthorized("invalid HoK signature")
		}
	case *ecdsa.PublicKey:
		if algorithm.KeyType != "ecdsa" {
			return unauthorized("invalid signature algorithm for ECDSA key")
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return unauthorized("invalid HoK signature")
		}
	default:
		return unauthorized("unsupported HoK public key type")
	}

	return nil
}

type hoKAlgorithm struct {
	Hash    crypto.Hash
	KeyType string
}

func resolveHoKAlgorithm(raw string) (hoKAlgorithm, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "rsa-sha256"
	}

	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rsa-sha256":
		return hoKAlgorithm{Hash: crypto.SHA256, KeyType: "rsa"}, nil
	case "rsa-sha384":
		return hoKAlgorithm{Hash: crypto.SHA384, KeyType: "rsa"}, nil
	case "rsa-sha512":
		return hoKAlgorithm{Hash: crypto.SHA512, KeyType: "rsa"}, nil
	case "ecdsa-sha256":
		return hoKAlgorithm{Hash: crypto.SHA256, KeyType: "ecdsa"}, nil
	case "ecdsa-sha384":
		return hoKAlgorithm{Hash: crypto.SHA384, KeyType: "ecdsa"}, nil
	case "ecdsa-sha512":
		return hoKAlgorithm{Hash: crypto.SHA512, KeyType: "ecdsa"}, nil
	default:
		return hoKAlgorithm{}, fmt.Errorf("unsupported signature algorithm")
	}
}

func hashSigningText(h crypto.Hash, data string) []byte {
	sum := sha256.Sum256([]byte("fallback"))
	if !h.Available() {
		return sum[:] // no-op fallback, never used
	}

	var digest []byte
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(data))
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(data))
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(data))
		digest = sum[:]
	default:
		sum := sha256.Sum256([]byte(data))
		digest = sum[:]
	}
	return digest
}

func parseSignedHeaderList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := strings.Fields(raw)
	for i := range out {
		out[i] = strings.ToLower(strings.TrimSpace(out[i]))
	}
	return out
}

func decodeSignature(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty signature")
	}

	sig, err := base64.RawStdEncoding.DecodeString(raw)
	if err == nil {
		return sig, nil
	}

	sig, err = base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func buildHoKSigningString(requestMethod, requestPath, requestHost string, requestHeaders map[string]string, headerList []string) (string, error) {
	method := strings.TrimSpace(strings.ToLower(requestMethod))
	if method == "" {
		return "", unauthorized("missing request method")
	}

	path := strings.TrimSpace(requestPath)
	if path == "" {
		path = "/"
	}

	host := strings.TrimSpace(requestHost)

	lines := make([]string, 0, len(headerList))
	for _, rawHeader := range headerList {
		header := strings.ToLower(strings.TrimSpace(rawHeader))
		if header == "" {
			continue
		}

		switch header {
		case "(request-target)":
			lines = append(lines, "(request-target): "+method+" "+path)
		default:
			headerValue, found := getHeaderValueCaseInsensitive(requestHeaders, header)
			if !found || strings.TrimSpace(headerValue) == "" {
				if header == "host" {
					if host != "" {
						lines = append(lines, header+": "+host)
						continue
					}
				}
				return "", unauthorized(fmt.Sprintf("missing header for signature verification: %s", header))
			}
			lines = append(lines, header+": "+normalizeHeaderValue(headerValue))
		}
	}

	if len(lines) == 0 {
		return "", unauthorized("missing headers for signature verification")
	}

	return strings.Join(lines, "\n"), nil
}

func getHeaderValueCaseInsensitive(headers map[string]string, name string) (string, bool) {
	if headers == nil {
		return "", false
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func normalizeHeaderValue(value string) string {
	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

func parseSignatureHeader(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing Signature header")
	}

	parts := splitSignatureParameters(raw)
	if len(parts) == 0 {
		return nil, errors.New("invalid Signature header")
	}

	params := map[string]string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		separator := strings.IndexByte(part, '=')
		if separator <= 0 {
			return nil, errors.New("invalid Signature header")
		}

		key := strings.TrimSpace(part[:separator])
		value := strings.TrimSpace(part[separator+1:])
		if key == "" || value == "" {
			return nil, errors.New("invalid Signature header")
		}

		if strings.HasPrefix(value, "\"") {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return nil, errors.New("invalid Signature header quoting")
			}
			value = decoded
		}

		params[key] = value
	}

	if _, ok := params["signature"]; !ok {
		return nil, errors.New("missing signature parameter")
	}

	return params, nil
}

func splitSignatureParameters(raw string) []string {
	parts := []string{}
	start := 0
	inQuotes := false
	escaped := false

	for i, ch := range raw {
		if escaped {
			escaped = false
			continue
		}

		switch ch {
		case '\\':
			escaped = true
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}

	parts = append(parts, raw[start:])
	return parts
}
