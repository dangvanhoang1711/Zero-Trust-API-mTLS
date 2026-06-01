package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestValidateHoKBinding_Success(t *testing.T) {
	key, jwk := newTestRSACNFJWK(t)
	method := "POST"
	path := "/api/v1/resource"
	host := "api.example.com"
	headers := map[string]string{
		"host": host,
		"date": "Tue, 20 Oct 2026 12:00:00 GMT",
	}
	signatureHeader := newHoKSignatureHeader(t, key, method, path, host, headers, []string{"(request-target)", "host", "date"}, "rsa-sha256")

	err := ValidateHoKBinding(jwk, method, path, host, headers, signatureHeader)
	if err != nil {
		t.Fatalf("expected valid HoK binding, got %v", err)
	}
}

func TestValidateHoKBinding_MissingSignature(t *testing.T) {
	key, jwk := newTestRSACNFJWK(t)
	method := "GET"
	path := "/"
	host := "api.example.com"
	headers := map[string]string{
		"host": host,
		"date": "Tue, 20 Oct 2026 12:00:00 GMT",
	}
	_ = key

	err := ValidateHoKBinding(jwk, method, path, host, headers, "keyId=\"test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\"")
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestValidateHoKBinding_BadSignature(t *testing.T) {
	key, jwk := newTestRSACNFJWK(t)
	method := "GET"
	path := "/api/v1/resource"
	host := "api.example.com"
	headers := map[string]string{
		"host": host,
		"date": "Tue, 20 Oct 2026 12:00:00 GMT",
	}
	signatureHeader := newHoKSignatureHeader(t, key, method, path, host, headers, []string{"(request-target)", "host", "date"}, "rsa-sha256")
	badSignatureHeader := strings.Replace(signatureHeader, "r", "s", 1)

	err := ValidateHoKBinding(jwk, method, path, host, headers, badSignatureHeader)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestValidateHoKBinding_MissingHeader(t *testing.T) {
	key, jwk := newTestRSACNFJWK(t)
	method := "GET"
	path := "/api/v1/resource"
	host := "api.example.com"
	headers := map[string]string{
		"host": host,
	}
	signatureHeader := newHoKSignatureHeader(t, key, method, path, host, headers, []string{"(request-target)", "host", "date"}, "rsa-sha256")

	err := ValidateHoKBinding(jwk, method, path, host, headers, signatureHeader)
	if err == nil {
		t.Fatal("expected error for missing signed header")
	}
}

func TestParseSignatureHeader_WithQuotesAndCommas(t *testing.T) {
	raw := `keyId="test",algorithm="rsa-sha256",headers="(request-target) host date",signature="abc,def"`
	params, err := parseSignatureHeader(raw)
	if err != nil {
		t.Fatalf("expected parsed signature header, got %v", err)
	}
	if params["signature"] != "abc,def" {
		t.Fatalf("unexpected signature value: %q", params["signature"])
	}
}

func newTestRSACNFJWK(t *testing.T) (*rsa.PrivateKey, map[string]any) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	return key, jwk
}

func newHoKSignatureHeader(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	method, path, host string,
	headers map[string]string,
	signedHeaders []string,
	algorithm string,
) string {
	t.Helper()

	canonicalized := buildHoKSigningInput(method, path, host, headers, signedHeaders)
	hashAlg := resolveHoKHash(algorithm)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashAlg, hashSigningInput(hashAlg, canonicalized))
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	return fmt.Sprintf(
		`keyId="test-key",algorithm="%s",headers="%s",signature="%s"`,
		algorithm,
		strings.Join(signedHeaders, " "),
		base64.StdEncoding.EncodeToString(signature),
	)
}

func resolveHoKHash(algorithm string) crypto.Hash {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "rsa-sha256", "ecdsa-sha256":
		return crypto.SHA256
	case "rsa-sha384", "ecdsa-sha384":
		return crypto.SHA384
	case "rsa-sha512", "ecdsa-sha512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func hashSigningInput(hashAlg crypto.Hash, raw string) []byte {
	switch hashAlg {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(raw))
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(raw))
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(raw))
		return sum[:]
	default:
		sum := sha256.Sum256([]byte(raw))
		return sum[:]
	}
}

func buildHoKSigningInput(method, path, host string, headers map[string]string, signedHeaders []string) string {
	lines := make([]string, 0, len(signedHeaders))
	for _, header := range signedHeaders {
		switch strings.ToLower(header) {
		case "(request-target)":
			lines = append(lines, "(request-target): "+strings.ToLower(strings.TrimSpace(method))+" "+strings.TrimSpace(path))
		case "host":
			lines = append(lines, "host: "+host)
		default:
			lines = append(lines, strings.ToLower(header)+": "+normalizeHeaderValue(headers[header]))
		}
	}
	return strings.Join(lines, "\n")
}
