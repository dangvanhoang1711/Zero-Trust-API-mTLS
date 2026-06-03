package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestValidateDPoPBinding_MissingHeader(t *testing.T) {
	err := ValidateDPoPBinding("dummy", "", "GET", "https://api.example.com/resource", "", 0, 0, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isUnauthorized(err) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestValidateDPoPBinding_ValidProof(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", "",
		2*time.Minute, 0, "")
	if err != nil {
		t.Fatalf("expected valid proof, got error: %v", err)
	}
}

func TestValidateDPoPBinding_ValidProofWithATH(t *testing.T) {
	method := "GET"
	uri := "https://api.example.com/resource"
	accessToken := "some-access-token-value"
	proof, expectedJWKThumbprint := newTestDPoPProofWithATH(t, method, uri, accessToken, nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, method, uri, accessToken,
		2*time.Minute, 0, "")
	if err != nil {
		t.Fatalf("expected valid proof with ath, got error: %v", err)
	}
}

func TestValidateDPoPBinding_ATHMismatch(t *testing.T) {
	method := "GET"
	uri := "https://api.example.com/resource"
	accessToken := "some-access-token-value"
	proof, expectedJWKThumbprint := newTestDPoPProofWithATH(t, method, uri, accessToken, nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, method, uri, "different-access-token",
		2*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for ath mismatch, got nil")
	}
}

func TestValidateDPoPBinding_InvalidMethod(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "POST", "https://api.example.com/resource", "",
		2*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for method mismatch")
	}
}

func TestValidateDPoPBinding_InvalidURI(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/other", "",
		2*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for URI mismatch")
	}
}

func TestValidateDPoPBinding_ExpiredIAT(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", []time.Time{time.Now().Add(-10 * time.Minute)})

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", "",
		1*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for expired iat")
	}
}

func TestValidateDPoPBinding_ValidNonce(t *testing.T) {
	requiredNonce := "nonce-123"
	proof, expectedJWKThumbprint := newTestDPoPProof(
		t,
		"GET",
		"https://api.example.com/resource",
		nil,
		map[string]any{
			"nonce": requiredNonce,
		},
	)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", "",
		2*time.Minute, 0, requiredNonce)
	if err != nil {
		t.Fatalf("expected valid proof with nonce, got error: %v", err)
	}
}

func TestValidateDPoPBinding_NonceMissing(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", "",
		2*time.Minute, 0, "required-nonce")
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
}

func TestValidateDPoPBinding_NonceMismatch(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(
		t,
		"GET",
		"https://api.example.com/resource",
		nil,
		map[string]any{
			"nonce": "wrong-nonce",
		},
	)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", "",
		2*time.Minute, 0, "required-nonce")
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func newTestDPoPProofWithATH(t *testing.T, method, uri, accessToken string, iatOverrides []time.Time) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	jwkThumbprint, err := thumbprintJWK(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	issuedAt := time.Now()
	if len(iatOverrides) > 0 {
		issuedAt = iatOverrides[0]
	}

	claims := jwt.MapClaims{
		"htu": uri,
		"htm": method,
		"jti": "test-jti-ath-1",
		"iat": issuedAt.Unix(),
		"ath": ath,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	rawProof, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	return rawProof, jwkThumbprint
}

func newTestDPoPProof(t *testing.T, method, uri string, iatOverrides []time.Time, extraClaims ...map[string]any) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	jwkThumbprint, err := thumbprintJWK(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	issuedAt := time.Now()
	if len(iatOverrides) > 0 {
		issuedAt = iatOverrides[0]
	}

	claims := jwt.MapClaims{
		"htu": uri,
		"htm": method,
		"jti": "test-jti-1",
		"iat": issuedAt.Unix(),
	}

	for _, claimSet := range extraClaims {
		for key, value := range claimSet {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	rawProof, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	return rawProof, jwkThumbprint
}
