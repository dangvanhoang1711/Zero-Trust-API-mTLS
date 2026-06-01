package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestValidateDPoPBinding_MissingHeader(t *testing.T) {
	err := ValidateDPoPBinding("dummy", "", "GET", "https://api.example.com/resource", 0, 0, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isUnauthorized(err) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestValidateDPoPBinding_ValidProof(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", 2*time.Minute, 0, "")
	if err != nil {
		t.Fatalf("expected valid proof, got error: %v", err)
	}
}

func TestValidateDPoPBinding_InvalidMethod(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "POST", "https://api.example.com/resource", 2*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for method mismatch")
	}
}

func TestValidateDPoPBinding_InvalidURI(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/other", 2*time.Minute, 0, "")
	if err == nil {
		t.Fatal("expected error for URI mismatch")
	}
}

func TestValidateDPoPBinding_ExpiredIAT(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", []time.Time{time.Now().Add(-10 * time.Minute)})

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", 1*time.Minute, 0, "")
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

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", 2*time.Minute, 0, requiredNonce)
	if err != nil {
		t.Fatalf("expected valid proof with nonce, got error: %v", err)
	}
}

func TestValidateDPoPBinding_NonceMissing(t *testing.T) {
	proof, expectedJWKThumbprint := newTestDPoPProof(t, "GET", "https://api.example.com/resource", nil)

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", 2*time.Minute, 0, "required-nonce")
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

	err := ValidateDPoPBinding(expectedJWKThumbprint, proof, "GET", "https://api.example.com/resource", 2*time.Minute, 0, "required-nonce")
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func newTestDPoPProof(t *testing.T, method, uri string, iatOverrides []time.Time, extraClaims ...map[string]any) (string, string) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	rawProof, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	return rawProof, jwkThumbprint
}
