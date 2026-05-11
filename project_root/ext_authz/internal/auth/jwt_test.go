package auth

import (
	"testing"
)

func TestExtractBearerToken_Success(t *testing.T) {
	header := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	token, err := extractBearerToken(header)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expected := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	if token != expected {
		t.Errorf("expected token %s, got %s", expected, token)
	}
}

func TestExtractBearerToken_CaseInsensitive(t *testing.T) {
	header := "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	token, err := extractBearerToken(header)
	if err != nil {
		t.Errorf("expected no error for lowercase bearer, got %v", err)
	}

	if token == "" {
		t.Error("expected token, got empty string")
	}
}

func TestExtractBearerToken_WithWhitespace(t *testing.T) {
	header := "  Bearer   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature  "
	token, err := extractBearerToken(header)
	if err != nil {
		t.Errorf("expected no error with whitespace, got %v", err)
	}

	expected := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	if token != expected {
		t.Errorf("expected token %s, got %s", expected, token)
	}
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	header := ""
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for missing header, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestExtractBearerToken_MissingBearer(t *testing.T) {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for missing Bearer prefix, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestExtractBearerToken_EmptyToken(t *testing.T) {
	header := "Bearer "
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for empty token, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestExtractBearerToken_WrongScheme(t *testing.T) {
	header := "Basic dXNlcjpwYXNz"
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for wrong scheme, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestExtractCNFThumbprint_Success(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"x5t#S256": "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba",
		},
	}

	thumbprint, err := extractCNFThumbprint(claims)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expected := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	if thumbprint != expected {
		t.Errorf("expected thumbprint %s, got %s", expected, thumbprint)
	}
}

func TestExtractCNFThumbprint_MissingCNF(t *testing.T) {
	claims := map[string]any{
		"sub": "test-user",
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for missing cnf claim, got nil")
	}
}

func TestExtractCNFThumbprint_InvalidCNFType(t *testing.T) {
	claims := map[string]any{
		"cnf": "invalid-string",
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for invalid cnf type, got nil")
	}
}

func TestExtractCNFThumbprint_MissingX5T(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"other": "value",
		},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for missing x5t#S256, got nil")
	}
}

func TestExtractCNFThumbprint_EmptyX5T(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"x5t#S256": "",
		},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for empty x5t#S256, got nil")
	}
}

func TestStringClaim_Success(t *testing.T) {
	claims := map[string]any{
		"sub": "test-user",
		"iss": "http://keycloak:8080/realms/zero-trust",
	}

	sub := stringClaim(claims, "sub")
	if sub != "test-user" {
		t.Errorf("expected sub 'test-user', got '%s'", sub)
	}

	iss := stringClaim(claims, "iss")
	if iss != "http://keycloak:8080/realms/zero-trust" {
		t.Errorf("expected iss 'http://keycloak:8080/realms/zero-trust', got '%s'", iss)
	}
}

func TestStringClaim_Missing(t *testing.T) {
	claims := map[string]any{
		"sub": "test-user",
	}

	result := stringClaim(claims, "missing")
	if result != "" {
		t.Errorf("expected empty string for missing claim, got '%s'", result)
	}
}

func TestStringClaim_WrongType(t *testing.T) {
	claims := map[string]any{
		"sub": 12345,
	}

	result := stringClaim(claims, "sub")
	if result != "" {
		t.Errorf("expected empty string for wrong type, got '%s'", result)
	}
}

func TestAudienceClaim_String(t *testing.T) {
	aud := audienceClaim("api-gateway")
	if len(aud) != 1 {
		t.Errorf("expected 1 audience, got %d", len(aud))
	}
	if aud[0] != "api-gateway" {
		t.Errorf("expected audience 'api-gateway', got '%s'", aud[0])
	}
}

func TestAudienceClaim_Array(t *testing.T) {
	aud := audienceClaim([]any{"api-gateway", "other-service"})
	if len(aud) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(aud))
	}
	if aud[0] != "api-gateway" {
		t.Errorf("expected first audience 'api-gateway', got '%s'", aud[0])
	}
	if aud[1] != "other-service" {
		t.Errorf("expected second audience 'other-service', got '%s'", aud[1])
	}
}

func TestAudienceClaim_EmptyString(t *testing.T) {
	aud := audienceClaim("")
	if aud != nil {
		t.Errorf("expected nil for empty string, got %v", aud)
	}
}

func TestAudienceClaim_EmptyArray(t *testing.T) {
	aud := audienceClaim([]any{})
	if len(aud) != 0 {
		t.Errorf("expected empty array, got %v", aud)
	}
}

func TestAudienceClaim_InvalidType(t *testing.T) {
	aud := audienceClaim(12345)
	if aud != nil {
		t.Errorf("expected nil for invalid type, got %v", aud)
	}
}

func TestBuildJWKSURL_Success(t *testing.T) {
	baseURL := "http://keycloak:8080/realms/zero-trust"
	jwksURL, err := BuildJWKSURL(baseURL)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expected := "http://keycloak:8080/realms/zero-trust/.well-known/jwks.json"
	if jwksURL != expected {
		t.Errorf("expected JWKS URL %s, got %s", expected, jwksURL)
	}
}

func TestBuildJWKSURL_WithTrailingSlash(t *testing.T) {
	baseURL := "http://keycloak:8080/realms/zero-trust/"
	jwksURL, err := BuildJWKSURL(baseURL)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expected := "http://keycloak:8080/realms/zero-trust/.well-known/jwks.json"
	if jwksURL != expected {
		t.Errorf("expected JWKS URL %s, got %s", expected, jwksURL)
	}
}

func TestBuildJWKSURL_Empty(t *testing.T) {
	baseURL := ""
	_, err := BuildJWKSURL(baseURL)
	if err == nil {
		t.Error("expected error for empty base URL, got nil")
	}
}

// Helper functions for error type checking
func isUnauthorized(err error) bool {
	authErr, ok := err.(*AuthError)
	return ok && authErr.HTTPStatus == 401
}

func isForbidden(err error) bool {
	authErr, ok := err.(*AuthError)
	return ok && authErr.HTTPStatus == 403
}
