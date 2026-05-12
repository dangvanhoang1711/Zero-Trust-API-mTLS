package auth

import (
	"testing"
)

// Additional edge case tests for JWT verification

func TestExtractBearerToken_InvalidFormat_NoSpace(t *testing.T) {
	header := "BearerTOKEN"
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for bearer token without space, got nil")
	}
}

func TestExtractBearerToken_InvalidFormat_OnlyBearer(t *testing.T) {
	header := "Bearer"
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for bearer without token, got nil")
	}
}

func TestExtractBearerToken_InvalidFormat_MultipleSpaces(t *testing.T) {
	header := "Bearer    "
	_, err := extractBearerToken(header)
	if err == nil {
		t.Error("expected error for bearer with only spaces, got nil")
	}
}

func TestExtractCNFThumbprint_InvalidCNFType_String(t *testing.T) {
	claims := map[string]any{
		"cnf": "invalid-string-not-map",
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for cnf as string, got nil")
	}
}

func TestExtractCNFThumbprint_InvalidCNFType_Array(t *testing.T) {
	claims := map[string]any{
		"cnf": []string{"invalid", "array"},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for cnf as array, got nil")
	}
}

func TestExtractCNFThumbprint_MissingX5TField(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"jkt": "some-other-field",
		},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for missing x5t#S256, got nil")
	}
}

func TestExtractCNFThumbprint_X5TNotString(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"x5t#S256": 12345,
		},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for x5t#S256 as number, got nil")
	}
}

func TestExtractCNFThumbprint_X5TWhitespaceOnly(t *testing.T) {
	claims := map[string]any{
		"cnf": map[string]any{
			"x5t#S256": "   ",
		},
	}

	_, err := extractCNFThumbprint(claims)
	if err == nil {
		t.Error("expected error for x5t#S256 with only whitespace, got nil")
	}
}

func TestStringClaim_NonStringType(t *testing.T) {
	claims := map[string]any{
		"sub": 12345,
		"iss": true,
		"aud": []string{"test"},
	}

	sub := stringClaim(claims, "sub")
	if sub != "" {
		t.Errorf("expected empty string for numeric sub, got '%s'", sub)
	}

	iss := stringClaim(claims, "iss")
	if iss != "" {
		t.Errorf("expected empty string for boolean iss, got '%s'", iss)
	}

	aud := stringClaim(claims, "aud")
	if aud != "" {
		t.Errorf("expected empty string for array aud, got '%s'", aud)
	}
}

func TestAudienceClaim_ArrayWithEmptyStrings(t *testing.T) {
	aud := audienceClaim([]any{"valid", "", "  ", "another"})
	
	// Should filter out empty and whitespace-only strings
	if len(aud) != 2 {
		t.Errorf("expected 2 valid audiences, got %d", len(aud))
	}
}

func TestAudienceClaim_ArrayWithNonStrings(t *testing.T) {
	aud := audienceClaim([]any{"valid", 123, true, "another"})
	
	// Should filter out non-string values
	if len(aud) != 2 {
		t.Errorf("expected 2 string audiences, got %d", len(aud))
	}
}

func TestAudienceClaim_Nil(t *testing.T) {
	aud := audienceClaim(nil)
	if aud != nil {
		t.Errorf("expected nil for nil input, got %v", aud)
	}
}

func TestBuildJWKSURL_WithMultipleSlashes(t *testing.T) {
	baseURL := "http://keycloak:8080/realms/zero-trust///"
	jwksURL, err := BuildJWKSURL(baseURL)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expected := "http://keycloak:8080/realms/zero-trust/.well-known/jwks.json"
	if jwksURL != expected {
		t.Errorf("expected JWKS URL %s, got %s", expected, jwksURL)
	}
}

func TestBuildJWKSURL_WhitespaceOnly(t *testing.T) {
	baseURL := "   "
	_, err := BuildJWKSURL(baseURL)
	if err == nil {
		t.Error("expected error for whitespace-only base URL, got nil")
	}
}

// Benchmark tests
func BenchmarkExtractBearerToken(b *testing.B) {
	header := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractBearerToken(header)
	}
}

func BenchmarkExtractCNFThumbprint(b *testing.B) {
	claims := map[string]any{
		"cnf": map[string]any{
			"x5t#S256": "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba",
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractCNFThumbprint(claims)
	}
}

func BenchmarkStringClaim(b *testing.B) {
	claims := map[string]any{
		"sub": "test-user",
		"iss": "http://keycloak:8080/realms/zero-trust",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stringClaim(claims, "sub")
	}
}

func BenchmarkAudienceClaim_String(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = audienceClaim("api-gateway")
	}
}

func BenchmarkAudienceClaim_Array(b *testing.B) {
	aud := []any{"api-gateway", "other-service", "third-service"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = audienceClaim(aud)
	}
}
