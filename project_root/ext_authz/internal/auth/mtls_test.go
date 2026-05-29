package auth

import (
	"crypto/x509"
	"testing"
)

func TestExtractCertPEM_Success(t *testing.T) {
	xfcc := `Cert="-----BEGIN%20CERTIFICATE-----%0AMIICxjCCAa4CCQDTest%3D%3D%0A-----END%20CERTIFICATE-----%0A"`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if pem == "" {
		t.Error("expected PEM certificate, got empty string")
	}

	if !containsString(pem, "BEGIN CERTIFICATE") {
		t.Errorf("expected PEM to contain BEGIN CERTIFICATE, got %s", pem)
	}
}

func TestExtractCertPEM_WithMultipleFields(t *testing.T) {
	xfcc := `Hash=abc123;Cert="-----BEGIN%20CERTIFICATE-----%0AMIICxjCCAa4CCQDTest%3D%3D%0A-----END%20CERTIFICATE-----%0A";Subject="CN=test"`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if pem == "" {
		t.Error("expected PEM certificate, got empty string")
	}
}

func TestExtractCertPEM_MissingCertField(t *testing.T) {
	xfcc := `Hash=abc123;Subject="CN=test"`
	
	_, err := extractCertPEM(xfcc)
	if err == nil {
		t.Error("expected error for missing Cert field, got nil")
	}
}

func TestExtractCertPEM_EmptyCertValue(t *testing.T) {
	xfcc := `Cert=""`
	
	_, err := extractCertPEM(xfcc)
	if err == nil {
		t.Error("expected error for empty Cert value, got nil")
	}
}

func TestSha256Thumbprint(t *testing.T) {
	// Test with known input
	input := []byte("test certificate data")
	thumbprint := sha256Thumbprint(input)

	// Verify it's a hex string
	if len(thumbprint) != 64 {
		t.Errorf("expected thumbprint length 64, got %d", len(thumbprint))
	}

	// Verify it's lowercase hex
	for _, c := range thumbprint {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("expected lowercase hex character, got %c", c)
		}
	}
}

func TestSha256Thumbprint_Deterministic(t *testing.T) {
	input := []byte("test certificate data")
	
	thumbprint1 := sha256Thumbprint(input)
	thumbprint2 := sha256Thumbprint(input)

	if thumbprint1 != thumbprint2 {
		t.Error("expected deterministic thumbprint calculation")
	}
}

func TestSha256Thumbprint_DifferentInputs(t *testing.T) {
	input1 := []byte("certificate 1")
	input2 := []byte("certificate 2")

	thumbprint1 := sha256Thumbprint(input1)
	thumbprint2 := sha256Thumbprint(input2)

	if thumbprint1 == thumbprint2 {
		t.Error("expected different thumbprints for different inputs")
	}
}

func TestParseClientIdentityFromXFCC_MissingHeader(t *testing.T) {
	xfcc := ""
	
	_, err := ParseClientIdentityFromXFCC(xfcc)
	if err == nil {
		t.Error("expected error for missing XFCC header, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestParseClientIdentityFromXFCC_InvalidFormat(t *testing.T) {
	xfcc := "invalid-format"
	
	_, err := ParseClientIdentityFromXFCC(xfcc)
	if err == nil {
		t.Error("expected error for invalid XFCC format, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestExtractSAN_Empty(t *testing.T) {
	// Create a minimal certificate with no SANs
	cert := &x509.Certificate{
		DNSNames:       nil,
		IPAddresses:    nil,
		EmailAddresses: nil,
		URIs:           nil,
	}

	san := extractSAN(cert)
	if san != nil {
		t.Errorf("expected nil for empty SAN, got %v", san)
	}
}

func TestExtractSAN_DNSNames(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com", "www.example.com"},
	}

	san := extractSAN(cert)
	if len(san) != 2 {
		t.Errorf("expected 2 SAN entries, got %d", len(san))
	}

	if san[0] != "example.com" {
		t.Errorf("expected first SAN 'example.com', got '%s'", san[0])
	}

	if san[1] != "www.example.com" {
		t.Errorf("expected second SAN 'www.example.com', got '%s'", san[1])
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
