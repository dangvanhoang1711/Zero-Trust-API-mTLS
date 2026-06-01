package auth

import (
	"crypto/x509"
	"net"
	"net/url"
	"testing"
)

// Enhanced edge case tests for mTLS certificate handling

func TestExtractCertPEM_URLEncodedSpecialChars(t *testing.T) {
	xfcc := `Cert="-----BEGIN%20CERTIFICATE-----%0A%2B%2F%3D%0A-----END%20CERTIFICATE-----%0A"`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error for URL-encoded special chars, got %v", err)
	}

	if pem == "" {
		t.Error("expected PEM certificate, got empty string")
	}
}

func TestExtractCertPEM_MultipleSegments(t *testing.T) {
	xfcc := `Hash=abc;Subject="CN=test";Cert="-----BEGIN%20CERTIFICATE-----%0Atest%0A-----END%20CERTIFICATE-----%0A";Chain="chain"`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if !containsString(pem, "BEGIN CERTIFICATE") {
		t.Error("expected valid PEM certificate")
	}
}

func TestExtractCertPEM_CertFieldFirst(t *testing.T) {
	xfcc := `Cert="-----BEGIN%20CERTIFICATE-----%0Atest%0A-----END%20CERTIFICATE-----%0A";Hash=abc;Subject="CN=test"`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if pem == "" {
		t.Error("expected PEM certificate, got empty string")
	}
}

func TestExtractCertPEM_NoQuotes(t *testing.T) {
	xfcc := `Cert=-----BEGIN%20CERTIFICATE-----%0Atest%0A-----END%20CERTIFICATE-----%0A`
	
	pem, err := extractCertPEM(xfcc)
	if err != nil {
		t.Errorf("expected no error for unquoted cert, got %v", err)
	}

	if pem == "" {
		t.Error("expected PEM certificate, got empty string")
	}
}

func TestSha256Thumbprint_EmptyInput(t *testing.T) {
	input := []byte{}
	thumbprint := sha256Thumbprint(input)

	// SHA-256 of empty input should still produce 64-char hex string
	if len(thumbprint) != 64 {
		t.Errorf("expected thumbprint length 64, got %d", len(thumbprint))
	}
}

func TestSha256Thumbprint_LargeInput(t *testing.T) {
	// Simulate large certificate (4KB)
	input := make([]byte, 4096)
	for i := range input {
		input[i] = byte(i % 256)
	}

	thumbprint := sha256Thumbprint(input)

	if len(thumbprint) != 64 {
		t.Errorf("expected thumbprint length 64, got %d", len(thumbprint))
	}
}

func TestExtractSAN_DNSAndIP(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
	}

	san := extractSAN(cert)
	if len(san) != 2 {
		t.Errorf("expected 2 SAN entries, got %d", len(san))
	}
}

func TestExtractSAN_AllTypes(t *testing.T) {
	testURL, _ := url.Parse("https://example.com")
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"test@example.com"},
		URIs:           []*url.URL{testURL},
	}

	san := extractSAN(cert)
	if len(san) != 4 {
		t.Errorf("expected 4 SAN entries, got %d", len(san))
	}
}

func TestExtractSAN_DuplicateEntries(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com", "example.com", "test.com"},
	}

	san := extractSAN(cert)
	// Should include duplicates (no deduplication)
	if len(san) != 3 {
		t.Errorf("expected 3 SAN entries, got %d", len(san))
	}
}

func TestParseClientIdentityFromXFCC_WhitespaceOnly(t *testing.T) {
	xfcc := "   \t\n   "
	
	_, err := ParseClientIdentityFromXFCC(xfcc)
	if err == nil {
		t.Error("expected error for whitespace-only XFCC, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

// Benchmark tests
func BenchmarkExtractCertPEM(b *testing.B) {
	xfcc := `Cert="-----BEGIN%20CERTIFICATE-----%0AMIICxjCCAa4CCQDTest%3D%3D%0A-----END%20CERTIFICATE-----%0A"`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractCertPEM(xfcc)
	}
}

func BenchmarkSha256Thumbprint(b *testing.B) {
	input := []byte("test certificate data for benchmarking")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha256Thumbprint(input)
	}
}

func BenchmarkExtractSAN(b *testing.B) {
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"test@example.com"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractSAN(cert)
	}
}
