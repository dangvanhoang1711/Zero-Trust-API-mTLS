package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestParseClientIdentityFromXFCC_ValidChain(t *testing.T) {
	rootCert, rootKey := generateTestCA(t, "Zero-Trust Test Root CA", 1)
	leafCert, _ := generateTestClientCert(t, "zero-trust-test-client", rootCert, rootKey, 2)

	caBundlePath := createTempCertBundle(t, rootCert)
	t.Setenv("CLIENT_CA_BUNDLE", caBundlePath)

	xfcc := buildXFCCFromCertPEM(certificateToPEM(t, leafCert))
	identity, err := ParseClientIdentityFromXFCC(xfcc)
	if err != nil {
		t.Fatalf("expected chain validation to pass, got %v", err)
	}

	if identity == nil || identity.Subject == "" {
		t.Fatalf("expected identity with subject, got %#v", identity)
	}
}

func TestParseClientIdentityFromXFCC_InvalidChain(t *testing.T) {
	attackerCA, _ := generateTestCA(t, "Attacker CA", 101)
	rootCert, rootKey := generateTestCA(t, "Zero-Trust Root CA", 102)
	leafCert, _ := generateTestClientCert(t, "zero-trust-test-client", rootCert, rootKey, 3)

	caBundlePath := createTempCertBundle(t, attackerCA)
	t.Setenv("CLIENT_CA_BUNDLE", caBundlePath)

	xfcc := buildXFCCFromCertPEM(certificateToPEM(t, leafCert))
	_, err := ParseClientIdentityFromXFCC(xfcc)
	if err == nil {
		t.Fatal("expected chain validation to fail with mismatched trust bundle")
	}
}

func generateTestCA(t *testing.T, commonName string, serial int64) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return cert, key
}

func generateTestClientCert(t *testing.T, commonName string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, serial int64) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	return cert, key
}

func certificateToPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	buf := bytes.Buffer{}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("encode cert to PEM: %v", err)
	}
	return buf.String()
}

func createTempCertBundle(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	filePath := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(filePath, []byte(certificateToPEM(t, cert)), 0o644); err != nil {
		t.Fatalf("write ca bundle: %v", err)
	}
	return filePath
}

func buildXFCCFromCertPEM(certPEM string) string {
	return `Cert="` + url.QueryEscape(certPEM) + `"`
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
