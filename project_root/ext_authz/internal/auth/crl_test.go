package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCRLChecker_NilChecker(t *testing.T) {
	var c *CRLChecker
	revoked, err := c.IsRevoked("abcd")
	if err != nil {
		t.Fatalf("expected no error for nil checker, got: %v", err)
	}
	if revoked {
		t.Fatal("expected not revoked for nil checker")
	}
}

func TestCRLChecker_EmptySerial(t *testing.T) {
	c := NewCRLChecker("http://example.com/crl", time.Minute)
	revoked, err := c.IsRevoked("")
	if err != nil {
		t.Fatalf("expected no error for empty serial, got: %v", err)
	}
	if revoked {
		t.Fatal("expected not revoked for empty serial")
	}
}

func TestCRLChecker_SerialNormalization(t *testing.T) {
	serial := big.NewInt(255)
	serialHex := serial.Text(16)

	entry := pkix.RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	}

	revokedList := &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{entry},
	}

	c := &CRLChecker{url: "http://test", ttl: time.Minute}
	c.cachedCRL = revokedList
	c.fetchedAt = time.Now()

	revoked, err := c.IsRevoked(serialHex)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !revoked {
		t.Fatal("expected serial to be revoked")
	}
}

func TestCRLChecker_NotRevoked(t *testing.T) {
	revokedSerial := big.NewInt(100)
	checkSerial := big.NewInt(200)

	entry := pkix.RevokedCertificate{
		SerialNumber:   revokedSerial,
		RevocationTime: time.Now(),
	}

	revokedList := &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{entry},
	}

	c := &CRLChecker{url: "http://test", ttl: time.Minute}
	c.cachedCRL = revokedList
	c.fetchedAt = time.Now()

	revoked, err := c.IsRevoked(checkSerial.Text(16))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if revoked {
		t.Fatal("expected serial not to be revoked")
	}
}

func TestCRLChecker_GenerateRevokedCRL(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	caCert, err := generateSelfSignedCACert(caKey)
	if err != nil {
		t.Fatalf("generate ca cert: %v", err)
	}

	serial := big.NewInt(42)

	entry := pkix.RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	}

	template := &x509.RevocationList{
		Number:             big.NewInt(1),
		RevokedCertificates: []pkix.RevokedCertificate{entry},
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		t.Fatalf("create crl: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}

	c := &CRLChecker{url: "http://test", ttl: time.Minute}
	c.cachedCRL = crl
	c.fetchedAt = time.Now()

	revoked, err := c.IsRevoked("2a")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !revoked {
		t.Fatal("expected serial 42 (0x2a) to be revoked")
	}
}

func generateSelfSignedCACert(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}
