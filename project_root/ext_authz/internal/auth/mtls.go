package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"
)

const xfccHeader = "x-forwarded-client-cert"
const clientCAPathEnv = "CLIENT_CA_BUNDLE"

type ClientIdentity struct {
	Subject    string
	SAN        []string
	Thumbprint string
}

func ParseClientIdentityFromXFCC(rawXFCC string) (*ClientIdentity, error) {
	if strings.TrimSpace(rawXFCC) == "" {
		return nil, unauthorized("missing x-forwarded-client-cert")
	}

	certPEM, err := extractCertPEM(rawXFCC)
	if err != nil {
		return nil, unauthorized("invalid x-forwarded-client-cert")
	}

	leaf, err := parseLeafCertificate(certPEM)
	if err != nil {
		return nil, unauthorized("unable to parse client certificate")
	}

	trustBundlePath := strings.TrimSpace(os.Getenv(clientCAPathEnv))
	if trustBundlePath != "" {
		if err := validateClientCertChain(leaf, rawXFCC, trustBundlePath); err != nil {
			return nil, unauthorized("unable to validate client certificate chain")
		}
	}

	identity := &ClientIdentity{
		Subject:    leaf.Subject.String(),
		SAN:        extractSAN(leaf),
		Thumbprint: sha256Thumbprint(leaf.Raw),
	}

	return identity, nil
}

func validateClientCertChain(leaf *x509.Certificate, rawXFCC, trustBundlePath string) error {
	rootPool, err := loadCertPool(trustBundlePath)
	if err != nil {
		return err
	}

	intermediatePool, err := parseIntermediatePool(rawXFCC)
	if err != nil {
		return err
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:   rootPool,
		Intermediates: intermediatePool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		CurrentTime: time.Now().UTC(),
	})

	return err
}

func loadCertPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if systemPool, err := x509.SystemCertPool(); err == nil && systemPool != nil {
		pool = systemPool
	}

	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("invalid certificate bundle")
	}

	return pool, nil
}

func parseIntermediatePool(rawXFCC string) (*x509.CertPool, error) {
	chainPEM, err := extractCertChainPEM(rawXFCC)
	if err != nil {
		return nil, err
	}
	if len(chainPEM) == 0 {
		return x509.NewCertPool(), nil
	}

	pool := x509.NewCertPool()
	for _, pemValue := range chainPEM {
		if strings.TrimSpace(pemValue) == "" {
			continue
		}
		pool.AppendCertsFromPEM([]byte(pemValue))
	}
	return pool, nil
}

func extractCertChainPEM(rawXFCC string) ([]string, error) {
	segments := strings.Split(rawXFCC, ";")
	var out []string
	for _, segment := range segments {
		part := strings.TrimSpace(segment)
		if !strings.HasPrefix(part, "Chain=") {
			continue
		}

		value := strings.TrimPrefix(part, "Chain=")
		value = strings.Trim(value, "\"")
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return nil, err
		}
		if decoded != "" {
			out = append(out, decoded)
		}
	}

	return out, nil
}

func extractCertPEM(rawXFCC string) (string, error) {
	segments := strings.Split(rawXFCC, ";")
	for _, segment := range segments {
		part := strings.TrimSpace(segment)
		if !strings.HasPrefix(part, "Cert=") {
			continue
		}

		value := strings.TrimPrefix(part, "Cert=")
		value = strings.Trim(value, "\"")
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return "", err
		}
		if decoded == "" {
			return "", errors.New("empty cert value")
		}
		return decoded, nil
	}

	return "", errors.New("Cert field not found")
}

func parseLeafCertificate(certPEM string) (*x509.Certificate, error) {
	decoded, err := pemToDER(certPEM)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func extractSAN(cert *x509.Certificate) []string {
	total := len(cert.DNSNames) + len(cert.URIs) + len(cert.IPAddresses) + len(cert.EmailAddresses)
	if total == 0 {
		return nil
	}

	out := make([]string, 0, total)
	for _, dns := range cert.DNSNames {
		out = append(out, dns)
	}
	for _, uri := range cert.URIs {
		out = append(out, uri.String())
	}
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		out = append(out, email)
	}

	return out
}

func sha256Thumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	buf := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(buf, sum[:])
	return string(buf)
}
