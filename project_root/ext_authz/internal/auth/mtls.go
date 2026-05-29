package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

const xfccHeader = "x-forwarded-client-cert"

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

	identity := &ClientIdentity{
		Subject:    leaf.Subject.String(),
		SAN:        extractSAN(leaf),
		Thumbprint: sha256Thumbprint(leaf.Raw),
	}

	return identity, nil
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
