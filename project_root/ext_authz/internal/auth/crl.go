package auth

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CRLChecker struct {
	url       string
	token     string
	client    *http.Client
	mu        sync.Mutex
	cachedCRL *x509.RevocationList
	fetchedAt time.Time
	ttl       time.Duration
}

func NewCRLChecker(crlURL string, ttl time.Duration) *CRLChecker {
	if crlURL == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &CRLChecker{
		url:    crlURL,
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    ttl,
	}
}

func NewCRLCheckerWithToken(crlURL string, token string, ttl time.Duration) *CRLChecker {
	c := NewCRLChecker(crlURL, ttl)
	if c != nil {
		c.token = strings.TrimSpace(token)
	}
	return c
}

func (c *CRLChecker) IsRevoked(serialHex string) (bool, error) {
	if c == nil || c.url == "" {
		return false, nil
	}

	serialHex = strings.ToLower(strings.TrimSpace(serialHex))
	if serialHex == "" {
		return false, nil
	}

	crl, err := c.getCRL()
	if err != nil {
		return false, fmt.Errorf("crl fetch failed: %w", err)
	}

	if len(serialHex) > 1 && serialHex[:1] == "0" {
		serialHex = serialHex[1:]
	}

	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber == nil {
			continue
		}
		entrySerial := strings.ToLower(entry.SerialNumber.Text(16))
		if len(entrySerial) > 1 && entrySerial[:1] == "0" {
			entrySerial = entrySerial[1:]
		}
		if entrySerial == serialHex {
			return true, nil
		}
	}

	return false, nil
}

func (c *CRLChecker) getCRL() (*x509.RevocationList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedCRL != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.cachedCRL, nil
	}

	crl, err := c.fetchCRL()
	if err != nil {
		if c.cachedCRL != nil {
			return c.cachedCRL, nil
		}
		return nil, err
	}

	c.cachedCRL = crl
	c.fetchedAt = time.Now()
	return crl, nil
}

func (c *CRLChecker) fetchCRL() (*x509.RevocationList, error) {
	req, err := http.NewRequest("GET", c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	if strings.TrimSpace(c.token) != "" {
		req.Header.Set("X-Vault-Token", strings.TrimSpace(c.token))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("parse crl: %w", err)
	}

	return crl, nil
}
