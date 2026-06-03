package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultJWKSHTTPTimeout = 3 * time.Second
	defaultJWKSTTL         = 5 * time.Minute
	minimumJWKSTTL         = 15 * time.Second
)

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

type JWKSCache struct {
	url         string
	issuer      string
	httpClient  *http.Client
	fallbackTTL time.Duration

	mu            sync.RWMutex
	keysByKID     map[string]crypto.PublicKey
	nextRefreshAt time.Time
	lastErr       error
}

func NewJWKSCache(url string, fallbackTTL time.Duration) *JWKSCache {
	if fallbackTTL <= 0 {
		fallbackTTL = defaultJWKSTTL
	}

	return &JWKSCache{
		url:         strings.TrimSpace(url),
		httpClient:  &http.Client{Timeout: defaultJWKSHTTPTimeout},
		fallbackTTL: fallbackTTL,
		keysByKID:   make(map[string]crypto.PublicKey),
	}
}

func (c *JWKSCache) SetIssuerForDiscovery(issuer string) {
	c.mu.Lock()
	c.issuer = strings.TrimSpace(issuer)
	c.mu.Unlock()
}

func (c *JWKSCache) Start(ctx context.Context) {
	go c.refreshLoop(ctx)
}

func (c *JWKSCache) Lookup(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	key := c.keysByKID[kid]
	err := c.lastErr
	c.mu.RUnlock()

	if key != nil {
		return key, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultJWKSHTTPTimeout)
	defer cancel()
	c.refreshOnce(ctx)

	c.mu.RLock()
	key = c.keysByKID[kid]
	err = c.lastErr
	c.mu.RUnlock()

	if key != nil {
		return key, nil
	}

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("jwks key not found for kid=%q", kid)
}

func (c *JWKSCache) refreshLoop(ctx context.Context) {
	c.refreshOnce(ctx)

	for {
		sleepFor := c.timeUntilRefresh()
		timer := time.NewTimer(sleepFor)

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
			c.refreshOnce(ctx)
		}
	}
}

func (c *JWKSCache) timeUntilRefresh() time.Duration {
	c.mu.RLock()
	next := c.nextRefreshAt
	c.mu.RUnlock()

	if next.IsZero() {
		return minimumJWKSTTL
	}

	until := time.Until(next)
	if until < minimumJWKSTTL {
		return minimumJWKSTTL
	}

	return until
}

func (c *JWKSCache) refreshOnce(ctx context.Context) {
	url := c.currentJWKSURL()
	if url == "" {
		discovered, err := c.discoverJWKSURL(ctx)
		if err != nil {
			c.setError(err)
			return
		}
		url = discovered
		c.setJWKSURL(discovered)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.setError(err)
		return
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.setError(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.setError(fmt.Errorf("jwks endpoint returned %d", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.setError(err)
		return
	}

	parsed, err := parseJWKS(body)
	if err != nil {
		c.setError(err)
		return
	}

	ttl := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"), c.fallbackTTL)

	c.mu.Lock()
	c.keysByKID = parsed
	c.lastErr = nil
	c.nextRefreshAt = time.Now().Add(ttl)
	c.mu.Unlock()
}

func (c *JWKSCache) currentJWKSURL() string {
	c.mu.RLock()
	url := c.url
	c.mu.RUnlock()
	return url
}

func (c *JWKSCache) setJWKSURL(url string) {
	c.mu.Lock()
	c.url = strings.TrimSpace(url)
	c.mu.Unlock()
}

func (c *JWKSCache) discoverJWKSURL(ctx context.Context) (string, error) {
	c.mu.RLock()
	issuer := c.issuer
	c.mu.RUnlock()

	if issuer == "" {
		return "", errors.New("missing JWKS_URL and JWT issuer discovery source")
	}

	configURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openid-configuration returned %d", resp.StatusCode)
	}

	var openid struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&openid); err != nil {
		return "", err
	}

	if strings.TrimSpace(openid.JWKSURI) == "" {
		return "", errors.New("jwks_uri missing in openid-configuration")
	}

	return strings.TrimSpace(openid.JWKSURI), nil
}

func (c *JWKSCache) setError(err error) {
	c.mu.Lock()
	c.lastErr = err
	if c.nextRefreshAt.IsZero() {
		c.nextRefreshAt = time.Now().Add(minimumJWKSTTL)
	}
	c.mu.Unlock()
}

func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var doc jwksResponse
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	if len(doc.Keys) == 0 {
		return nil, errors.New("jwks has no keys")
	}

	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kid == "" {
			continue
		}

		switch key.Kty {
		case "RSA":
			if key.N == "" || key.E == "" {
				continue
			}
			pubKey, err := jwkToRSAPublicKey(key.N, key.E)
			if err != nil {
				continue
			}
			out[key.Kid] = pubKey

		case "EC":
			if key.Crv == "" || key.X == "" || key.Y == "" {
				continue
			}
			pubKey, err := jwkToECDSAPublicKey(key.Crv, key.X, key.Y)
			if err != nil {
				continue
			}
			out[key.Kid] = pubKey
		}
	}

	if len(out) == 0 {
		return nil, errors.New("jwks has no usable keys")
	}

	return out, nil
}

func jwkToRSAPublicKey(nB64 string, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}

	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("invalid rsa key parameters")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	if e <= 0 {
		return nil, errors.New("invalid rsa exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func jwkToECDSAPublicKey(crvB64, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crvB64 {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crvB64)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ec point is not on curve")
	}

	return pub, nil
}

func parseCacheControlMaxAge(cacheControl string, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = defaultJWKSTTL
	}

	parts := strings.Split(cacheControl, ",")
	for _, part := range parts {
		value := strings.TrimSpace(strings.ToLower(part))
		if !strings.HasPrefix(value, "max-age=") {
			continue
		}

		sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(value, "max-age=")), 10, 64)
		if err != nil || sec <= 0 {
			continue
		}

		ttl := time.Duration(sec) * time.Second
		if ttl < minimumJWKSTTL {
			return minimumJWKSTTL
		}
		return ttl
	}

	return fallback
}
