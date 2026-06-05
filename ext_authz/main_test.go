package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"strings"
	"testing"
	"time"

	"ext-authz/internal/auth"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
)

func TestNewReplayCache_DefaultTTL(t *testing.T) {
	cache := newReplayCache(0)
	if cache.ttl != 10*time.Minute {
		t.Errorf("expected default TTL 10m, got %v", cache.ttl)
	}
}

func TestNewReplayCache_CustomTTL(t *testing.T) {
	cache := newReplayCache(5 * time.Minute)
	if cache.ttl != 5*time.Minute {
		t.Errorf("expected TTL 5m, got %v", cache.ttl)
	}
}

func TestReplayCache_MarkIfNew_Success(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("unique-jti-1")
	if err != nil {
		t.Errorf("expected no error for new jti, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_Duplicate(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	jti := "duplicate-jti"

	// First use should succeed
	err := cache.MarkIfNew(jti)
	if err != nil {
		t.Errorf("expected no error for first use, got %v", err)
	}

	// Second use should fail
	err = cache.MarkIfNew(jti)
	if err == nil {
		t.Error("expected error for duplicate jti, got nil")
	}

	if err.Error() != "replay detected" {
		t.Errorf("expected 'replay detected' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_EmptyJTI(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("")
	if err == nil {
		t.Error("expected error for empty jti, got nil")
	}

	if err.Error() != "missing jti claim" {
		t.Errorf("expected 'missing jti claim' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_WhitespaceJTI(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("   ")
	if err == nil {
		t.Error("expected error for whitespace jti, got nil")
	}

	if err.Error() != "missing jti claim" {
		t.Errorf("expected 'missing jti claim' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_MultipleUnique(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	jtis := []string{"jti-1", "jti-2", "jti-3", "jti-4", "jti-5"}

	for _, jti := range jtis {
		err := cache.MarkIfNew(jti)
		if err != nil {
			t.Errorf("expected no error for unique jti %s, got %v", jti, err)
		}
	}
}

func TestReplayCache_MaxEntriesEvictsOldest(t *testing.T) {
	cache := newReplayCache(10*time.Minute, 1)

	err := cache.MarkIfNew("first-jti")
	if err != nil {
		t.Errorf("expected no error for first jti, got %v", err)
	}

	err = cache.MarkIfNew("second-jti")
	if err != nil {
		t.Errorf("expected no error when inserting new jti after max size is reached, got %v", err)
	}

	err = cache.MarkIfNew("first-jti")
	if err != nil {
		t.Errorf("expected first jti to be evicted after max size reached, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_Concurrent(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)
	jti := "concurrent-jti"

	var wg sync.WaitGroup
	results := make(chan error, 10)

	// Launch 10 concurrent attempts to mark same jti
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cache.MarkIfNew(jti)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	// Exactly one should succeed
	successCount := 0
	failCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 success, got %d", successCount)
	}

	if failCount != 9 {
		t.Errorf("expected exactly 9 failures, got %d", failCount)
	}
}

func TestReplayCache_MarkIfNew_ConcurrentUnique(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	var wg sync.WaitGroup
	results := make(chan error, 100)

	// Launch 100 concurrent attempts with unique jtis
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			jti := fmt.Sprintf("concurrent-unique-jti-%d", id)
			err := cache.MarkIfNew(jti)
			results <- err
		}(i)
	}

	wg.Wait()
	close(results)

	// All should succeed
	for err := range results {
		if err != nil {
			t.Errorf("expected no error for unique concurrent jti, got %v", err)
		}
	}
}

func TestReplayCache_Eviction(t *testing.T) {
	// Use very short TTL for testing
	cache := newReplayCache(100 * time.Millisecond)

	// Mark first jti
	err := cache.MarkIfNew("jti-1")
	if err != nil {
		t.Errorf("expected no error for jti-1, got %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Mark second jti to trigger eviction
	err = cache.MarkIfNew("jti-2")
	if err != nil {
		t.Errorf("expected no error for jti-2, got %v", err)
	}

	// First jti should now be evicted and can be reused
	err = cache.MarkIfNew("jti-1")
	if err != nil {
		t.Errorf("expected no error for jti-1 after eviction, got %v", err)
	}
}

func BenchmarkReplayCache_MarkIfNew(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jti := fmt.Sprintf("benchmark-jti-%d", i)
		_ = cache.MarkIfNew(jti)
	}
}

func BenchmarkReplayCache_MarkIfNew_Parallel(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			jti := fmt.Sprintf("parallel-jti-%d", i)
			_ = cache.MarkIfNew(jti)
			i++
		}
	})
}

func BenchmarkReplayCache_MarkIfNew_Duplicate(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)
	jti := "duplicate-benchmark-jti"

	// Pre-populate
	_ = cache.MarkIfNew(jti)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.MarkIfNew(jti)
	}
}

func TestAuthzServer_Check_AllowsValidRequest(t *testing.T) {
	signer, certPEM, expectedThumbprint := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	validToken, err := buildTestToken(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		expectedThumbprint,
		"test-jti-allow",
		nil,
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/", "localhost:10000", certPEM, validToken)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.OK)

	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OK response")
	}

	hasAuthUser := false
	hasAuthCert := false

	for _, header := range ok.Headers {
		switch header.GetHeader().GetKey() {
		case "x-auth-user":
			hasAuthUser = true
		case "x-auth-cert-subject":
			hasAuthCert = true
		}
	}

	if !hasAuthUser || !hasAuthCert {
		t.Fatalf("missing expected headers: x-auth-user=%v x-auth-cert-subject=%v", hasAuthUser, hasAuthCert)
	}
}

func TestAuthzServer_Check_DeniesReplayRequest(t *testing.T) {
	signer, certPEM, expectedThumbprint := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	replayedJTI := "test-jti-replay"
	token, err := buildTestToken(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		expectedThumbprint,
		replayedJTI,
		nil,
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/", "localhost:10000", certPEM, token)
	firstResp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("first check failed: %v", err)
	}
	assertCheckStatus(t, firstResp, codes.OK)

	secondResp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("second check failed: %v", err)
	}

	assertCheckStatus(t, secondResp, codes.PermissionDenied)
}

func TestAuthzServer_Check_DeniesCertificateBindingMismatch(t *testing.T) {
	signer, certPEM, _ := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	token, err := buildTestToken(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"test-jti-mismatch",
		nil,
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/", "localhost:10000", certPEM, token)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.PermissionDenied)
}

func TestAuthzServer_Check_DeniesRequestWithoutRequiredScope(t *testing.T) {
	signer, certPEM, expectedThumbprint := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	server.requiredScopes = []string{"api:read"}

	token, err := buildTestToken(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		expectedThumbprint,
		"test-jti-missing-scope",
		map[string]any{
			"scope": "openid",
		},
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/protected", "localhost:10000", certPEM, token)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.PermissionDenied)
}

func TestAuthzServer_Check_AllowsRequestWithRequiredScope(t *testing.T) {
	signer, certPEM, expectedThumbprint := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	server.requiredScopes = []string{"api:read"}

	token, err := buildTestToken(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		expectedThumbprint,
		"test-jti-scoped-allow",
		map[string]any{
			"scope": "openid api:read api:write",
		},
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/protected", "localhost:10000", certPEM, token)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.OK)
}

func TestAuthzServer_Check_AllowsRequestWithHoKBinding(t *testing.T) {
	signer, certPEM, _ := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	requestMethod := "GET"
	requestPath := "/protected"
	requestHost := "localhost:10000"
	requestHeaders := map[string]string{
		"host": requestHost,
		"date": "Tue, 20 Oct 2026 12:00:00 GMT",
	}

	cnfJWK := buildECCNFJWK(signer)
	token, err := buildTestTokenWithCNFJWK(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		"test-jti-hok-allow",
		cnfJWK,
		map[string]any{
			"scope": "openid api:read api:write",
		},
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signatureHeader := buildHoKSignatureHeader(
		t,
		signer,
		requestMethod,
		requestPath,
		requestHost,
		requestHeaders,
		[]string{"(request-target)", "host", "date"},
		"ecdsa-sha256",
	)

	req := buildAuthzCheckRequestWithHeaders(
		requestMethod,
		requestPath,
		requestHost,
		certPEM,
		token,
		map[string]string{
			"signature": signatureHeader,
			"date":      "Tue, 20 Oct 2026 12:00:00 GMT",
			"host":      requestHost,
		},
	)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.OK)
}

func TestAuthzServer_Check_DeniesRequestWithHoKBindingAndMissingSignature(t *testing.T) {
	signer, certPEM, _ := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	cnfJWK := buildECCNFJWK(signer)
	token, err := buildTestTokenWithCNFJWK(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		"test-jti-hok-missing-sig",
		cnfJWK,
		nil,
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	req := buildAuthzCheckRequest("GET", "/protected", "localhost:10000", certPEM, token)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.Unauthenticated)
}

func TestAuthzServer_Check_DeniesRequestWithHoKBindingAndInvalidSignature(t *testing.T) {
	signer, certPEM, _ := generateTestSigningMaterial(t)
	server, closeServer := newTestAuthzServer(t, "https://localhost:10000/realms/zero-trust", "api-gateway", signer)
	defer closeServer()

	cnfJWK := buildECCNFJWK(signer)
	token, err := buildTestTokenWithCNFJWK(
		signer,
		"test-kid",
		"https://localhost:10000/realms/zero-trust",
		"api-gateway",
		"test-jti-hok-invalid-sig",
		cnfJWK,
		nil,
	)
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	requestMethod := "GET"
	requestPath := "/protected"
	requestHost := "localhost:10000"
	requestHeaders := map[string]string{
		"host": requestHost,
		"date": "Tue, 20 Oct 2026 12:00:00 GMT",
	}
	signatureHeader := buildHoKSignatureHeader(
		t,
		signer,
		requestMethod,
		requestPath,
		requestHost,
		requestHeaders,
		[]string{"(request-target)", "host", "date"},
		"ecdsa-sha256",
	)
	invalidSignature, err := flipLastBase64Char(signatureHeader)
	if err != nil {
		t.Fatalf("flip signature: %v", err)
	}

	req := buildAuthzCheckRequestWithHeaders(
		requestMethod,
		requestPath,
		requestHost,
		certPEM,
		token,
		map[string]string{
			"signature": invalidSignature,
			"date":      "Tue, 20 Oct 2026 12:00:00 GMT",
			"host":      requestHost,
		},
	)
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	assertCheckStatus(t, resp, codes.Unauthenticated)
}

func generateTestSigningMaterial(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ext-authz-client",
		},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	certFingerprint := sha256.Sum256(certDER)
	return privateKey, certPEM, hex.EncodeToString(certFingerprint[:])
}

func newTestAuthzServer(t *testing.T, issuer, audience string, signer *ecdsa.PrivateKey) (*authzServer, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protocol/openid-connect/certs":
			xBytes := signer.PublicKey.X.Bytes()
			yBytes := signer.PublicKey.Y.Bytes()
			// Pad to 32 bytes for P-256
			xPadded := make([]byte, 32)
			yPadded := make([]byte, 32)
			copy(xPadded[32-len(xBytes):], xBytes)
			copy(yPadded[32-len(yBytes):], yBytes)
			keys := []map[string]any{{
				"kty": "EC",
				"use": "sig",
				"alg": "ES256",
				"kid": "test-kid",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(xPadded),
				"y":   base64.RawURLEncoding.EncodeToString(yPadded),
			}}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{
				"keys": keys,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.NotFound(w, r)
		}
	}))

	cache := auth.NewJWKSCache(server.URL+"/protocol/openid-connect/certs", time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cache.Start(ctx)

	serverObject := &authzServer{
		jwtVerifier: auth.NewJWTVerifier(issuer, audience, cache),
		replayCache: newReplayCache(10 * time.Minute),
		policy:      auth.NewAllowPolicy(),
	}

	return serverObject, func() {
		cancel()
		server.Close()
	}
}

func buildTestToken(
	signer *ecdsa.PrivateKey,
	keyID string,
	issuer string,
	audience string,
	cnfThumb string,
	jti string,
	extraClaims map[string]any,
) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "integration-user",
		"jti": jti,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	if strings.TrimSpace(cnfThumb) != "" {
		claims["cnf"] = map[string]any{"x5t#S256": cnfThumb}
	}

	for key, value := range extraClaims {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(signer)
}

func buildTestTokenWithCNFJWK(
	signer *ecdsa.PrivateKey,
	keyID string,
	issuer string,
	audience string,
	jti string,
	cnfJWK map[string]any,
	extraClaims map[string]any,
) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "integration-user",
		"jti": jti,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"cnf": map[string]any{"jwk": cnfJWK},
	}

	for key, value := range extraClaims {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(signer)
}

func buildAuthzCheckRequest(method, path, host, certPEM, token string) *authv3.CheckRequest {
	return buildAuthzCheckRequestWithHeaders(method, path, host, certPEM, token, nil)
}

func buildAuthzCheckRequestWithHeaders(method, path, host, certPEM, token string, extraHeaders map[string]string) *authv3.CheckRequest {
	requestHeaders := map[string]string{
		"x-forwarded-client-cert": fmt.Sprintf("Cert=%q", url.QueryEscape(certPEM)),
		"authorization":           "Bearer " + token,
	}

	for key, value := range extraHeaders {
		requestHeaders[key] = value
	}

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Path:    path,
					Scheme:  "https",
					Host:    host,
					Headers: requestHeaders,
				},
			},
		},
	}
}

func buildECCNFJWK(signer *ecdsa.PrivateKey) map[string]any {
	xBytes := signer.PublicKey.X.Bytes()
	yBytes := signer.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

func buildHoKSignatureHeader(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	method, path, host string,
	headers map[string]string,
	signedHeaders []string,
	algorithm string,
) string {
	t.Helper()

	canonicalString := buildHoKSigningString(method, path, host, headers, signedHeaders)
	hashAlg := resolveHoKHash(algorithm)
	digest := hashSigningInput(hashAlg, canonicalString)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	return fmt.Sprintf(
		`keyId="test-key",algorithm="%s",headers="%s",signature="%s"`,
		algorithm,
		strings.Join(signedHeaders, " "),
		base64.StdEncoding.EncodeToString(sig),
	)
}

func buildHoKSigningString(method, path, host string, headers map[string]string, signedHeaders []string) string {
	lines := make([]string, 0, len(signedHeaders))
	for _, rawHeader := range signedHeaders {
		header := strings.ToLower(strings.TrimSpace(rawHeader))
		switch header {
		case "(request-target)":
			lines = append(lines, "(request-target): "+strings.ToLower(strings.TrimSpace(method))+" "+strings.TrimSpace(path))
		case "host":
			lines = append(lines, "host: "+host)
		default:
			lines = append(lines, header+": "+strings.Join(strings.Fields(headers[header]), " "))
		}
	}
	return strings.Join(lines, "\n")
}

func resolveHoKHash(algorithm string) crypto.Hash {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "rsa-sha256", "ecdsa-sha256":
		return crypto.SHA256
	case "rsa-sha384", "ecdsa-sha384":
		return crypto.SHA384
	case "rsa-sha512", "ecdsa-sha512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func hashSigningInput(hashAlg crypto.Hash, raw string) []byte {
	switch hashAlg {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(raw))
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(raw))
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(raw))
		return sum[:]
	default:
		sum := sha256.Sum256([]byte(raw))
		return sum[:]
	}
}

func flipLastBase64Char(signatureHeader string) (string, error) {
	prefix := `signature="`
	start := strings.Index(signatureHeader, prefix)
	if start < 0 {
		return "", fmt.Errorf("signature header missing signature field")
	}
	start += len(prefix)
	end := strings.Index(signatureHeader[start:], `"`)
	if end < 0 {
		return "", fmt.Errorf("invalid signature header")
	}
	end += start

	value := signatureHeader[start:end]
	if value == "" {
		return "", fmt.Errorf("empty signature value")
	}

	last := len(value) - 1
	valueBytes := []byte(value)
	if valueBytes[last] == '=' {
		valueBytes[last] = 'A'
	} else if valueBytes[last] == 'A' {
		valueBytes[last] = 'B'
	} else {
		valueBytes[last] = 'A'
	}

	return signatureHeader[:start] + string(valueBytes) + signatureHeader[end:], nil
}

func assertCheckStatus(t *testing.T, resp *authv3.CheckResponse, expected codes.Code) {
	t.Helper()

	if resp == nil {
		t.Fatal("expected non-nil check response")
	}

	if resp.GetStatus() == nil {
		t.Fatal("expected status in check response")
	}

	if got := resp.GetStatus().GetCode(); got != int32(expected) {
		t.Fatalf(
			"expected check status %s (%d), got %d %q",
			expected.String(),
			expected,
			got,
			resp.GetStatus().Message,
		)
	}
}
