package main

import (
	"crypto/rand"
	"crypto/tls"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"strings"
	"time"

	"ext-authz/internal/cache"
	"ext-authz/internal/auth"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type authzServer struct {
	authv3.UnimplementedAuthorizationServer
	jwtVerifier    *auth.JWTVerifier
	replayCache    *replayCache
	dpopProofCache *replayCache
	crlChecker     *auth.CRLChecker
	requiredScopes   []string
	configErr        error
	dpopNonceEnabled bool
	dpopNonce       string
	dpopNonceTTL    time.Duration
	dpopNonceExp    time.Time
	dpopNonceMu     sync.Mutex
	policy          *auth.PolicyConfig
	rateLimiter     *cache.RateLimiter
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	if tlsCertFile == "" {
		tlsCertFile = "/etc/internal-tls/tls.crt"
	}
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if tlsKeyFile == "" {
		tlsKeyFile = "/etc/internal-tls/tls.key"
	}

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		log.Fatalf("failed to load TLS cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := buildAuthzServer(context.Background())

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	authv3.RegisterAuthorizationServer(grpcServer, server)

	log.Printf("ext_authz gRPC server listening on :%s (TLS)", port)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("grpc server failed: %v", err)
	}
}

// Check implements the Envoy external authorization gRPC service.
// This is the main authorization pipeline that enforces zero-trust security through:
// 1. Optional client certificate validation when a browser/API client presents one
// 2. Optional JWT signature verification when a bearer token is supplied
// 3. Policy evaluation to distinguish public and protected routes
// 4. Token-certificate binding (RFC 8705 cnf.x5t#S256) when cnf claims are present
// 5. Replay protection (jti tracking) for authenticated tokens
func (s *authzServer) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	httpRequest := req.GetAttributes().GetRequest().GetHttp()
	requestMethod := strings.TrimSpace(httpRequest.GetMethod())
	requestPath := strings.TrimSpace(httpRequest.GetPath())
	requestHost := strings.TrimSpace(httpRequest.GetHost())
	if requestHost == "" {
		requestHost = getHeader(headers, "host")
	}
	rawXFCC := getHeader(headers, "x-forwarded-client-cert")
	rawAuthorization := authorizationFromHeaders(headers)

	if s.configErr != nil {
		log.Printf("CONFIG ERROR: %v", s.configErr)
		return deny(http.StatusUnauthorized, "authorization service configuration error"), nil
	}

	// Step 1: Extract and validate client certificate when one is presented.
	identity := &auth.ClientIdentity{}
	if strings.TrimSpace(rawXFCC) != "" {
		parsedIdentity, err := auth.ParseClientIdentityFromXFCC(rawXFCC)
		if err != nil {
			log.Printf("AUTH DENY (step1 cert): %v", err)
			return mapAuthErr(err), nil
		}
		identity = parsedIdentity
	}

	// Step 1b: Check certificate revocation status (CRL)
	if s.crlChecker != nil && strings.TrimSpace(identity.SerialNumber) != "" {
		revoked, crlErr := s.crlChecker.IsRevoked(identity.SerialNumber)
		if crlErr != nil {
			return deny(http.StatusInternalServerError, fmt.Sprintf("crl check error: %v", crlErr)), nil
		}
		if revoked {
			return deny(http.StatusForbidden, "client certificate has been revoked"), nil
		}
	}

	// Step 2: Verify JWT signature when a bearer token is supplied.
	tokenClaims := &auth.TokenClaims{RawClaims: map[string]any{}}
	if strings.TrimSpace(rawAuthorization) != "" {
		verifiedClaims, err := s.jwtVerifier.VerifyAuthorizationHeader(rawAuthorization)
		if err != nil {
			return mapAuthErr(err), nil
		}
		tokenClaims = verifiedClaims
	}

	// Step 3: Verify token is bound to the presented certificate (proof-of-possession)
	if strings.TrimSpace(tokenClaims.CnfX5TS256) != "" {
		if err := auth.ValidateTokenCertBinding(tokenClaims.CnfX5TS256, identity.Thumbprint); err != nil {
			return mapAuthErr(err), nil
		}
	}

	if strings.TrimSpace(tokenClaims.CnfJKT) != "" {
		requiredNonce := ""
		if s.dpopNonceEnabled {
			requiredNonce = s.currentDPoPNonce()
		}
		requestURL := buildRequestURL(httpRequest.GetScheme(), httpRequest.GetHost(), requestPath)
		rawAccessToken := stripBearerPrefix(rawAuthorization)
		if err := auth.ValidateDPoPBinding(
			tokenClaims.CnfJKT,
			getHeader(headers, "dpop"),
			requestMethod,
			requestURL,
			rawAccessToken,
			parseDurationEnv("DPoP_MAX_AGE", 2*time.Minute),
			parseDurationEnv("DPoP_CLOCK_SKEW", 2*time.Second),
			requiredNonce,
		); err != nil {
			return mapAuthErr(err), nil
		}
		if s.dpopNonceEnabled {
			s.rotateDPoPNonce()
		}
		dpopProofJTI := extractDPoPProofJTI(getHeader(headers, "dpop"))
		if strings.TrimSpace(dpopProofJTI) != "" {
			if err := s.dpopProofCache.MarkIfNew(dpopProofJTI); err != nil {
				return mapAuthErr(err), nil
			}
		}
	}

	if strings.TrimSpace(tokenClaims.CnfJKT) == "" && len(tokenClaims.CnfJWK) > 0 {
		if err := auth.ValidateHoKBinding(
			tokenClaims.CnfJWK,
			requestMethod,
			requestPath,
			requestHost,
			headers,
			getHeader(headers, "signature"),
		); err != nil {
			return mapAuthErr(err), nil
		}
	}

	policyDecision := s.policy.Evaluate(auth.PolicyRequest{
		Method:   requestMethod,
		Path:     requestPath,
		Claims:   tokenClaims,
		Identity: identity,
	})
	if !policyDecision.Allowed {
		if strings.TrimSpace(rawAuthorization) == "" && tokenRequiredPolicyReason(policyDecision.Reason) {
			return deny(http.StatusUnauthorized, "Missing Bearer Token"), nil
		}
		return deny(policyDecision.HTTPStatus, policyDecision.Reason), nil
	}

	requiredScopes := mergeStringSlices(s.requiredScopes, policyDecision.RequiredScopes)
	if err := auth.ValidateScopes(tokenClaims.Scopes, requiredScopes); err != nil {
		return mapAuthErr(err), nil
	}

	if err := s.enforceRateLimit(policyDecision.RateLimit, tokenClaims, identity); err != nil {
		return deny(err.HTTPStatus, err.Message), nil
	}

	dpopNonce := ""
	if s.dpopNonceEnabled {
		dpopNonce = s.currentDPoPNonce()
	}
	return allow(tokenClaims.Subject, identity.Subject, dpopNonce), nil
}

func getHeader(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return strings.TrimSpace(value)
	}

	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func authorizationFromHeaders(headers map[string]string) string {
	if authz := getHeader(headers, "authorization"); strings.TrimSpace(authz) != "" {
		return authz
	}
	if token := cookieValue(getHeader(headers, "cookie"), "access_token"); token != "" {
		return "Bearer " + token
	}
	return ""
}

func cookieValue(rawCookie string, name string) string {
	for _, part := range strings.Split(rawCookie, ";") {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) == 2 && keyValue[0] == name {
			return strings.TrimSpace(keyValue[1])
		}
	}
	return ""
}

func tokenRequiredPolicyReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	return strings.Contains(reason, "token claim") ||
		strings.Contains(reason, "token claims") ||
		strings.Contains(reason, "missing token")
}

func buildRequestURL(scheme string, host string, path string) string {
	protocol := strings.TrimSpace(strings.ToLower(scheme))
	requestHost := strings.TrimSpace(host)
	requestPath := strings.TrimSpace(path)

	if requestHost == "" {
		return ""
	}

	if protocol == "" {
		protocol = "https"
	}

	if requestPath == "" {
		requestPath = "/"
	}

	return protocol + "://" + requestHost + requestPath
}

func buildAuthzServer(ctx context.Context) *authzServer {
	issuer := strings.TrimSpace(firstNonEmpty(os.Getenv("JWT_ISSUER"), os.Getenv("KEYCLOAK_ISSUER_URL")))
	audience := strings.TrimSpace(os.Getenv("JWT_AUDIENCE"))

	if issuer == "" || audience == "" {
		return &authzServer{configErr: fmt.Errorf("JWT_ISSUER/KEYCLOAK_ISSUER_URL and JWT_AUDIENCE are required")}
	}

	jwksURL := strings.TrimSpace(os.Getenv("JWKS_URL"))
	requiredScopes := parseScopesEnv("REQUIRED_SCOPE", "REQUIRED_SCOPES")

	jwksTTL := parseDurationEnv("JWKS_REFRESH_INTERVAL", 5*time.Minute)
	jwksCache := auth.NewJWKSCache(jwksURL, jwksTTL)
	jwksCache.SetIssuerForDiscovery(issuer)
	jwksCache.Start(ctx)

	verifier := auth.NewJWTVerifier(issuer, audience, jwksCache)
	replay := newReplayCache(
		parseDurationEnv("REPLAY_TTL", 10*time.Minute),
		parseIntEnv("REPLAY_CACHE_MAX_ENTRIES", 10000),
	)
	dpopNonceEnabled := parseBoolEnv("DPoP_REQUIRE_NONCE", false)
	dpopNonceTTL := parseDPoPNonceTTL("DPoP_NONCE_TTL", 5*time.Minute)
	policyFile := strings.TrimSpace(os.Getenv("AUTHZ_POLICY_FILE"))
	policy, err := auth.LoadPolicyFromFile(policyFile)
	if err != nil {
		return &authzServer{configErr: fmt.Errorf("failed to load policy: %w", err)}
	}
	if policy == nil {
		policy = auth.NewAllowPolicy()
	}

	dpopProofTTL := parseDurationEnv("DPoP_PROOF_TTL", 5*time.Minute)
	dpopProofMax := parseIntEnv("DPoP_PROOF_MAX_ENTRIES", 100000)
	crlURL := parseStringEnv("CRL_DISTRIBUTION_URL")
	crlToken := parseStringEnv("VAULT_TOKEN")
	crlChecker := auth.NewCRLCheckerWithToken(crlURL, crlToken, parseDurationEnv("CRL_REFRESH_INTERVAL", 15*time.Minute))

	return &authzServer{
		jwtVerifier:      verifier,
		replayCache:      replay,
		dpopProofCache:   cache.NewReplayCache(dpopProofTTL, dpopProofMax),
		crlChecker:       crlChecker,
		requiredScopes:   requiredScopes,
		dpopNonceEnabled: dpopNonceEnabled,
		dpopNonceTTL:     dpopNonceTTL,
		policy:           policy,
		rateLimiter:      cache.NewRateLimiter(),
	}
}

func (s *authzServer) enforceRateLimit(policyRateLimit *auth.RateLimitDecision, tokenClaims *auth.TokenClaims, identity *auth.ClientIdentity) *auth.AuthError {
	if policyRateLimit == nil || !policyRateLimit.Enabled || s.rateLimiter == nil {
		return nil
	}

	identityToken := rateLimitIdentity(policyRateLimit.IdentityBy, tokenClaims, identity)
	if strings.TrimSpace(identityToken) == "" {
		return &auth.AuthError{HTTPStatus: http.StatusUnauthorized, Message: "missing identity for rate limiting"}
	}

	if allowed := s.rateLimiter.Allow(identityToken, policyRateLimit.MaxRequests, policyRateLimit.Window); !allowed {
		return &auth.AuthError{HTTPStatus: http.StatusTooManyRequests, Message: "rate limit exceeded"}
	}

	return nil
}

func rateLimitIdentity(mode string, tokenClaims *auth.TokenClaims, identity *auth.ClientIdentity) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "cert_subject":
		if identity != nil && strings.TrimSpace(identity.Subject) != "" {
			return "cert_subject:" + strings.TrimSpace(identity.Subject)
		}
	case "cert_thumbprint":
		if identity != nil && strings.TrimSpace(identity.Thumbprint) != "" {
			return "cert_thumbprint:" + strings.TrimSpace(identity.Thumbprint)
		}
	case "sub", "subject", "token_subject":
		if strings.TrimSpace(tokenClaims.Subject) != "" {
			return "token_subject:" + strings.TrimSpace(tokenClaims.Subject)
		}
	}

	if strings.TrimSpace(tokenClaims.Subject) != "" {
		return "token_subject:" + strings.TrimSpace(tokenClaims.Subject)
	}
	if identity != nil && strings.TrimSpace(identity.Subject) != "" {
		return "cert_subject:" + strings.TrimSpace(identity.Subject)
	}
	return ""
}

func parseScopesEnv(names ...string) []string {
	for _, name := range names {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}

		scopes := make([]string, 0)
		normalized := strings.ReplaceAll(raw, ",", " ")
		for _, scope := range strings.Fields(normalized) {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				scopes = append(scopes, scope)
			}
		}

		if len(scopes) > 0 {
			return scopes
		}
	}
	return nil
}

func parseDurationEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}

	return d
}

func parseIntEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func parseBoolEnv(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}

	if value, err := strconv.ParseBool(raw); err == nil {
		return value
	}

	return fallback
}

func parseDPoPNonceTTL(name string, fallback time.Duration) time.Duration {
	return parseDurationEnv(name, fallback)
}

func (s *authzServer) currentDPoPNonce() string {
	if !s.dpopNonceEnabled {
		return ""
	}

	s.dpopNonceMu.Lock()
	defer s.dpopNonceMu.Unlock()

	if strings.TrimSpace(s.dpopNonce) == "" || time.Now().After(s.dpopNonceExp) {
		s.dpopNonce = newDPoPNonce()
		s.dpopNonceExp = time.Now().Add(s.dpopNonceTTL)
	}

	return s.dpopNonce
}

func (s *authzServer) rotateDPoPNonce() {
	s.dpopNonceMu.Lock()
	s.dpopNonce = newDPoPNonce()
	s.dpopNonceExp = time.Now().Add(s.dpopNonceTTL)
	s.dpopNonceMu.Unlock()
}

func newDPoPNonce() string {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return "fallback-nonce"
	}

	return base64.RawURLEncoding.EncodeToString(seed)
}

func mapAuthErr(err error) *authv3.CheckResponse {
	authErr, ok := err.(*auth.AuthError)
	if !ok {
		log.Printf("AUTH DENY (generic): %v", err)
		return deny(http.StatusUnauthorized, "unauthorized")
	}

	log.Printf("AUTH DENY (status=%d): %s", authErr.HTTPStatus, authErr.Message)
	return deny(authErr.HTTPStatus, authErr.Message)
}

func deny(httpStatus int, message string) *authv3.CheckResponse {
	log.Printf("DENY status=%d msg=%q", httpStatus, message)
	statusCode := codes.Unauthenticated
	typeCode := typev3.StatusCode_Unauthorized

	if httpStatus == http.StatusForbidden {
		statusCode = codes.PermissionDenied
		typeCode = typev3.StatusCode_Forbidden
	}
	if httpStatus == http.StatusTooManyRequests {
		statusCode = codes.ResourceExhausted
		typeCode = typev3.StatusCode_TooManyRequests
	}

	return &authv3.CheckResponse{
		Status: status.New(statusCode, message).Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typeCode},
				Body:   message,
			},
		},
	}
}

func allow(user string, certSubject string, dpopNonce string) *authv3.CheckResponse {
	headers := []*corev3.HeaderValueOption{
		{
			Header:       &corev3.HeaderValue{Key: "x-authz-result", Value: "allow"},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
	}

	if strings.TrimSpace(user) != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: "x-auth-user", Value: user},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	if strings.TrimSpace(certSubject) != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: "x-auth-cert-subject", Value: certSubject},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	if strings.TrimSpace(dpopNonce) != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: "x-dpop-nonce", Value: dpopNonce},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	return &authv3.CheckResponse{
		Status: status.New(codes.OK, "allowed").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: headers},
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func mergeStringSlices(left, right []string) []string {
	out := make([]string, 0, len(left)+len(right))
	out = append(out, left...)
	out = append(out, right...)
	return out
}

type replayCache = cache.ReplayCache

// newReplayCache keeps the existing authz server factory API while delegating
// implementation to the internal cache package.
func newReplayCache(ttl time.Duration, maxEntries ...int) *replayCache {
	if len(maxEntries) == 0 {
		return cache.NewReplayCacheWithConfig(
			ttl,
			10000,
			parseStringEnv("REPLAY_BACKEND"),
			parseStringEnv("REPLAY_REDIS_URL"),
			parseStringEnv("REPLAY_REDIS_KEY_PREFIX"),
		)
	}
	return cache.NewReplayCacheWithConfig(
		ttl,
		maxEntries[0],
		parseStringEnv("REPLAY_BACKEND"),
		parseStringEnv("REPLAY_REDIS_URL"),
		parseStringEnv("REPLAY_REDIS_KEY_PREFIX"),
	)
}

func parseStringEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func stripBearerPrefix(authHeader string) string {
	raw := strings.TrimSpace(authHeader)
	for _, prefix := range []string{"Bearer ", "bearer "} {
		if strings.HasPrefix(raw, prefix) {
			return strings.TrimSpace(raw[len(prefix):])
		}
	}
	return ""
}

func extractDPoPProofJTI(dpopHeader string) string {
	if strings.TrimSpace(dpopHeader) == "" {
		return ""
	}
	token, _, err := new(jwt.Parser).ParseUnverified(dpopHeader, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	raw, _ := claims["jti"]
	value, _ := raw.(string)
	return strings.TrimSpace(value)
}
