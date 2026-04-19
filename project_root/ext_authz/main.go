package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ext-authz/internal/auth"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authzServer struct {
	authv3.UnimplementedAuthorizationServer
	jwtVerifier *auth.JWTVerifier
	replayCache *replayCache
	configErr   error
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

	server := buildAuthzServer(context.Background())

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, server)

	log.Printf("ext_authz gRPC server listening on :%s", port)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("grpc server failed: %v", err)
	}
}

func (s *authzServer) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	if s.configErr != nil {
		return deny(http.StatusUnauthorized, "authorization service configuration error"), nil
	}

	identity, err := auth.ParseClientIdentityFromXFCC(getHeader(headers, "x-forwarded-client-cert"))
	if err != nil {
		return mapAuthErr(err), nil
	}

	tokenClaims, err := s.jwtVerifier.VerifyAuthorizationHeader(getHeader(headers, "authorization"))
	if err != nil {
		return mapAuthErr(err), nil
	}

	if err := auth.ValidateTokenCertBinding(tokenClaims.CnfX5TS256, identity.Thumbprint); err != nil {
		return mapAuthErr(err), nil
	}

	if err := s.replayCache.MarkIfNew(tokenClaims.JWTID); err != nil {
		return mapAuthErr(err), nil
	}

	return allow(tokenClaims.Subject, identity.Subject), nil
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

func buildAuthzServer(ctx context.Context) *authzServer {
	issuer := strings.TrimSpace(firstNonEmpty(os.Getenv("JWT_ISSUER"), os.Getenv("KEYCLOAK_ISSUER_URL")))
	audience := strings.TrimSpace(os.Getenv("JWT_AUDIENCE"))

	if issuer == "" || audience == "" {
		return &authzServer{configErr: fmt.Errorf("JWT_ISSUER/KEYCLOAK_ISSUER_URL and JWT_AUDIENCE are required")}
	}

	jwksURL := strings.TrimSpace(os.Getenv("JWKS_URL"))

	jwksTTL := parseDurationEnv("JWKS_REFRESH_INTERVAL", 5*time.Minute)
	jwksCache := auth.NewJWKSCache(jwksURL, jwksTTL)
	jwksCache.SetIssuerForDiscovery(issuer)
	jwksCache.Start(ctx)

	verifier := auth.NewJWTVerifier(issuer, audience, jwksCache)
	replay := newReplayCache(parseDurationEnv("REPLAY_TTL", 10*time.Minute))

	return &authzServer{
		jwtVerifier: verifier,
		replayCache: replay,
	}
}

func parseDurationEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}

	return d
}

func mapAuthErr(err error) *authv3.CheckResponse {
	authErr, ok := err.(*auth.AuthError)
	if !ok {
		return deny(http.StatusUnauthorized, "unauthorized")
	}

	return deny(authErr.HTTPStatus, authErr.Message)
}

func deny(httpStatus int, message string) *authv3.CheckResponse {
	statusCode := codes.Unauthenticated
	typeCode := typev3.StatusCode_Unauthorized

	if httpStatus == http.StatusForbidden {
		statusCode = codes.PermissionDenied
		typeCode = typev3.StatusCode_Forbidden
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

func allow(user string, certSubject string) *authv3.CheckResponse {
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

type replayCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	items map[string]time.Time
	last  time.Time
}

func newReplayCache(ttl time.Duration) *replayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &replayCache{ttl: ttl, items: make(map[string]time.Time, 256), last: time.Now()}
}

func (c *replayCache) MarkIfNew(jti string) error {
	if strings.TrimSpace(jti) == "" {
		return &auth.AuthError{HTTPStatus: http.StatusUnauthorized, Message: "missing jti claim"}
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if now.Sub(c.last) >= c.ttl {
		cutoff := now.Add(-c.ttl)
		for key, seenAt := range c.items {
			if seenAt.Before(cutoff) {
				delete(c.items, key)
			}
		}
		c.last = now
	}

	if _, exists := c.items[jti]; exists {
		return &auth.AuthError{HTTPStatus: http.StatusForbidden, Message: "replay detected"}
	}

	c.items[jti] = now
	return nil
}
