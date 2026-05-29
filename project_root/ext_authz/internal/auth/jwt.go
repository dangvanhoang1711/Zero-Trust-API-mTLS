package auth

import (
	"errors"
	"fmt"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

type JWTVerifier struct {
	issuer   string
	audience string
	cache    *JWKSCache
	parser   *jwt.Parser
}

type TokenClaims struct {
	Subject    string
	JWTID      string
	Issuer     string
	Audience   []string
	CnfX5TS256 string
}

func NewJWTVerifier(issuer string, audience string, cache *JWKSCache) *JWTVerifier {
	return &JWTVerifier{
		issuer:   strings.TrimSpace(issuer),
		audience: strings.TrimSpace(audience),
		cache:    cache,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
			jwt.WithIssuer(strings.TrimSpace(issuer)),
			jwt.WithAudience(strings.TrimSpace(audience)),
		),
	}
}

func (v *JWTVerifier) VerifyAuthorizationHeader(authzHeader string) (*TokenClaims, error) {
	raw, err := extractBearerToken(authzHeader)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	_, err = v.parser.ParseWithClaims(raw, claims, v.keyFunc)
	if err != nil {
		return nil, unauthorized("invalid token")
	}

	cnf, err := extractCNFThumbprint(claims)
	if err != nil {
		return nil, forbidden("missing cnf.x5t#S256")
	}

	subject := stringClaim(claims, "sub")
	if strings.TrimSpace(subject) == "" {
		return nil, unauthorized("invalid token")
	}

	return &TokenClaims{
		Subject:    subject,
		JWTID:      stringClaim(claims, "jti"),
		Issuer:     stringClaim(claims, "iss"),
		Audience:   audienceClaim(claims["aud"]),
		CnfX5TS256: cnf,
	}, nil
}

func (v *JWTVerifier) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return nil, errors.New("missing kid")
	}

	if v.cache == nil {
		return nil, errors.New("jwks cache not configured")
	}

	key, err := v.cache.Lookup(kid)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func extractBearerToken(authzHeader string) (string, error) {
	if strings.TrimSpace(authzHeader) == "" {
		return "", unauthorized("missing bearer token")
	}

	parts := strings.SplitN(strings.TrimSpace(authzHeader), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", unauthorized("invalid authorization header")
	}

	return strings.TrimSpace(parts[1]), nil
}

func extractCNFThumbprint(claims jwt.MapClaims) (string, error) {
	rawCNF, ok := claims["cnf"]
	if !ok {
		return "", errors.New("cnf missing")
	}

	cnfMap, ok := rawCNF.(map[string]any)
	if !ok {
		return "", errors.New("cnf invalid")
	}

	rawThumb, ok := cnfMap["x5t#S256"].(string)
	if !ok || strings.TrimSpace(rawThumb) == "" {
		return "", errors.New("x5t missing")
	}

	return strings.TrimSpace(rawThumb), nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return value
}

func audienceClaim(raw any) []string {
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok || strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, text)
		}
		return out
	default:
		return nil
	}
}

func BuildJWKSURL(baseURL string) (string, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return "", fmt.Errorf("KEYCLOAK_ISSUER_URL is required")
	}

	return strings.TrimRight(trimmed, "/") + "/.well-known/jwks.json", nil
}
