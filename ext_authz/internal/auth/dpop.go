package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	defaultDPoPMaxAge     = 2 * time.Minute
	defaultDPoPClockSkew = 2 * time.Second
	dpopProofType        = "dpop+jwt"
)

func ValidateDPoPBinding(expectedJKT, dpopHeader, requestMethod, requestURI string, accessToken string, maxAge, clockSkew time.Duration, requiredNonce string) error {
	if strings.TrimSpace(expectedJKT) == "" {
		return unauthorized("missing cnf.jkt binding claim")
	}

	if strings.TrimSpace(dpopHeader) == "" {
		return unauthorized("missing DPoP header")
	}

	if strings.TrimSpace(requestMethod) == "" {
		return unauthorized("missing request method")
	}

	if strings.TrimSpace(requestURI) == "" {
		return unauthorized("missing request URI")
	}

	parsedMaxAge := maxAge
	if parsedMaxAge <= 0 {
		parsedMaxAge = defaultDPoPMaxAge
	}

	parsedClockSkew := clockSkew
	if parsedClockSkew < 0 {
		parsedClockSkew = 0
	}
	if parsedClockSkew > defaultDPoPClockSkew {
		parsedClockSkew = defaultDPoPClockSkew
	}

	var proofJWK map[string]any
	token, err := jwt.Parse(
		dpopHeader,
		func(token *jwt.Token) (any, error) {
			if token.Method == nil {
				return nil, unauthorized("invalid DPoP proof algorithm")
			}

			if token.Header == nil {
				return nil, unauthorized("missing DPoP header")
			}

			if typRaw, ok := token.Header["typ"]; ok {
				typ, ok := typRaw.(string)
				if ok && typ != "" && !strings.EqualFold(typ, dpopProofType) {
					return nil, unauthorized("invalid DPoP proof type")
				}
			}

			rawJWK, ok := token.Header["jwk"]
			if !ok {
				return nil, unauthorized("missing DPoP jwk")
			}

			parsedMap, ok := rawJWK.(map[string]any)
			if !ok {
				return nil, unauthorized("invalid DPoP jwk")
			}

			publicKey, err := parseJWKPublicKey(parsedMap)
			if err != nil {
				return nil, err
			}

			proofJWK = parsedMap
			return publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}),
	)
	if err != nil || token == nil || !token.Valid {
		return unauthorized("invalid DPoP proof")
	}

	if proofJWK == nil {
		return unauthorized("missing DPoP jwk")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return unauthorized("invalid DPoP claims")
	}

	if err := validateDPoPClaims(claims, requestMethod, requestURI); err != nil {
		return err
	}

	jwtJWKThumbprint, err := thumbprintJWK(proofJWK)
	if err != nil {
		return unauthorized("invalid DPoP jwk thumbprint")
	}

	if !strings.EqualFold(jwtJWKThumbprint, expectedJKT) {
		return forbidden("DPoP proof key does not match token cnf.jkt")
	}

	if err := validateDPoPIAT(claims["iat"], parsedMaxAge, parsedClockSkew); err != nil {
		return err
	}

	if strings.TrimSpace(requiredNonce) != "" {
		actualNonce := strings.TrimSpace(stringClaim(claims, "nonce"))
		if actualNonce == "" {
			return unauthorized("DPoP proof missing nonce")
		}

		if !strings.EqualFold(actualNonce, strings.TrimSpace(requiredNonce)) {
			return forbidden("DPoP proof nonce mismatch")
		}
	}

	if err := validateDPoPATH(claims, accessToken); err != nil {
		return err
	}

	return nil
}

func validateDPoPATH(claims jwt.MapClaims, accessToken string) error {
	if strings.TrimSpace(accessToken) == "" {
		return nil
	}

	ath := strings.TrimSpace(stringClaim(claims, "ath"))
	if ath == "" {
		return unauthorized("DPoP proof missing ath claim (RFC 9449 §2)")
	}

	sum := sha256.Sum256([]byte(accessToken))
	expectedATH := base64.RawURLEncoding.EncodeToString(sum[:])

	if !strings.EqualFold(ath, expectedATH) {
		return forbidden("DPoP proof ath mismatch (access token hash)")
	}

	return nil
}

func validateDPoPClaims(claims jwt.MapClaims, requestMethod, requestURI string) error {
	htm := strings.TrimSpace(stringClaim(claims, "htm"))
	if htm == "" {
		return unauthorized("DPoP proof missing htm")
	}
	if !strings.EqualFold(htm, strings.TrimSpace(requestMethod)) {
		return forbidden("DPoP method mismatch")
	}

	htu := strings.TrimSpace(stringClaim(claims, "htu"))
	if htu == "" {
		return unauthorized("DPoP proof missing htu")
	}

	expectedHTU, err := normalizeDPoPUTU(requestURI)
	if err != nil {
		return unauthorized("invalid request URI")
	}

	actualHTU, err := normalizeDPoPUTU(htu)
	if err != nil {
		return unauthorized("invalid DPoP htu")
	}
	if !strings.EqualFold(expectedHTU, actualHTU) {
		return forbidden("DPoP htu mismatch")
	}

	if strings.TrimSpace(stringClaim(claims, "jti")) == "" {
		return unauthorized("DPoP proof missing jti")
	}

	return nil
}

func validateDPoPIAT(rawIAT any, maxAge, clockSkew time.Duration) error {
	issuedAt, err := parseNumericDate(rawIAT)
	if err != nil {
		return unauthorized("invalid DPoP proof iat")
	}

	now := time.Now().UTC()
	if issuedAt.After(now.Add(clockSkew)) {
		return unauthorized("DPoP proof used before issued")
	}

	if now.Sub(issuedAt) > maxAge {
		return unauthorized("DPoP proof expired")
	}

	return nil
}

func parseNumericDate(raw any) (time.Time, error) {
	switch v := raw.(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case json.Number:
		intValue, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(intValue, 0).UTC(), nil
	default:
		return time.Time{}, errors.New("invalid numeric date")
	}
}

func normalizeDPoPUTU(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("invalid URI")
	}
	if parsed.Fragment != "" {
		return "", errors.New("DPoP htu must not include fragment")
	}

	path := strings.TrimSpace(parsed.EscapedPath())
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}

	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host) + path, nil
}

func parseJWKPublicKey(jwk map[string]any) (any, error) {
	kty := strings.TrimSpace(stringValue(jwk["kty"]))
	switch kty {
	case "RSA":
		return parseRSAJWKPublicKey(jwk)
	case "EC":
		return parseECJWKPublicKey(jwk)
	default:
		return nil, unauthorized("unsupported DPoP jwk kty")
	}
}

func parseRSAJWKPublicKey(jwk map[string]any) (any, error) {
	nRaw := stringValue(jwk["n"])
	eRaw := stringValue(jwk["e"])
	if nRaw == "" || eRaw == "" {
		return nil, unauthorized("DPoP jwk missing RSA parameters")
	}

	n, err := decodeBase64ToBigInt(nRaw)
	if err != nil {
		return nil, unauthorized("invalid DPoP jwk modulus")
	}
	e, err := decodeBase64ToInt(eRaw)
	if err != nil || e <= 0 {
		return nil, unauthorized("invalid DPoP jwk exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECJWKPublicKey(jwk map[string]any) (any, error) {
	crv := strings.TrimSpace(stringValue(jwk["crv"]))
	xRaw := stringValue(jwk["x"])
	yRaw := stringValue(jwk["y"])
	if crv == "" || xRaw == "" || yRaw == "" {
		return nil, unauthorized("DPoP jwk missing EC parameters")
	}

	curve, err := curveFromName(crv)
	if err != nil {
		return nil, unauthorized("unsupported DPoP ec curve")
	}

	x, err := decodeBase64ToBigInt(xRaw)
	if err != nil {
		return nil, unauthorized("invalid DPoP jwk x coordinate")
	}

	y, err := decodeBase64ToBigInt(yRaw)
	if err != nil {
		return nil, unauthorized("invalid DPoP jwk y coordinate")
	}

	if !curve.IsOnCurve(x, y) {
		return nil, unauthorized("invalid DPoP ec public key")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func decodeBase64ToBigInt(value string) (*big.Int, error) {
	raw, err := decodeBase64URLEncoded(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func decodeBase64ToInt(value string) (int, error) {
	raw, err := decodeBase64URLEncoded(value)
	if err != nil {
		return 0, err
	}

	i := new(big.Int).SetBytes(raw).Int64()
	if i <= 0 {
		return 0, errors.New("invalid integer")
	}
	return int(i), nil
}

func decodeBase64URLEncoded(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty base64 value")
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func stringValue(raw any) string {
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func thumbprintJWK(jwk map[string]any) (string, error) {
	kty := strings.TrimSpace(stringValue(jwk["kty"]))
	switch kty {
	case "RSA":
		return thumbprintRSAJWK(jwk)
	case "EC":
		return thumbprintECJWK(jwk)
	default:
		return "", errors.New("unsupported DPoP jwk thumbprint")
	}
}

func thumbprintRSAJWK(jwk map[string]any) (string, error) {
	n := strings.TrimSpace(stringValue(jwk["n"]))
	e := strings.TrimSpace(stringValue(jwk["e"]))
	if n == "" || e == "" {
		return "", errors.New("invalid RSA thumbprint input")
	}

	payload, err := marshalSortedJSON(map[string]any{
		"e":   e,
		"kty": "RSA",
		"n":   n,
	})
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func thumbprintECJWK(jwk map[string]any) (string, error) {
	crv := strings.TrimSpace(stringValue(jwk["crv"]))
	x := strings.TrimSpace(stringValue(jwk["x"]))
	y := strings.TrimSpace(stringValue(jwk["y"]))
	if crv == "" || x == "" || y == "" {
		return "", errors.New("invalid EC thumbprint input")
	}

	payload, err := marshalSortedJSON(map[string]any{
		"crv": crv,
		"kty": "EC",
		"x":   x,
		"y":   y,
	})
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func marshalSortedJSON(values map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	builder := strings.Builder{}
	builder.WriteString("{")
	for idx, key := range keys {
		if idx > 0 {
			builder.WriteString(",")
		}

		value, err := json.Marshal(values[key])
		if err != nil {
			return nil, err
		}
		builder.WriteString(fmt.Sprintf("\"%s\":%s", key, string(value)))
	}
	builder.WriteString("}")

	return []byte(builder.String()), nil
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, errors.New("unsupported curve")
	}
}
