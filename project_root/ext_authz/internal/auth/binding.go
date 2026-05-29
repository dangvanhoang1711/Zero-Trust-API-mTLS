package auth

import (
	"strings"
)

func ValidateTokenCertBinding(tokenThumbprint string, clientThumbprint string) error {
	if strings.TrimSpace(tokenThumbprint) == "" {
		return forbidden("missing cnf.x5t#S256 claim")
	}

	if strings.TrimSpace(clientThumbprint) == "" {
		return unauthorized("missing client certificate thumbprint")
	}

	if !strings.EqualFold(strings.TrimSpace(tokenThumbprint), strings.TrimSpace(clientThumbprint)) {
		return forbidden("token is not bound to presented client certificate")
	}

	return nil
}
