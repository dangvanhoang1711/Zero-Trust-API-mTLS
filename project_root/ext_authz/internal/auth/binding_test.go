package auth

import (
	"testing"
)

func TestValidateTokenCertBinding_Success(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateTokenCertBinding_CaseInsensitive(t *testing.T) {
	tokenThumbprint := "5238B8BA24419FD472ECEBE18010E0D2256C420C7AA50CBA080E9ABD9C60BBBA"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error for case-insensitive match, got %v", err)
	}
}

func TestValidateTokenCertBinding_WithWhitespace(t *testing.T) {
	tokenThumbprint := "  5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba  "
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error with whitespace trimming, got %v", err)
	}
}

func TestValidateTokenCertBinding_Mismatch(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for mismatched thumbprints, got nil")
	}

	if !isForbidden(err) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestValidateTokenCertBinding_MissingTokenThumbprint(t *testing.T) {
	tokenThumbprint := ""
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for missing token thumbprint, got nil")
	}

	if !isForbidden(err) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestValidateTokenCertBinding_MissingClientThumbprint(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := ""

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for missing client thumbprint, got nil")
	}

	if !isUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestValidateTokenCertBinding_BothEmpty(t *testing.T) {
	tokenThumbprint := ""
	clientThumbprint := ""

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for both empty thumbprints, got nil")
	}
}
