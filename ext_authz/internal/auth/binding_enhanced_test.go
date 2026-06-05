package auth

import (
	"testing"
)

// Enhanced edge case tests for token-certificate binding

func TestValidateTokenCertBinding_NullBytes(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba\x00"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for thumbprint with null byte, got nil")
	}
}

func TestValidateTokenCertBinding_DifferentCase(t *testing.T) {
	tokenThumbprint := "5238B8BA24419FD472ECEBE18010E0D2256C420C7AA50CBA080E9ABD9C60BBBA"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error for case-insensitive match, got %v", err)
	}
}

func TestValidateTokenCertBinding_MixedCase(t *testing.T) {
	tokenThumbprint := "5238B8ba24419FD472ecebe18010E0D2256c420C7aa50CBA080e9ABD9c60BBBA"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error for mixed-case match, got %v", err)
	}
}

func TestValidateTokenCertBinding_LeadingTrailingWhitespace(t *testing.T) {
	tokenThumbprint := "\t5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba\n"
	clientThumbprint := " 5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba "

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err != nil {
		t.Errorf("expected no error with whitespace trimming, got %v", err)
	}
}

func TestValidateTokenCertBinding_OneByteDifference(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbbb"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for one-byte difference, got nil")
	}

	if !isForbidden(err) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestValidateTokenCertBinding_ShortThumbprint(t *testing.T) {
	tokenThumbprint := "5238b8ba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for short thumbprint, got nil")
	}
}

func TestValidateTokenCertBinding_LongThumbprint(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba5238b8ba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for long thumbprint, got nil")
	}
}

func TestValidateTokenCertBinding_NonHexCharacters(t *testing.T) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbzz"

	err := ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	if err == nil {
		t.Error("expected error for non-hex characters, got nil")
	}
}

// Benchmark tests
func BenchmarkValidateTokenCertBinding_Success(b *testing.B) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	}
}

func BenchmarkValidateTokenCertBinding_CaseInsensitive(b *testing.B) {
	tokenThumbprint := "5238B8BA24419FD472ECEBE18010E0D2256C420C7AA50CBA080E9ABD9C60BBBA"
	clientThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	}
}

func BenchmarkValidateTokenCertBinding_Mismatch(b *testing.B) {
	tokenThumbprint := "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
	clientThumbprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateTokenCertBinding(tokenThumbprint, clientThumbprint)
	}
}
