package auth

import (
	"os"
	"testing"
)

func TestLoadPolicyFromFile_MatchesTokenSubjectAndScopes(t *testing.T) {
	content := []byte(`
version: "1"
default_action: "allow"
rules:
  - name: protected-read
    match:
      path_prefix: "/protected"
      methods: ["GET"]
    conditions:
      token_subjects: ["integration-user"]
      required_scopes: ["api:read"]
`)

	tmp, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(content); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	cfg, err := LoadPolicyFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	decision := cfg.Evaluate(PolicyRequest{
		Method: "GET",
		Path:   "/protected/resource",
		Claims: &TokenClaims{
			Subject:   "integration-user",
			Scopes:    []string{"api:read"},
			RawClaims: map[string]any{"iss": "issuer"},
		},
		Identity: &ClientIdentity{
			Subject: "CN=demo-client",
		},
	})

	if !decision.Allowed {
		t.Fatalf("expected allowed, got deny: %q", decision.Reason)
	}
	if len(decision.RequiredScopes) != 1 || decision.RequiredScopes[0] != "api:read" {
		t.Fatalf("expected required scope api:read, got %v", decision.RequiredScopes)
	}
}

func TestLoadPolicyFromFile_DeniesTokenSubjectMismatch(t *testing.T) {
	content := []byte(`
version: "1"
default_action: "allow"
rules:
  - name: deny-others
    match:
      path_prefix: "/protected"
      methods: ["GET"]
    conditions:
      token_subjects: ["integration-user"]
`)

	tmp, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(content); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	cfg, err := LoadPolicyFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	decision := cfg.Evaluate(PolicyRequest{
		Method: "GET",
		Path:   "/protected/resource",
		Claims: &TokenClaims{
			Subject:   "unauthorized-user",
			RawClaims: map[string]any{"iss": "issuer"},
		},
		Identity: &ClientIdentity{
			Subject: "CN=demo-client",
		},
	})

	if decision.Allowed {
		t.Fatal("expected deny for mismatched subject")
	}
}

func TestLoadPolicyFromFile_FallsThroughToLaterMatchingRule(t *testing.T) {
	content := []byte(`
version: "1"
default_action: "allow"
rules:
  - name: weekday-rule
    match:
      path_prefix: "/protected"
      methods: ["GET"]
    conditions:
      token_subjects: ["weekday-user"]
  - name: break-glass-rule
    match:
      path_prefix: "/protected"
      methods: ["GET"]
    conditions:
      cert_subjects: ["CN=demo-client"]
`)

	tmp, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(content); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	cfg, err := LoadPolicyFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	decision := cfg.Evaluate(PolicyRequest{
		Method: "GET",
		Path:   "/protected/resource",
		Claims: &TokenClaims{
			Subject:   "weekend-user",
			RawClaims: map[string]any{"iss": "issuer"},
		},
		Identity: &ClientIdentity{
			Subject: "CN=demo-client",
		},
	})

	if !decision.Allowed {
		t.Fatalf("expected later matching rule to allow request, got deny: %q", decision.Reason)
	}
}
