# Token-Certificate Binding Design

## Overview

This document describes the cryptographic binding mechanism that ties access tokens (JWTs) to client certificates, implementing proof-of-possession for zero-trust API authentication.

## Problem Statement

Traditional bearer tokens suffer from a fundamental security weakness: anyone who possesses the token can use it. This creates several attack vectors:

1. **Token theft**: Stolen tokens can be used by attackers
2. **Token replay**: Captured tokens can be replayed from different clients
3. **Insufficient authentication**: Token alone doesn't prove client identity

Zero-trust security requires **proof-of-possession**: the client must prove they possess a specific cryptographic key, not just present a token.

## Design Goals

1. **Cryptographic binding**: Token must be cryptographically bound to client certificate
2. **Theft prevention**: Stolen token must be unusable without certificate private key
3. **Standards compliance**: Follow established RFCs and industry standards
4. **Performance**: Minimal overhead for verification
5. **Compatibility**: Work with standard OAuth 2.0 and OpenID Connect flows

## Evaluated Approaches

### Option 1: DPoP (RFC 9449)

**Mechanism**: Client generates ephemeral key pair and signs each request with a DPoP proof.

**Pros**:
- Works for browser and mobile clients
- No need for long-lived client certificates
- Supports key rotation per request

**Cons**:
- Requires DPoP-aware client implementation
- More complex verification (per-request signature check)
- Limited IdP support (Keycloak doesn't fully support DPoP as of v26)

**Status**: Not implemented. Future work for mobile/browser clients.

### Option 2: HTTP Message Signatures (RFC 9421)

**Mechanism**: Client signs HTTP request headers and body using certificate private key.

**Pros**:
- Strong request integrity
- Prevents request tampering
- Standards-based

**Cons**:
- Complex canonicalization rules
- High computational overhead
- Requires signature verification per request

**Status**: Not implemented. Overkill for current use case.

### Option 3: mTLS Certificate-Bound Tokens (RFC 8705) ✅

**Mechanism**: IdP embeds client certificate thumbprint in JWT `cnf` claim. Authorization service verifies thumbprint matches presented certificate.

**Pros**:
- Simple verification (one-time thumbprint comparison)
- Strong binding (requires certificate private key)
- Well-supported by enterprise IdPs (Keycloak, Auth0, Okta)
- Suitable for machine-to-machine authentication

**Cons**:
- Requires mTLS infrastructure
- Not suitable for browser clients
- Certificate management overhead

**Status**: ✅ **Implemented** (chosen approach)

## Implemented Design: RFC 8705 Certificate-Bound Tokens

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Client requests token from IdP                               │
│    - Presents client certificate during TLS handshake           │
│    - Sends client credentials (client_id, client_secret)        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. IdP (Keycloak) issues JWT with cnf claim                     │
│    {                                                             │
│      "iss": "http://keycloak:8080/realms/zero-trust",          │
│      "sub": "demo-client",                                       │
│      "aud": "api-gateway",                                       │
│      "exp": 1234567890,                                          │
│      "cnf": {                                                    │
│        "x5t#S256": "5238b8ba24419fd472ecebe18010e0d2..."        │
│      }                                                            │
│    }                                                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. Client calls API with mTLS + JWT                             │
│    - Presents same certificate during TLS handshake             │
│    - Sends JWT in Authorization header                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. Envoy forwards request to ext_authz                          │
│    - Extracts client certificate from TLS handshake             │
│    - Forwards certificate in x-forwarded-client-cert header     │
│    - Forwards Authorization header                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. ext_authz verifies binding                                   │
│    a. Parse JWT and extract cnf.x5t#S256                        │
│    b. Parse XFCC header and extract certificate                 │
│    c. Calculate SHA-256 thumbprint of certificate               │
│    d. Compare thumbprints (case-insensitive)                    │
│    e. Allow if match, deny if mismatch                          │
└─────────────────────────────────────────────────────────────────┘
```

### Cryptographic Details

#### Certificate Thumbprint Calculation

The thumbprint is calculated as:

```
thumbprint = hex(SHA-256(DER-encoded-certificate))
```

**Implementation**: `project_root/ext_authz/internal/auth/mtls.go:88`

```go
func sha256Thumbprint(derBytes []byte) string {
    hash := sha256.Sum256(derBytes)
    return hex.EncodeToString(hash[:])
}
```

#### JWT cnf Claim Structure

Per RFC 8705 Section 3.1:

```json
{
  "cnf": {
    "x5t#S256": "5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba"
  }
}
```

- `cnf`: Confirmation claim (RFC 7800)
- `x5t#S256`: X.509 certificate SHA-256 thumbprint

#### Binding Verification

**Implementation**: `project_root/ext_authz/internal/auth/binding.go:7`

```go
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
```

**Key properties**:
- Case-insensitive comparison (hex encoding may vary)
- Whitespace trimming (handle formatting differences)
- Clear error messages for debugging

### Keycloak Configuration

#### Protocol Mapper

Keycloak uses a custom protocol mapper to add the `cnf` claim:

**Type**: `Certificate Thumbprint (SHA-256)`

**Configuration**:
- Mapper Type: `User Attribute`
- Token Claim Name: `cnf.x5t#S256`
- Claim JSON Type: `String`
- Add to ID token: `false`
- Add to access token: `true`
- Add to userinfo: `false`

**Realm export**: `project_root/infra/keycloak/realm-export.json`

#### Client Configuration

**Client ID**: `demo-client`

**Access Type**: `confidential`

**Authentication Flow**: Client Credentials Grant (OAuth 2.0)

**Certificate Binding**: Enabled via protocol mapper

### Security Properties

#### Property 1: Token Theft Prevention

**Scenario**: Attacker intercepts JWT from network or logs.

**Protection**: Attacker cannot use token without certificate private key.

**Verification**: Test D (`04-fail-valid-token-wrong-cert-binding.sh`)

#### Property 2: Certificate Theft Prevention

**Scenario**: Attacker steals client certificate.

**Protection**: Certificate alone is insufficient; valid JWT is also required.

**Verification**: Test B (`02-fail-no-cert.sh`)

#### Property 3: Binding Integrity

**Scenario**: Attacker modifies `cnf` claim in JWT.

**Protection**: JWT signature verification fails if claims are modified.

**Verification**: Test C (`03-fail-invalid-auth-header.sh`)

#### Property 4: Replay Prevention

**Scenario**: Attacker replays valid request with bound token and certificate.

**Protection**: `jti` tracking prevents reuse of same token.

**Verification**: Test E (`05-fail-replay-jti.sh`)

### Performance Characteristics

#### Token Issuance Overhead

- **Thumbprint calculation**: ~0.1ms (one-time during token issuance)
- **JWT signing**: ~1-2ms (RSA-2048)
- **Total overhead**: Negligible compared to network latency

#### Verification Overhead

- **JWT signature verification**: ~1-2ms (RSA-2048)
- **Thumbprint calculation**: ~0.1ms
- **Thumbprint comparison**: <0.01ms
- **Total overhead**: ~2-3ms per request

**Optimization**: JWKS caching eliminates repeated public key fetches.

### Comparison with Alternatives

| Feature | mTLS-bound (RFC 8705) | DPoP (RFC 9449) | HTTP Signatures (RFC 9421) |
|---------|----------------------|-----------------|---------------------------|
| Browser support | ❌ No | ✅ Yes | ✅ Yes |
| Mobile support | ⚠️ Limited | ✅ Yes | ✅ Yes |
| M2M support | ✅ Excellent | ⚠️ Possible | ✅ Yes |
| Verification cost | Low (one-time) | Medium (per-request) | High (per-request) |
| IdP support | ✅ Wide | ⚠️ Limited | ⚠️ Limited |
| Key rotation | Manual (cert renewal) | Automatic (ephemeral) | Manual |
| Implementation complexity | Low | Medium | High |

### Limitations and Future Work

#### Limitation 1: Browser Clients

**Issue**: Browsers cannot easily use client certificates for API calls.

**Workaround**: Use DPoP for browser-based clients.

**Future work**: Implement DPoP alongside mTLS-bound tokens.

#### Limitation 2: Certificate Lifecycle

**Issue**: Certificate renewal requires coordination with IdP.

**Current state**: Manual certificate management.

**Future work**: Integrate cert-manager for automated certificate lifecycle.

#### Limitation 3: Cross-Domain Binding

**Issue**: Token bound to one certificate cannot be used with another.

**Impact**: No token delegation or impersonation.

**Assessment**: This is a feature, not a bug. Prevents lateral movement.

#### Limitation 4: Revocation

**Issue**: Compromised certificate remains valid until expiration.

**Current state**: CRL infrastructure exists but not enforced.

**Future work**: Enable CRL checking in Envoy or implement OCSP.

### Testing and Verification

#### Manual Verification

Calculate certificate thumbprint:

```bash
openssl x509 -in project_root/infra/certs/client.crt -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p -c 256
```

Expected output:
```
5238b8ba24419fd472ecebe18010e0d2256c420c7aa50cba080e9abd9c60bbba
```

Decode JWT and verify `cnf.x5t#S256` matches:

```bash
echo "<JWT>" | cut -d. -f2 | base64 -d | jq .cnf
```

#### Automated Testing

Run full security test suite:

```bash
cd project_root
./tests/run-all.sh
```

Tests verify:
- Valid binding allows access
- Missing token is rejected
- Invalid token is rejected
- Binding mismatch is rejected
- Replay is rejected

## Standards References

- **RFC 8705**: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
  - https://tools.ietf.org/html/rfc8705
- **RFC 7800**: Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)
  - https://tools.ietf.org/html/rfc7800
- **RFC 9449**: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
  - https://tools.ietf.org/html/rfc9449
- **RFC 9421**: HTTP Message Signatures
  - https://tools.ietf.org/html/rfc9421

## Conclusion

The implemented RFC 8705 certificate-bound token design provides strong proof-of-possession for machine-to-machine authentication. The cryptographic binding between JWT and client certificate prevents token theft and replay attacks while maintaining acceptable performance overhead.

For browser and mobile clients, future work should implement DPoP (RFC 9449) as a complementary mechanism that provides similar security properties without requiring client certificates.
