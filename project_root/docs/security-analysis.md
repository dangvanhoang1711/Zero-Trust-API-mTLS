# Security Analysis

## Overview

This document analyzes the security properties of the Zero-Trust API Authentication system, documenting implemented protections, tested attack scenarios, and known limitations.

## Implemented Security Properties

### 1. Mutual TLS (mTLS) Client Authentication

**Implementation**: Envoy proxy enforces TLS client certificate verification during the handshake.

**Security guarantee**: Only clients presenting a certificate signed by the trusted CA can establish a connection to the gateway.

**Configuration**: `envoy_config/envoy.yaml` requires client certificates with `require_client_certificate: true`.

**Threat mitigation**:
- Prevents unauthorized network access
- Authenticates client machine/service identity
- Protects against network-level impersonation

### 2. JWT Signature Verification

**Implementation**: The ext_authz service validates JWT signatures using JWKS fetched from Keycloak.

**Security guarantee**: Only tokens signed by the trusted identity provider are accepted.

**Algorithm whitelist**: RS256, RS384, RS512 (asymmetric signatures only)

**Validation checks**:
- Signature verification using JWKS public keys
- Issuer (`iss`) claim matches expected value
- Audience (`aud`) claim matches expected value
- Expiration (`exp`) claim is in the future
- Not-before (`nbf`) claim is in the past

**Threat mitigation**:
- Prevents token forgery
- Prevents token tampering
- Prevents algorithm downgrade attacks (e.g., `alg: none`)

### 3. Token-Certificate Binding (Proof-of-Possession)

**Implementation**: RFC 8705-style certificate-bound access tokens using `cnf.x5t#S256` claim.

**Security guarantee**: A valid JWT can only be used by the client that possesses the private key corresponding to the bound certificate.

**Binding mechanism**:
1. Keycloak issues JWT with `cnf.x5t#S256` claim containing SHA-256 thumbprint of client certificate
2. Envoy forwards client certificate via `x-forwarded-client-cert` header
3. ext_authz extracts certificate from XFCC header
4. ext_authz calculates SHA-256 thumbprint of presented certificate
5. ext_authz compares token claim with calculated thumbprint
6. Authorization succeeds only if thumbprints match

**Threat mitigation**:
- Prevents bearer token theft
- Prevents token replay from different client
- Binds authorization to cryptographic proof-of-possession

**Code reference**: `project_root/ext_authz/internal/auth/binding.go:7`

### 4. Replay Protection

**Implementation**: In-memory cache tracking recently seen JWT IDs (`jti` claim).

**Security guarantee**: A JWT cannot be reused within the replay window (default 10 minutes).

**Mechanism**:
- ext_authz extracts `jti` claim from JWT
- Checks if `jti` exists in replay cache
- If new, stores `jti` with TTL and allows request
- If duplicate, rejects request with `403 Forbidden`

**Limitations**:
- Cache is in-memory per ext_authz instance
- Multi-instance deployments require shared cache (Redis)
- Replay protection window is bounded by JWT expiration

**Threat mitigation**:
- Prevents token replay attacks
- Limits damage from token compromise
- Enforces single-use semantics for short-lived tokens

**Code reference**: `project_root/ext_authz/main.go:73`

### 5. JWKS Caching and Rotation

**Implementation**: ext_authz fetches and caches JWKS from Keycloak OpenID discovery endpoint.

**Security guarantee**: Signing key rotation is supported without service restart.

**Mechanism**:
- Fetch JWKS from `/.well-known/openid-configuration` → `jwks_uri`
- Cache keys in memory with configurable refresh interval
- Automatic refresh on cache miss (key rotation)

**Threat mitigation**:
- Supports key rotation for cryptographic agility
- Reduces dependency on IdP availability
- Honors `Cache-Control` headers from IdP

**Code reference**: `project_root/ext_authz/internal/auth/jwks.go`

## Tested Attack Scenarios

All tests are automated in `project_root/tests/run-all.sh`.

### Test A: Valid Authentication (Baseline)

**Scenario**: Client presents valid mTLS certificate and valid bound JWT.

**Expected result**: `200 OK`

**Verification**: `project_root/clients/curl-scripts/01-ok-mtls-valid-header.sh`

### Test B: Missing Bearer Token

**Scenario**: Client presents valid mTLS certificate but no JWT.

**Expected result**: `401 Unauthorized`

**Security property**: mTLS alone is insufficient for application-level authorization.

**Verification**: `project_root/clients/curl-scripts/02-fail-no-cert.sh`

### Test C: Invalid or Malformed JWT

**Scenario**: Client presents valid mTLS certificate and invalid JWT.

**Expected result**: `401 Unauthorized`

**Security property**: Token signature verification prevents forgery.

**Verification**: `project_root/clients/curl-scripts/03-fail-invalid-auth-header.sh`

### Test D: Token-Certificate Binding Mismatch

**Scenario**: Client presents valid mTLS certificate and valid JWT, but `cnf.x5t#S256` does not match certificate thumbprint.

**Expected result**: `403 Forbidden`

**Security property**: Stolen tokens cannot be used by different clients.

**Attack simulation**: This simulates token theft where attacker obtains a valid JWT but does not possess the bound certificate's private key.

**Verification**: `project_root/clients/curl-scripts/04-fail-valid-token-wrong-cert-binding.sh`

### Test E: JWT Replay Attack

**Scenario**: Client reuses the same JWT (same `jti`) in multiple requests.

**Expected result**: First request succeeds (`200`), subsequent requests fail (`403 Forbidden`).

**Security property**: Replay protection prevents token reuse.

**Verification**: `project_root/clients/curl-scripts/05-fail-replay-jti.sh`

## Security Limitations and Future Work

### 1. Replay Cache Scalability

**Current state**: In-memory cache per ext_authz instance.

**Limitation**: Multi-instance deployments have independent caches, allowing cross-instance replay.

**Mitigation**: Deploy Redis or similar distributed cache for production.

### 2. Certificate Revocation

**Current state**: CRL infrastructure exists but is not enforced in active Envoy runtime.

**Limitation**: Revoked certificates are not rejected until expiration.

**Mitigation**: Enable CRL checking in Envoy TLS configuration or implement OCSP stapling.

**Documentation**: `project_root/docs/runbook.md`

### 3. DPoP (Demonstration of Proof-of-Possession)

**Current state**: Not implemented.

**Limitation**: Mobile/browser clients cannot use mTLS-bound tokens.

**Future work**: Implement RFC 9449 DPoP for ephemeral key binding.

**Design notes**: `project_root/docs/token-binding-design.md`

### 4. Vault PKI Integration

**Current state**: Vault PKI scripts and artifacts exist but are not part of active docker-compose runtime.

**Limitation**: Certificate issuance is manual, not automated.

**Future work**: Integrate Vault as dynamic PKI backend for automated certificate lifecycle.

**Artifacts**: `project_root/infra/vault/`

### 5. Kubernetes and cert-manager

**Current state**: Kubernetes manifests exist but are not tested in runtime.

**Limitation**: No automated certificate provisioning for Kubernetes workloads.

**Future work**: Deploy cert-manager with Vault Issuer for automated client certificate issuance.

**Manifests**: `project_root/k8s/`, `project_root/infra/cert-manager/`

### 6. Rate Limiting and Policy Enforcement

**Current state**: Not implemented.

**Limitation**: No protection against abuse from authenticated clients.

**Future work**: Implement per-client rate limiting and scope-based access control.

### 7. Observability and Monitoring

**Current state**: Basic logging only.

**Limitation**: No metrics, tracing, or alerting.

**Future work**: Integrate Prometheus metrics, OpenTelemetry tracing, and alerting rules.

## Threat Model Coverage

See `docs/threat-model.md` for detailed threat analysis using STRIDE methodology.

**Covered threats**:
- Spoofing: mTLS + JWT signature verification
- Tampering: JWT signature verification
- Repudiation: Audit logging (partial)
- Information Disclosure: TLS encryption
- Denial of Service: Not addressed
- Elevation of Privilege: Token-certificate binding

## Compliance and Standards

This implementation follows:

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7515**: JSON Web Signature (JWS)
- **RFC 8705**: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
- **OWASP API Security Top 10**: Addresses broken authentication, broken authorization, and security misconfiguration

## Verification

Run the full security test suite:

```bash
cd project_root
./tests/run-all.sh
```

Expected output:

```
All MVP demo tests passed
```

## Conclusion

The implemented system provides strong zero-trust authorization through cryptographic binding of tokens to client certificates. The combination of mTLS, JWT verification, and proof-of-possession prevents common API security threats including token theft, replay attacks, and unauthorized access.

Known limitations are documented and do not compromise the core security model for the demonstrated use case. Production deployment would require addressing scalability (distributed replay cache), revocation (CRL/OCSP), and observability (metrics and alerting).
