# Client Onboarding Guide

## Overview

This guide describes how to onboard new clients to the Zero-Trust API Authentication system. The current implementation supports machine-to-machine authentication using mTLS with certificate-bound JWTs (RFC 8705).

## Current Implementation Status

**Implemented**:
- Machine-to-machine (M2M) authentication with mTLS + certificate-bound tokens
- Docker Compose-based demo environment
- Keycloak identity provider integration
- JWT verification with JWKS caching
- Token-certificate binding via `cnf.x5t#S256`
- Replay protection using `jti` tracking

**Not Implemented** (future work):
- Full native DPoP (RFC 9449) for mobile/browser clients
- Automated certificate management via cert-manager
- Vault PKI runtime integration (scripts exist, not active in docker-compose)
- Certificate revocation enforcement (CRL infrastructure exists, not enforced)
- Kubernetes deployment (manifests exist, not runtime tested)
- Distributed replay cache (current: in-memory per instance)
- Mock/extend DPoP support using local key pair (see `clients/curl-scripts/06-ok-dpop-mock.sh`) is available for lab testing.

---

## Supported Client Types

### 1. Machine-to-Machine (M2M) Services ✅ IMPLEMENTED

**Use case**: Backend services, microservices, batch jobs, server-to-server communication

**Authentication pattern**: mTLS + Certificate-Bound JWT (RFC 8705)

**Requirements**:
- Client certificate signed by trusted CA
- Keycloak client credentials (client_id, client_secret)
- Network access to Keycloak and API gateway

#### Onboarding Steps

**Step 1: Generate client certificate**

Current demo setup uses static certificates. For new clients:

```bash
# Generate private key
openssl genrsa -out client.key 2048

# Generate certificate signing request
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=service-name"

# Sign with demo CA (requires CA private key)
openssl x509 -req -in client.csr \
  -CA project_root/infra/certs/root-ca.crt \
  -CAkey project_root/infra/certs/root-ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256
```

**Note**: Vault PKI scripts exist in `project_root/infra/vault/` but are not integrated into the active docker-compose runtime.

**Step 2: Calculate certificate thumbprint**

The thumbprint is used for token-certificate binding:

```bash
openssl x509 -in client.crt -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p -c 256
```

Save this value - it will be configured in Keycloak.

**Step 3: Create Keycloak client**

1. Access Keycloak admin console: `http://localhost:18080`
   - Username: `admin`
   - Password: `admin`

2. Navigate to realm `zero-trust` → Clients → Create

3. Configure client:
   - **Client ID**: `service-name`
   - **Client Protocol**: `openid-connect`
   - **Access Type**: `confidential`
   - **Service Accounts Enabled**: `ON`
   - **Standard Flow Enabled**: `OFF`
   - **Direct Access Grants Enabled**: `OFF`

4. Save and note the client secret from the **Credentials** tab

**Step 4: Add certificate thumbprint mapper**

1. Navigate to client → **Mappers** → **Create**

2. Configure mapper:
   - **Name**: `certificate-thumbprint`
   - **Mapper Type**: `Hardcoded claim`
   - **Token Claim Name**: `cnf.x5t#S256`
   - **Claim value**: `<thumbprint from Step 2>`
   - **Claim JSON Type**: `String`
   - **Add to ID token**: `OFF`
   - **Add to access token**: `ON`
   - **Add to userinfo**: `OFF`

3. Save

**Step 5: Test authentication**

Request token from Keycloak:

```bash
curl -X POST \
  -d "grant_type=client_credentials" \
  -d "client_id=service-name" \
  -d "client_secret=<client-secret>" \
  http://localhost:18080/realms/zero-trust/protocol/openid-connect/token
```

Extract access token from response:

```bash
TOKEN=$(curl -s -X POST \
  -d "grant_type=client_credentials" \
  -d "client_id=service-name" \
  -d "client_secret=<client-secret>" \
  http://localhost:18080/realms/zero-trust/protocol/openid-connect/token | \
  jq -r .access_token)
```

Call protected API:

```bash
curl --cert client.crt --key client.key \
  --cacert project_root/infra/certs/root-ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/
```

**Expected result**: `200 OK` with response from backend service

**Step 6: Verify token binding**

Decode JWT and verify `cnf.x5t#S256` matches certificate thumbprint:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .cnf
```

Expected output:
```json
{
  "x5t#S256": "<certificate-thumbprint>"
}
```

**Step 7: Distribute credentials securely**

Provide to service:
- `client.crt` (certificate)
- `client.key` (private key, encrypted at rest)
- `client_id` (Keycloak client ID)
- `client_secret` (Keycloak client secret, encrypted)
- `root-ca.crt` (CA certificate for TLS verification)
- API gateway URL: `https://localhost:10000` (or production URL)
- Keycloak token endpoint: `http://localhost:18080/realms/zero-trust/protocol/openid-connect/token`

**Security recommendations**:
- Store private key encrypted at rest
- Use environment variables or secret management system (e.g., Kubernetes Secrets, HashiCorp Vault)
- Rotate certificates before expiration (recommend 30-90 day TTL)
- Monitor certificate expiration dates
- Implement automated certificate renewal (future: cert-manager integration)

---

### 2. Mobile Applications ❌ NOT IMPLEMENTED

**Use case**: iOS, Android mobile apps

**Status**: Not currently supported. Future work.

**Recommended approach** (future implementation):
- Implement DPoP (RFC 9449) for proof-of-possession
- Mobile app generates ephemeral key pair on device
- App authenticates user via OAuth 2.0 Authorization Code + PKCE
- App requests DPoP-bound access token
- App signs each API request with DPoP proof
- ext_authz verifies DPoP proof and token binding

**Current limitation**: mTLS is not suitable for mobile clients as certificate distribution and management is impractical.

**Workaround** (not recommended for production):
- Deploy separate API gateway for mobile clients
- Use OAuth 2.0 bearer tokens without certificate binding
- Gateway translates to internal mTLS for backend communication

---

### 3. Browser Single-Page Applications (SPA) ❌ NOT IMPLEMENTED

**Use case**: React, Vue, Angular web applications

**Status**: Not currently supported. Future work.

**Recommended approach** (future implementation):
- Implement DPoP (RFC 9449) for browser clients
- SPA uses OAuth 2.0 Authorization Code + PKCE flow
- SPA generates ephemeral key pair using Web Crypto API
- SPA requests DPoP-bound access token
- SPA signs each API request with DPoP proof
- ext_authz verifies DPoP proof and token binding

**Current limitation**: Browsers cannot use client certificates for API calls (mTLS not practical).

**Workaround** (not recommended for production):
- Use Backend-for-Frontend (BFF) pattern
- BFF handles mTLS authentication to API gateway
- SPA authenticates to BFF with session cookies
- BFF proxies requests to protected APIs

---

### 4. Third-Party Integrators

**Use case**: External partners, customer integrations, B2B API access

**Authentication pattern**: Same as M2M (mTLS + certificate-bound JWT)

**Status**: ✅ Supported (same as M2M onboarding)

**Additional considerations**:
- Issue certificates from separate intermediate CA for third parties (future: Vault PKI)
- Implement stricter rate limiting per partner (not currently implemented)
- Add advanced scope-based access control (partially via `REQUIRED_SCOPE(S)` today)
- Monitor usage patterns for anomalies
- Provide API documentation and integration guides

**Onboarding**: Follow M2M steps 1-7, plus:

**Step 8: Define access scope** (future work)

Current implementation enforces required global scope claims via env var `REQUIRED_SCOPE(S)`. For full partner-level policy:
- Define allowed scopes for partner
- Add scope mapper to Keycloak client
- Configure ext_authz policy enforcement

**Step 9: Provide integration documentation**

- API endpoint documentation
- Authentication flow examples
- Rate limits and quotas (not currently enforced)
- Support contact information
- SLA and incident response procedures

**Step 10: Monitor and audit**

- Track API usage per partner (requires observability implementation)
- Alert on unusual patterns (not currently implemented)
- Regular access reviews
- Certificate expiration notifications

---

## Certificate Lifecycle Management

### Issuance

**Current**: Manual certificate generation using OpenSSL

**Future**: Automated via cert-manager + Vault PKI

### Renewal

**Current**: Manual renewal required before expiration

**Recommended TTL**: 
- Manual process: 365 days
- Automated process (future): 30-90 days

**Renewal process** (current manual approach):
1. Generate new certificate 7-14 days before expiration
2. Calculate new certificate thumbprint
3. Update Keycloak client mapper with new thumbprint
4. Request new token with new certificate
5. Update service configuration with new certificate and token
6. Verify new credentials work
7. Decommission old certificate after grace period

**Future automation**:
- cert-manager automatically renews certificates
- Service watches for certificate updates
- Automatic token refresh on certificate change
- Zero-downtime certificate rotation

### Revocation

**Current**: CRL infrastructure exists but not enforced in Envoy runtime

**Process** (when CRL enforcement is enabled):
1. Identify compromised certificate serial number
2. Revoke certificate in CA
3. Update CRL
4. Distribute updated CRL to Envoy
5. Restart or reload Envoy to pick up new CRL

**Future**: Enable CRL checking in Envoy configuration or implement OCSP

**Immediate mitigation** (current workaround):
- Delete Keycloak client to prevent new token issuance
- Wait for existing tokens to expire (default: 5 minutes)
- Compromised certificate cannot obtain new valid tokens

---

## Current Environment

### Docker Compose Setup

The demo environment runs on Docker Compose:

```bash
# Start services
docker-compose up --build -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f envoy ext_authz keycloak

# Run functional suite (A-H)
cd project_root && ./tests/run-all.sh

# Run security attack scenarios (SEC-01..SEC-04)
cd project_root && ./tests/security/run-all-security.sh

# Stop services
docker-compose down
```

**Services**:
- **Keycloak**: `http://localhost:18080` (identity provider)
- **Envoy**: `https://localhost:10000` (mTLS gateway)
- **ext_authz**: Internal gRPC service on port `50051`
- **backend**: Internal echo service on port `8080`

### Kubernetes Deployment

**Status**: Manifests exist in `project_root/k8s/` but are not runtime tested

**Future work**:
- Test Kubernetes deployment end-to-end
- Integrate cert-manager for automated certificate management
- Deploy distributed replay cache (Redis)
- Implement horizontal scaling for ext_authz
- Add observability (Prometheus, Grafana, Jaeger)

---

## Troubleshooting

### Token request fails with "invalid_client"

**Cause**: Incorrect client_id or client_secret

**Solution**: 
1. Verify credentials in Keycloak admin console
2. Check client exists in `zero-trust` realm
3. Verify client secret matches

### Token request succeeds but API call returns 403 Forbidden

**Cause**: Certificate thumbprint mismatch

**Solution**:
1. Calculate actual certificate thumbprint:
   ```bash
   openssl x509 -in client.crt -outform DER | \
     openssl dgst -sha256 -binary | xxd -p -c 256
   ```
2. Decode JWT and check `cnf.x5t#S256`:
   ```bash
   echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .cnf
   ```
3. Verify thumbprints match (case-insensitive)
4. Update Keycloak mapper if mismatch

### API call returns 401 Unauthorized

**Cause**: Missing or invalid bearer token

**Solution**:
1. Verify token is included in `Authorization: Bearer <token>` header
2. Check token expiration:
   ```bash
   echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .exp
   ```
3. Compare with current time: `date +%s`
4. Request new token if expired

### API call returns 403 "replay detected"

**Cause**: JWT ID (`jti`) already used within replay window

**Solution**:
1. Request new token (each token has unique `jti`)
2. Do not reuse tokens across multiple requests if replay protection is strict
3. Current replay window: 10 minutes (configurable via `REPLAY_TTL` env var)
4. Replay cache size: 10,000 entries (configurable via `REPLAY_CACHE_MAX_ENTRIES` env var)

### TLS handshake fails

**Cause**: Certificate not trusted by Envoy

**Solution**:
1. Verify certificate is signed by trusted CA
2. Check certificate expiration:
   ```bash
   openssl x509 -in client.crt -noout -dates
   ```
3. Verify CA certificate is in Envoy trust store
4. Check Envoy logs:
   ```bash
   docker-compose logs envoy | grep -i tls
   ```

### Keycloak not accessible

**Cause**: Service not started or port conflict

**Solution**:
1. Check service status: `docker-compose ps keycloak`
2. Check logs: `docker-compose logs keycloak`
3. Verify port 18080 is not in use: `netstat -an | grep 18080`
4. Restart if needed: `docker-compose restart keycloak`

---

## Security Best Practices

1. **Never commit private keys to version control**
2. **Use short-lived certificates** (30-90 days with automated renewal)
3. **Rotate client secrets regularly** (90 days recommended)
4. **Monitor certificate expiration** (alert 7-14 days before expiry)
5. **Use separate CAs** for internal vs external clients (future: Vault PKI)
6. **Implement rate limiting** per client identity (not currently implemented)
7. **Log all authentication attempts** for audit (basic logging exists)
8. **Review access regularly** (quarterly recommended)
9. **Revoke compromised credentials immediately**
10. **Use hardware security modules (HSM)** for production CA keys (future)

---

## Current Limitations

1. **No DPoP support**: Mobile and browser clients not supported
2. **Manual certificate management**: No automated issuance or renewal
3. **CRL not enforced**: Revoked certificates not rejected until expiration
4. **In-memory replay cache**: Not suitable for multi-instance deployments
5. **Coarse scope enforcement**: Global scope claims are checked; per-route/verb policy matrix is not yet implemented
6. **No rate limiting**: No protection against abuse from authenticated clients
7. **Basic observability**: No metrics, tracing, or alerting
8. **Vault PKI not active**: Scripts exist but not integrated into runtime
9. **Kubernetes not tested**: Manifests exist but not validated end-to-end

---

## Documentation References

- **Architecture**: `docs/architecture.md`
- **Quickstart**: `docs/quickstart.md`
- **Security Analysis**: `docs/security-analysis.md`
- **Threat Model**: `docs/threat-model.md`
- **Token Binding Design**: `docs/token-binding-design.md`
- **Operational Resilience**: `docs/operational-resilience.md`
- **PKI Architecture**: `docs/pki-architecture.md`
- **Runbook**: `docs/runbook.md`

---

## Support and Next Steps

For production deployment, implement:
1. **Automated certificate management** (cert-manager + Vault PKI)
2. **DPoP support** for mobile and browser clients (RFC 9449)
3. **Distributed replay cache** (Redis with circuit breaker)
4. **Scope-based access control** in ext_authz
5. **Rate limiting** per client identity
6. **Observability stack** (Prometheus, Grafana, Jaeger)
7. **CRL/OCSP enforcement** in Envoy
8. **Kubernetes deployment** with horizontal scaling
9. **Automated testing** for certificate rotation and key rotation
10. **Security monitoring** and alerting

For current demo environment:
- Follow quickstart guide: `docs/quickstart.md`
- Run functional tests: `cd project_root && ./tests/run-all.sh`
- Run security attack scenarios: `cd project_root && ./tests/security/run-all-security.sh`
- Review architecture: `docs/architecture.md`
