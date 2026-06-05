# Threat Model — Zero Trust API Gateway

## Scope

This document applies to the Zero Trust API Gateway with mTLS system — a two-EC2 deployment of Envoy, ext_authz, Keycloak, Vault, and Redis providing authenticated and authorized API access with mutual TLS, ES256 JWT, and token binding.

## Methodology

STRIDE threat classification: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

### Trust Boundaries

```
[Internet] ──mTLS──▶ [EC2-1: Envoy] ──gRPC──▶ [EC2-2: ext_authz] ──▶ [EC2-1: Backend]
                                ▲                       │
                                │                       ├── Keycloak (JWKS fetch)
                                │                       ├── Vault (PKI)
                                │                       └── Redis (replay cache)
```

| # | Boundary | Trust | Notes |
|---|----------|-------|-------|
| 1 | Internet → Envoy | **Untrusted** | Public access over mTLS |
| 2 | Envoy → ext_authz | **Trusted** | Internal gRPC, TLS encrypted |
| 3 | ext_authz → Keycloak | **Trusted** | Internal network, JWKS fetch |
| 4 | ext_authz → Backend | **Trusted** | Internal, via Envoy routing |

### Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Client certificate private keys | Critical | Client machines, Vault |
| Server TLS private key | Critical | EC2-1 (Envoy) |
| JWT signing key (Keycloak ES256) | Critical | EC2-2 (Keycloak) |
| Root CA private key | Critical | EC2-2 (Vault) |
| Intermediate CA private key | Critical | EC2-2 (Vault) |
| Replay cache (JTI entries) | Medium | EC2-2 (Redis) |
| User credentials | High | EC2-2 (Keycloak DB) |
| API data (mock) | Low | EC2-1 (Flask Backend) |

---

## STRIDE Analysis

### S — Spoofing

#### S1: Client Certificate Spoofing

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker presents a forged client certificate to impersonate a legitimate client |
| **Attack vector** | Generate self-signed cert, steal cert file, replay captured cert |
| **Impact** | High — unauthorized API access |
| **Mitigation** | Envoy `require_client_certificate: true`; cert verified against trusted CA chain (Intermediate CA); certificate must be signed by Vault PKI |
| **Residual risk** | **Low** — requires CA compromise or stolen private key |

#### S2: JWT Forgery

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker crafts a JWT with forged claims or signature |
| **Attack vector** | Use "none" algorithm, steal signing key, replay captured JWT |
| **Impact** | High — impersonate any user |
| **Mitigation** | ES256 signature verification via JWKS; algorithm whitelist (asymmetric only); `cnf.x5t#S256` binding ties token to cert |
| **Residual risk** | **Low** — signing key stored in Keycloak, not exportable |

#### S3: IdP Spoofing

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker runs rogue IdP to issue valid-looking JWTs |
| **Attack vector** | DNS poisoning, MITM on JWKS endpoint |
| **Impact** | High — issue tokens with arbitrary claims |
| **Mitigation** | Hardcoded trusted issuer URL in ext_authz; `iss` claim validation |
| **Residual risk** | **Medium** — JWKS fetch uses HTTP (internal network); recommend HTTPS in production |

---

### T — Tampering

#### T1: JWT Claim Tampering

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker modifies JWT claims (exp, scope, roles) |
| **Attack vector** | Modify JWT payload, change algorithm to "none", re-sign with own key |
| **Impact** | High — privilege escalation, extended token validity |
| **Mitigation** | ES256 signature verification; algorithm whitelist; `exp`/`nbf`/`iss`/`aud` validation |
| **Residual risk** | **Low** — signature invalidates on modification |

#### T2: Request Tampering in Transit

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker modifies HTTP request between Envoy and backend |
| **Attack vector** | MITM on internal network, compromised internal service |
| **Impact** | Medium — data manipulation |
| **Mitigation** | TLS encryption for all internal communication; ext_authz sets verified headers (`x-auth-user`) |
| **Residual risk** | **Low** in VPC; **Medium** if internal network breached |

---

### R — Repudiation

#### R1: Action Repudiation

| Attribute | Detail |
|-----------|--------|
| **Threat** | Authenticated client denies performing an API action |
| **Attack vector** | Claim token was stolen, cert was compromised, or system error |
| **Impact** | Low-Medium — no non-repudiation for audit |
| **Mitigation** | JWT contains `sub` (subject), `jti` (unique ID); client cert subject DN; structured request logging |
| **Residual risk** | **Medium** — no signed audit trail or blockchain-backed logs |

---

### I — Information Disclosure

#### I1: Token Interception

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker intercepts JWT in transit |
| **Attack vector** | Network sniffing, MITM, compromised proxy |
| **Impact** | Medium — attacker learns user identity and roles |
| **Mitigation** | TLS encryption for all external traffic; **token-cert binding** makes stolen token unusable without bound cert private key |
| **Residual risk** | **Low** — token useless without corresponding cert |

#### I2: JWKS / Public Key Exposure

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker accesses JWKS endpoint |
| **Attack vector** | Direct access to Keycloak JWKS URL |
| **Impact** | Low — public keys are non-secret by design |
| **Mitigation** | Keycloak in private subnet; JWKS contains only public keys |
| **Residual risk** | **None** — public keys are meant to be public |

#### I3: Certificate Private Key Disclosure

| Attribute | Detail |
|-----------|--------|
| **Threat** | Client or server private key is compromised |
| **Attack vector** | Stolen key file, memory dump, compromised host |
| **Impact** | High — full impersonation possible |
| **Mitigation** | Vault-managed PKI with short-lived certs (24h); intermediate CA for scoped issuance |
| **Residual risk** | **Medium** — no HSM; revocation via CRL not enforced at runtime |

---

### D — Denial of Service

#### D1: Resource Exhaustion

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker floods system with requests |
| **Attack vector** | High-volume valid requests, expensive JWKS lookups, large payloads |
| **Impact** | High — service unavailable |
| **Mitigation** | ext_authz per-identity rate limiting (optional, YAML policy); Envoy connection limits; upstream timeouts |
| **Residual risk** | **Medium** — rate limiting is optional and not enforced by default |

#### D2: Replay Cache Exhaustion

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker fills replay cache with unique JTIs to force eviction of legitimate entries |
| **Attack vector** | Request many tokens, each with unique `jti` |
| **Impact** | Medium — replay protection weakened |
| **Mitigation** | LRU eviction with bounded cache size; Redis TTL auto-expiry |
| **Residual risk** | **Low** — cache eviction is graceful |

---

### E — Elevation of Privilege

#### E1: Token Theft and Reuse

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker steals valid JWT and uses it from a different client |
| **Attack vector** | Intercept token, extract from logs, steal from client |
| **Impact** | High — unauthorized API access as victim user |
| **Mitigation** | **Token-certificate binding** (`cnf.x5t#S256`) ties JWT to a specific client certificate; stolen token rejected unless attacker also has the bound cert private key |
| **Residual risk** | **Low** — strongest mitigation; requires two-factor compromise |

#### E2: Replay Attack

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker captures a valid request and replays it |
| **Attack vector** | Network capture, re-send same JWT |
| **Impact** | Medium — repeated operations (data creation, state changes) |
| **Mitigation** | JTI tracking in replay cache; short token TTL (configurable); first-use semantics |
| **Residual risk** | **Low** — replay detected within cache window; DPoP adds per-request nonce |

#### E3: Privilege Escalation via Scope/Role Manipulation

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker accesses resources beyond authorized scope |
| **Attack vector** | Modify JWT scopes, request token with elevated scopes, access admin endpoints with user token |
| **Impact** | High — access sensitive admin data |
| **Mitigation** | JWT signature prevents tampering; ext_authz ABAC policy (YAML); backend enforces role checks (`/api/admin-data` requires `admin` role) |
| **Residual risk** | **Medium** — fine-grained route/action policy is optional |

---

## Threat Mitigation Mapping

| ID | Threat | STRIDE | Severity | Mitigation | Status |
|----|--------|--------|----------|------------|--------|
| S1 | Client cert spoofing | Spoofing | High | mTLS, CA chain verification | ✅ Implemented |
| S2 | JWT forgery | Spoofing | High | ES256 signature, JWKS, algorithm whitelist | ✅ Implemented |
| S3 | IdP spoofing | Spoofing | Medium | Hardcoded issuer, `iss` validation | ⚠️ Partial (HTTP) |
| T1 | JWT tampering | Tampering | High | Signature verification | ✅ Implemented |
| T2 | Request tampering | Tampering | Medium | Internal TLS, verified headers | ✅ Implemented |
| R1 | Action repudiation | Repudiation | Low | JWT `sub`/`jti`, structured logging | ⚠️ Partial |
| I1 | Token interception | Info Disclosure | Medium | TLS + token-cert binding | ✅ Implemented |
| I2 | JWKS exposure | Info Disclosure | Low | Public by design | ✅ Implemented |
| I3 | Key disclosure | Info Disclosure | High | Vault PKI, short-lived certs | ⚠️ Partial (no CRL) |
| D1 | Resource exhaustion | DoS | High | Rate limiting (optional), timeouts | ⚠️ Partial |
| D2 | Cache exhaustion | DoS | Medium | LRU eviction, Redis TTL | ✅ Implemented |
| E1 | Token theft | Elevation | High | `cnf.x5t#S256` cert binding | ✅ Implemented |
| E2 | Replay attack | Elevation | Medium | JTI cache, short TTL | ✅ Implemented |
| E3 | Privilege escalation | Elevation | High | ABAC policy, backend role checks | ⚠️ Partial |

---

## Risk Summary

| Risk Category | Rating | Key Concern |
|---------------|--------|-------------|
| Spoofing | **Low** | mTLS + JWT signing + cert binding provide strong identity verification |
| Tampering | **Low** | Signature verification covers JWT; TLS protects in transit |
| Repudiation | **Medium** | Basic audit logging without cryptographic proof |
| Information Disclosure | **Low** | TLS everywhere; stolen tokens bound to certs |
| Denial of Service | **Medium** | Rate limiting optional; basic resource controls in place |
| Elevation of Privilege | **Low** | Cert binding + JWT verify + role checks in depth |

---

## Recommendations

### Production Hardening

1. **Enforce CRL/OCSP checking** — configure Envoy or ext_authz to check certificate revocation status on every request
2. **Enable HTTPS for JWKS fetch** — serve Keycloak over TLS with a trusted certificate
3. **Make rate limiting mandatory** — tune and enable per-identity rate limits in ext_authz YAML policy
4. **Deploy Redis replay cache** — replace in-memory cache with Redis for multi-instance ext_authz
5. **Implement structured audit logging** — log all auth decisions (allow/deny) with client identity, resource, and timestamp
6. **Use short-lived certificates** — 24-hour validity with automated Vault renewal (compared to current 730h)
7. **Add DPoP for per-request binding** — extend from current mock to native DPoP with real key rotation
8. **Deploy WAF** — front Envoy with AWS WAF or similar for application-layer attack detection
