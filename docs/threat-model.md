# Threat Model - Zero Trust API Gateway

## Scope

This document covers the current two-host AWS deployment:

- EC2-Envoy (`10.0.5.131`, `13.238.159.245`) runs Envoy, backend, and frontend
- EC2-Services (`10.0.2.27`, `3.106.196.141`) runs ext_authz, Keycloak, Vault, and Redis

The main security controls are TLS at the edge, certificate-bound JWT validation in `ext_authz`, route policy, and replay protection.

## Methodology

STRIDE:

- S: Spoofing
- T: Tampering
- R: Repudiation
- I: Information disclosure
- D: Denial of service
- E: Elevation of privilege

## Trust Boundaries

```text
Internet -> Envoy on EC2-Envoy -> ext_authz on EC2-Services -> Backend on EC2-Envoy
                                      |
                                      +-> Keycloak
                                      +-> Vault
                                      +-> Redis
```

| Boundary | Trust Level | Notes |
|----------|-------------|-------|
| Internet -> Envoy | Untrusted | Browser and API traffic arrive over public HTTPS |
| Envoy -> ext_authz | Trusted but verified | Internal TLS over private IP |
| ext_authz -> Keycloak | Trusted but verified | JWKS and issuer checks over HTTPS |
| ext_authz -> Redis / Vault | Trusted but verified | Internal service-to-service trust |

## Key Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Client certificate private keys | Critical | Client machine or secure operator workstation |
| Envoy and backend server private keys | Critical | EC2-Envoy |
| Keycloak signing keys | Critical | EC2-Services |
| Vault root and intermediate CA material | Critical | EC2-Services |
| Replay cache state | Medium | Redis on EC2-Services |
| User credentials and client secrets | High | Keycloak on EC2-Services |

## STRIDE Summary

### Spoofing

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Forged JWT | JWKS signature validation, issuer and audience checks | Low |
| Misbound token replayed from another client | `cnf.x5t#S256` certificate binding | Low |
| Rogue client certificate | Envoy trust chain validation plus thumbprint match in ext_authz | Low to medium if a client key is stolen |

### Tampering

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| JWT claim modification | Signature verification | Low |
| Request mutation in transit | TLS on public ingress and internal service hops | Low |
| Policy file drift | Version-controlled YAML policy plus tests | Medium if changes bypass review |

### Repudiation

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| User denies a protected request | Request logs include JWT subject, `jti`, and certificate subject when present | Medium because there is no signed audit trail |

### Information Disclosure

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Token interception | HTTPS plus certificate binding for cert-bound tokens | Low |
| Accidental exposure of service endpoints | EC2-Services uses private IPs for app traffic and should keep service ports closed by SG | Medium because the host still has a public IP |
| Private key compromise | Vault-issued short-lived certs and limited key distribution | Medium because there is no HSM or runtime CRL enforcement |

### Denial of Service

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Flooding Envoy or ext_authz | Envoy timeouts, optional policy limits, Docker restart policy | Medium |
| Replay cache exhaustion | Redis TTL plus bounded in-memory fallback | Low to medium |

### Elevation of Privilege

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Reuse of a valid token on another machine | Token thumbprint binding | Low |
| Replay of the same JWT | `jti` replay detection | Low |
| Access to an endpoint without the right role or route policy | ext_authz route policy plus backend checks | Medium if policy coverage is incomplete |

## Current Security Posture Notes

1. Browser access now enters through `https://13.238.159.245/` without mandatory TLS client-certificate negotiation on every route. Protected certificate-bound API flows are enforced at the authorization layer instead.
2. EC2-Services has a public IP. That is operationally convenient but increases the importance of strict security group rules.
3. Keycloak and JWKS traffic now run over HTTPS, which removes the previous plaintext internal-token-validation gap.
4. Replay protection is effective only if callers do not intentionally reuse the same JWT for multiple protected requests.

## Risk Summary

| Category | Rating | Main Concern |
|----------|--------|--------------|
| Spoofing | Low | Strong JWT verification and certificate binding |
| Tampering | Low | TLS and signature validation cover the main paths |
| Repudiation | Medium | Logging exists, but non-repudiation is limited |
| Information disclosure | Medium | Service host has a public IP and private CA certs require careful handling |
| Denial of service | Medium | No hard default rate-limiting at the edge |
| Elevation of privilege | Low to medium | Good defense-in-depth, but policy completeness still matters |

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
