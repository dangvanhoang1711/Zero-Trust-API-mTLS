# Threat Model

## Overview

This document analyzes security threats to the Zero-Trust API Authentication system using the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

## System Architecture

```
┌─────────┐         ┌───────────────┐         ┌────────────┐         ┌─────────┐
│ Client  │────────▶│ Envoy Proxy   │────────▶│ ext_authz  │────────▶│ Backend │
│ (mTLS)  │  HTTPS  │ (mTLS + TLS)  │  gRPC   │ (Go)       │  HTTP   │ Service │
└─────────┘         └───────────────┘         └────────────┘         └─────────┘
     │                      │                        │
     │                      │                        │
     └──────────────────────┴────────────────────────┴──────────────┐
                                                                     │
                                                              ┌──────▼──────┐
                                                              │  Keycloak   │
                                                              │  (IdP)      │
                                                              └─────────────┘
```

## Trust Boundaries

1. **External → Envoy**: Untrusted clients attempt to access protected APIs
2. **Envoy → ext_authz**: Trusted internal communication (gRPC)
3. **ext_authz → Keycloak**: Trusted internal communication (JWKS fetch)
4. **ext_authz → Backend**: Trusted internal communication (authorized requests only)

## Assets

1. **Protected APIs**: Backend services requiring authentication and authorization
2. **Client certificates**: Private keys proving client identity
3. **Access tokens (JWTs)**: Bearer tokens granting API access
4. **JWKS**: Public keys for JWT signature verification
5. **Replay cache**: State tracking used tokens
6. **TLS private keys**: Server and client private keys

## STRIDE Analysis

### S — Spoofing Identity

#### Threat S1: Client Identity Spoofing

**Description**: Attacker attempts to impersonate a legitimate client without possessing valid credentials.

**Attack vectors**:
- Present forged or stolen certificate
- Present no certificate and bypass mTLS
- Use stolen JWT without bound certificate

**Mitigations**:
- ✅ Envoy enforces mTLS with `require_client_certificate: true`
- ✅ Certificates must be signed by trusted CA
- ✅ JWT signature verification using JWKS
- ✅ Token-certificate binding via `cnf.x5t#S256`

**Residual risk**: Low. Requires compromise of both certificate private key and bound JWT.

**Test coverage**: Test B (no cert), Test C (invalid token), Test D (binding mismatch)

#### Threat S2: IdP Spoofing

**Description**: Attacker sets up rogue identity provider to issue fraudulent tokens.

**Attack vectors**:
- DNS poisoning to redirect JWKS fetch
- Man-in-the-middle attack on JWKS endpoint

**Mitigations**:
- ✅ JWT issuer (`iss`) claim validation
- ✅ Hardcoded trusted issuer URL in ext_authz configuration
- ⚠️ JWKS fetch over HTTP (internal network only)

**Residual risk**: Medium. JWKS fetch should use HTTPS in production.

**Recommendation**: Use HTTPS for Keycloak in production deployments.

### T — Tampering

#### Threat T1: JWT Tampering

**Description**: Attacker modifies JWT claims to escalate privileges or extend validity.

**Attack vectors**:
- Modify `exp`, `aud`, `sub`, or `cnf` claims
- Change signature algorithm to `none`
- Re-sign token with attacker's key

**Mitigations**:
- ✅ JWT signature verification using RS256/RS384/RS512
- ✅ Algorithm whitelist (asymmetric only)
- ✅ Standard claim validation (`exp`, `nbf`, `iss`, `aud`)

**Residual risk**: Low. Tampering invalidates signature.

**Test coverage**: Test C (invalid token)

#### Threat T2: Request Tampering

**Description**: Attacker modifies HTTP request after authorization check.

**Attack vectors**:
- MITM between Envoy and backend
- Compromise of backend service

**Mitigations**:
- ✅ TLS encryption for all communication
- ⚠️ Internal traffic (Envoy → backend) not encrypted in current setup

**Residual risk**: Low in trusted network. Medium if internal network is compromised.

**Recommendation**: Use TLS for internal service-to-service communication in production.

### R — Repudiation

#### Threat R1: Action Repudiation

**Description**: Authenticated client denies performing an action.

**Attack vectors**:
- Client claims token was stolen
- Client claims certificate was compromised

**Mitigations**:
- ⚠️ Basic logging only (no structured audit trail)
- ✅ JWT contains `sub` (subject) and `jti` (unique ID)
- ✅ Client certificate contains subject DN

**Residual risk**: Medium. Insufficient audit logging.

**Recommendation**: Implement structured audit logging with:
- Request timestamp
- Client certificate subject
- JWT subject and `jti`
- Requested resource and method
- Authorization decision

### I — Information Disclosure

#### Threat I1: Token Interception

**Description**: Attacker intercepts JWT in transit.

**Attack vectors**:
- Network sniffing
- MITM attack
- Compromised proxy or load balancer

**Mitigations**:
- ✅ TLS encryption for all external communication
- ✅ Token-certificate binding prevents use of stolen token

**Residual risk**: Low. Stolen token is useless without bound certificate private key.

**Test coverage**: Test D (binding mismatch simulates token theft)

#### Threat I2: JWKS Exposure

**Description**: Attacker gains access to JWKS endpoint.

**Attack vectors**:
- Public exposure of Keycloak endpoint
- Unauthorized access to internal network

**Mitigations**:
- ✅ JWKS contains only public keys (no secrets)
- ✅ Keycloak exposed only on internal network in production

**Residual risk**: Low. JWKS is public information by design.

#### Threat I3: Certificate Private Key Disclosure

**Description**: Client certificate private key is compromised.

**Attack vectors**:
- Stolen key file
- Memory dump
- Compromised client system

**Mitigations**:
- ⚠️ No hardware security module (HSM) or key management service
- ⚠️ Certificate revocation not enforced in active runtime

**Residual risk**: High. Compromised key allows full impersonation until certificate expiration.

**Recommendation**: 
- Implement CRL or OCSP checking in Envoy
- Use short-lived certificates (24-48 hours)
- Store keys in HSM or cloud KMS for production

### D — Denial of Service

#### Threat D1: Resource Exhaustion

**Description**: Attacker floods system with requests to exhaust resources.

**Attack vectors**:
- High volume of valid requests
- High volume of invalid requests triggering expensive validation
- JWKS cache poisoning

**Mitigations**:
- ⚠️ No rate limiting implemented
- ⚠️ No request size limits
- ⚠️ Replay cache unbounded growth

**Residual risk**: High. System vulnerable to DoS from authenticated clients.

**Recommendation**:
- Implement per-client rate limiting
- Set replay cache max size with LRU eviction
- Add request timeout and size limits

#### Threat D2: Replay Cache Exhaustion

**Description**: Attacker generates many unique JWTs to fill replay cache.

**Attack vectors**:
- Request many tokens from IdP
- Generate unique `jti` for each request

**Mitigations**:
- ✅ Replay cache entries expire after TTL
- ✅ Max cache size is bounded and evicts oldest entries when full

**Residual risk**: Reduced. Cache can still fill to configured max before eviction; tune `REPLAY_CACHE_MAX_ENTRIES`.

**Recommendation**: Keep `REPLAY_CACHE_MAX_ENTRIES` tuned for your traffic profile and move to Redis for multi-instance deployments.

### E — Elevation of Privilege

#### Threat E1: Token Theft and Reuse

**Description**: Attacker steals valid JWT and uses it to access APIs.

**Attack vectors**:
- Intercept token in transit
- Extract token from logs or memory
- Steal token from compromised client

**Mitigations**:
- ✅ Token-certificate binding via `cnf.x5t#S256`
- ✅ Stolen token cannot be used without bound certificate private key

**Residual risk**: Low. Strongest mitigation in the system.

**Test coverage**: Test D (binding mismatch)

#### Threat E2: Replay Attack

**Description**: Attacker captures and replays valid request.

**Attack vectors**:
- Network capture of valid request
- Replay same JWT multiple times

**Mitigations**:
- ✅ Replay protection via `jti` tracking
- ✅ Short JWT expiration (configurable)

**Residual risk**: Low within replay window. Medium across ext_authz instances.

**Test coverage**: Test E (replay attack)

**Recommendation**: Use distributed replay cache (Redis) for multi-instance deployments.

#### Threat E3: Privilege Escalation via Scope Manipulation

**Description**: Attacker modifies JWT scopes to gain unauthorized access.

**Attack vectors**:
- Tamper with `scope` claim in JWT
- Request token with elevated scopes

**Mitigations**:
- ✅ JWT signature prevents tampering
- ✅ Global scope enforcement in ext_authz via `REQUIRED_SCOPE(S)`

**Residual risk**: Medium. Fine-grained route/action policy still requires backend or policy engine.

**Recommendation**: Extend ext_authz to support route/verb specific scope mapping.

## Attack Scenarios

### Scenario 1: Stolen Token Attack

**Attacker goal**: Use stolen JWT to access protected API.

**Attack steps**:
1. Attacker intercepts valid JWT (e.g., from logs, network capture)
2. Attacker attempts to use JWT with their own certificate

**System response**:
- Envoy accepts attacker's certificate (if signed by trusted CA)
- ext_authz extracts JWT and certificate
- ext_authz compares `cnf.x5t#S256` with certificate thumbprint
- Mismatch detected → `403 Forbidden`

**Outcome**: ✅ Attack prevented by token-certificate binding.

**Test coverage**: Test D

### Scenario 2: Certificate Compromise

**Attacker goal**: Use stolen certificate to access protected API.

**Attack steps**:
1. Attacker steals client certificate and private key
2. Attacker attempts to use certificate without valid JWT

**System response**:
- Envoy accepts certificate (valid signature)
- ext_authz checks for bearer token
- No token present → `401 Unauthorized`

**Outcome**: ✅ Attack prevented. Certificate alone is insufficient.

**Test coverage**: Test B

### Scenario 3: Combined Credential Compromise

**Attacker goal**: Use stolen certificate AND bound JWT.

**Attack steps**:
1. Attacker steals both certificate private key and bound JWT
2. Attacker uses both credentials together

**System response**:
- Envoy accepts certificate
- ext_authz validates JWT signature
- ext_authz validates token-certificate binding
- ext_authz checks replay cache
- If `jti` not seen before → `200 OK`

**Outcome**: ⚠️ Attack succeeds if both credentials are compromised.

**Mitigation**: This is the strongest attack requiring compromise of both factors. Additional mitigations:
- Short-lived certificates (reduce exposure window)
- Certificate revocation (CRL/OCSP)
- Anomaly detection (unusual access patterns)

### Scenario 4: Replay Attack

**Attacker goal**: Reuse captured valid request.

**Attack steps**:
1. Attacker captures valid request with JWT
2. Attacker replays request multiple times

**System response**:
- First request: `jti` not in cache → `200 OK`, `jti` stored
- Subsequent requests: `jti` found in cache → `403 Forbidden`

**Outcome**: ✅ Attack prevented after first use.

**Test coverage**: Test E

## Risk Summary

| Threat | Severity | Likelihood | Mitigation Status | Residual Risk |
|--------|----------|------------|-------------------|---------------|
| Client spoofing | High | Low | ✅ Implemented | Low |
| IdP spoofing | High | Low | ⚠️ Partial | Medium |
| JWT tampering | High | Low | ✅ Implemented | Low |
| Token theft | High | Medium | ✅ Implemented | Low |
| Certificate compromise | High | Low | ⚠️ Partial | Medium |
| Replay attack | Medium | Medium | ✅ Implemented | Low |
| DoS | Medium | High | ❌ Not implemented | High |
| Privilege escalation | Medium | Low | ⚠️ Partial | Medium |
| Information disclosure | Low | Low | ✅ Implemented | Low |
| Repudiation | Low | Low | ⚠️ Partial | Medium |

## Recommendations for Production

### High Priority

1. **Enable certificate revocation checking** (CRL or OCSP in Envoy)
2. **Implement rate limiting** per client identity
3. **Use HTTPS for JWKS fetch** from Keycloak
4. **Deploy distributed replay cache** (Redis) for multi-instance setups
5. **Implement structured audit logging**

### Medium Priority

6. **Add scope-based access control** in ext_authz
7. **Use short-lived certificates** (24-48 hours) with automated renewal
8. **Implement request size and timeout limits**
9. **Tune `REPLAY_CACHE_MAX_ENTRIES`** and monitor eviction metrics
10. **Enable TLS for internal service communication**

### Low Priority

11. **Integrate HSM or cloud KMS** for key storage
12. **Implement anomaly detection** for unusual access patterns
13. **Add OpenTelemetry tracing** for security event correlation
14. **Deploy Web Application Firewall** (WAF) in front of Envoy

## Conclusion

The implemented zero-trust architecture provides strong protection against common API security threats through defense-in-depth:

1. **Network layer**: mTLS prevents unauthorized connections
2. **Application layer**: JWT signature verification prevents token forgery
3. **Binding layer**: Token-certificate binding prevents credential theft
4. **Replay layer**: `jti` tracking prevents replay attacks

The most significant residual risks are:
- Certificate compromise without revocation checking
- DoS attacks due to lack of rate limiting
- Scope-based privilege escalation without policy enforcement

These risks are acceptable for the demonstrated use case but should be addressed before production deployment.
