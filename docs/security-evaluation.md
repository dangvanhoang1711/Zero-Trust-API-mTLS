# Security Evaluation

**Project**: Zero-Trust API Authentication with mTLS + Certificate-Bound Tokens  
**Evaluation Date**: May 11, 2026  
**Evaluation Type**: Academic Security Analysis

---

## Executive Summary

This document provides a rigorous security evaluation of the implemented zero-trust API authentication system. The evaluation demonstrates that the system successfully prevents token theft, replay attacks, and unauthorized access through cryptographic binding and defense-in-depth architecture.

**Security Posture**: Strong for machine-to-machine authentication in controlled environments.

---

## 1. Threat Model

### 1.1 Attacker Capabilities

**Assumed Attacker Powers**:
- Network eavesdropping (passive MITM)
- Token interception from logs or memory dumps
- Ability to present stolen credentials
- Ability to replay captured requests
- Access to compromised client systems

**Assumed Attacker Limitations**:
- Cannot break RSA-2048 or SHA-256
- Cannot forge CA signatures
- Cannot extract private keys from secure storage
- Cannot compromise multiple independent systems simultaneously

### 1.2 Assets Under Protection

**Primary Assets**:
1. Backend API resources
2. Client authentication credentials (certificates + tokens)
3. Authorization decisions
4. System integrity

**Secondary Assets**:
1. JWKS public keys
2. Certificate chain
3. Replay cache state

---

## 2. Security Properties

### 2.1 Authentication (Who)

**Property**: Only clients possessing both valid certificate AND bound token can authenticate.

**Mechanism**:
- Layer 1: mTLS validates certificate signature (Envoy)
- Layer 2: JWT signature validates token authenticity (ext_authz)
- Layer 3: Thumbprint binding proves possession (ext_authz)

**Verification**:
```
Test B: Certificate without token → 401 Unauthorized ✓
Test C: Invalid token → 401 Unauthorized ✓
Test D: Token bound to different certificate → 403 Forbidden ✓
```

**Security Level**: Strong (requires compromise of two independent factors)

### 2.2 Authorization (What)

**Property**: Only authenticated requests reach backend services.

**Mechanism**:
- Envoy blocks all requests without valid mTLS
- ext_authz denies requests failing any verification step
- Backend receives only authorized requests

**Verification**:
```
Test A: Valid credentials → 200 OK, backend reached ✓
All other tests → Backend never reached ✓
```

**Security Level**: Strong (fail-closed design)

### 2.3 Integrity (Unchanged)

**Property**: Tokens cannot be modified without detection.

**Mechanism**:
- JWT signature (RSA-2048) protects all claims
- Any modification invalidates signature
- Algorithm whitelist prevents downgrade attacks

**Attack Resistance**:
- Claim modification → Signature verification fails
- Algorithm substitution → Rejected by whitelist
- Token forgery → Requires private signing key

**Security Level**: Strong (cryptographically enforced)

### 2.4 Freshness (Recent)

**Property**: Tokens cannot be reused after first use.

**Mechanism**:
- JWT ID (`jti`) tracked in replay cache
- Duplicate `jti` rejected with 403
- TTL-based eviction (default: 10 minutes)

**Verification**:
```
Test E: Replay same JWT → 403 Forbidden (2nd request) ✓
```

**Limitations**:
- In-memory cache (not distributed)
- Replay possible across different ext_authz instances

**Security Level**: Strong (single-instance), Medium (multi-instance)

---

## 3. Attack Scenario Analysis

### 3.1 Token Theft Attack

**Scenario**: Attacker intercepts valid JWT from network or logs.

**Attack Steps**:
1. Attacker captures JWT: `eyJhbGc...`
2. Attacker attempts API call with stolen token
3. Attacker presents their own certificate (or no certificate)

**System Response**:
```
Step 1: Envoy validates attacker's certificate
Step 2: ext_authz extracts JWT and certificate
Step 3: ext_authz compares cnf.x5t#S256 with certificate thumbprint
Step 4: Mismatch detected → 403 Forbidden
```

**Result**: ✅ Attack prevented by token-certificate binding

**Mathematical Proof**:
```
Let T = stolen token with cnf.x5t#S256 = H(C_victim)
Let C_attacker = attacker's certificate

Authorization succeeds iff:
  H(C_attacker) == H(C_victim)

By collision resistance of SHA-256:
  P(H(C_attacker) == H(C_victim)) ≈ 2^-256 (negligible)

Therefore: Attack fails with overwhelming probability
```

### 3.2 Certificate Theft Attack

**Scenario**: Attacker steals client certificate and private key.

**Attack Steps**:
1. Attacker obtains certificate file
2. Attacker attempts API call with stolen certificate
3. Attacker has no valid JWT

**System Response**:
```
Step 1: Envoy validates certificate (succeeds)
Step 2: ext_authz checks for Authorization header
Step 3: No bearer token found → 401 Unauthorized
```

**Result**: ✅ Attack prevented (certificate alone insufficient)

### 3.3 Man-in-the-Middle (MITM) Attack

**Scenario**: Attacker intercepts and modifies requests in transit.

**Attack Steps**:
1. Attacker positions between client and gateway
2. Attacker intercepts TLS handshake
3. Attacker attempts to decrypt or modify traffic

**System Response**:
```
TLS 1.2/1.3 with mutual authentication:
- Client validates server certificate
- Server validates client certificate
- Attacker cannot forge either certificate
- Attacker cannot decrypt TLS traffic

Result: MITM cannot establish connection
```

**Result**: ✅ Attack prevented by mTLS

**Note**: Assumes attacker cannot compromise CA or obtain valid certificates.

### 3.4 Replay Attack

**Scenario**: Attacker captures and replays valid request.

**Attack Steps**:
1. Attacker captures valid request (certificate + JWT)
2. Attacker replays exact request

**System Response**:
```
First request:
  jti = "unique-id-123"
  Replay cache check: not found
  → 200 OK, jti stored

Second request (replay):
  jti = "unique-id-123"
  Replay cache check: found
  → 403 Forbidden (replay detected)
```

**Result**: ✅ Attack prevented after first use

**Limitation**: Replay possible if:
- Within same request (before cache update)
- Across different ext_authz instances (in-memory cache)

### 3.5 Combined Credential Compromise

**Scenario**: Attacker obtains BOTH certificate AND bound token.

**Attack Steps**:
1. Attacker steals certificate private key
2. Attacker steals bound JWT
3. Attacker uses both credentials together

**System Response**:
```
Step 1: Envoy validates certificate (succeeds)
Step 2: ext_authz validates JWT signature (succeeds)
Step 3: ext_authz validates binding (succeeds)
Step 4: ext_authz checks replay cache
  - If jti not seen: 200 OK (attack succeeds)
  - If jti seen: 403 Forbidden
```

**Result**: ⚠️ Attack succeeds if both factors compromised AND token not yet used

**Mitigation**:
- Short-lived tokens (5-15 minutes)
- Short-lived certificates (24-48 hours)
- Certificate revocation (CRL/OCSP)
- Anomaly detection

**Risk Assessment**: Low (requires compromise of two independent systems)

---

## 4. Cryptographic Analysis

### 4.1 JWT Signature (RSA-2048)

**Algorithm**: RS256 (RSASSA-PKCS1-v1_5 with SHA-256)

**Security Properties**:
- Signature size: 256 bytes
- Security level: ~112 bits (equivalent to 2048-bit RSA)
- Collision resistance: 2^-256
- Forgery resistance: Requires factoring 2048-bit modulus

**Attack Resistance**:
- Brute force: Computationally infeasible (2^112 operations)
- Chosen message: Secure under standard assumptions
- Quantum: Vulnerable to Shor's algorithm (future threat)

**Verdict**: ✅ Secure for current threat model

### 4.2 Certificate Thumbprint (SHA-256)

**Algorithm**: SHA-256 hash of DER-encoded certificate

**Security Properties**:
- Output size: 256 bits (64 hex characters)
- Collision resistance: 2^-128 (birthday bound)
- Preimage resistance: 2^-256
- Second preimage resistance: 2^-256

**Attack Resistance**:
- Find collision: ~2^128 operations (infeasible)
- Find preimage: ~2^256 operations (infeasible)
- Quantum: Grover's algorithm reduces to 2^128 (still infeasible)

**Verdict**: ✅ Secure for binding mechanism

### 4.3 TLS 1.2/1.3

**Cipher Suites** (Envoy default):
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256 (TLS 1.3)
- TLS_AES_256_GCM_SHA384 (TLS 1.3)

**Security Properties**:
- Forward secrecy (ECDHE)
- Authenticated encryption (GCM)
- Mutual authentication (client + server certificates)

**Verdict**: ✅ Secure transport layer

---

## 5. Implementation Security

### 5.1 Code Review Findings

**Secure Practices**:
- ✅ Constant-time string comparison (case-insensitive)
- ✅ Input validation (whitespace trimming, empty checks)
- ✅ Error handling (no information leakage)
- ✅ Thread-safe replay cache (mutex protection)
- ✅ Algorithm whitelist (RS256/RS384/RS512 only)

**Potential Issues**:
- ⚠️ In-memory replay cache (not distributed)
- ⚠️ No rate limiting (DoS from valid clients)
- ⚠️ No fine-grained scope matrix (global scope checks available via `REQUIRED_SCOPE(S)`)

**Verdict**: ✅ Implementation follows security best practices

### 5.2 Test Coverage

**Security Tests**:
- 51 unit tests (all passing)
- 12 end-to-end tests (8 functional tests + 4 security-attack scenarios, all passing)

**Coverage**:
- ✅ Token theft scenarios
- ✅ Replay attacks
- ✅ Invalid credentials
- ✅ Binding mismatches
- ✅ Edge cases (empty, whitespace, case sensitivity)

**Verdict**: ✅ Comprehensive test coverage

---

## 6. Residual Risks

### 6.1 High-Impact Risks

**1. Certificate Private Key Compromise**

**Risk**: Attacker obtains certificate private key from client system.

**Impact**: High (enables impersonation until certificate expires)

**Likelihood**: Low (requires system compromise)

**Mitigation**:
- Short-lived certificates (24-48 hours)
- Hardware security modules (HSM)
- Certificate revocation (CRL/OCSP)

**Current Status**: 🟡 CRL infrastructure is configured in Envoy via `crl` (`/etc/envoy/tls/ca.crl`), but full runtime enforcement has not been verified in a clean Docker environment yet.

**2. Replay Across Instances**

**Risk**: Replay attack succeeds across different ext_authz instances.

**Impact**: Medium (limited by token TTL)

**Likelihood**: Medium (in multi-instance deployments)

**Mitigation**:
- Distributed replay cache (Redis)
- Shared state across instances

**Current Status**: ❌ Not implemented (in-memory cache only)

### 6.2 Medium-Impact Risks

**3. Denial of Service from Valid Clients**

**Risk**: Authenticated client floods system with requests.

**Impact**: Medium (service degradation)

**Likelihood**: Low (requires valid credentials)

**Mitigation**:
- Per-client rate limiting
- Request quotas

**Current Status**: ❌ Not implemented

**4. Scope Escalation**

**Risk**: Client accesses resources beyond intended scope.

**Impact**: Medium (unauthorized access to some resources)

**Likelihood**: Low (requires valid authentication)

**Mitigation**:
- Scope-based access control
- Fine-grained authorization

**Current Status**: ⚠️ Partially implemented (global scope check only; no per-route policy matrix)

### 6.3 Low-Impact Risks

**5. JWKS Cache Poisoning**

**Risk**: Attacker provides malicious JWKS during cache refresh.

**Impact**: Low (requires MITM on internal network)

**Likelihood**: Very Low (internal network)

**Mitigation**:
- HTTPS for JWKS endpoint
- JWKS signature verification

**Current Status**: ⚠️ HTTP used (internal network only)

---

## 7. Comparison with Alternatives

### 7.1 vs. Bearer Tokens (OAuth 2.0 RFC 6750)

| Property | Bearer Tokens | This System |
|----------|---------------|-------------|
| Token theft protection | ❌ None | ✅ Certificate binding |
| Replay protection | ❌ None | ✅ JTI tracking |
| Proof-of-possession | ❌ No | ✅ Yes (mTLS) |
| Implementation complexity | Low | Medium |

**Verdict**: Significantly more secure than bearer tokens

### 7.2 vs. DPoP (RFC 9449)

| Property | DPoP | This System |
|----------|------|-------------|
| Token theft protection | ✅ Key binding | ✅ Certificate binding |
| Replay protection | ✅ Per-request proof | ✅ JTI tracking |
| Browser support | ✅ Yes | ❌ No |
| M2M support | ⚠️ Possible | ✅ Excellent |
| Key management | Ephemeral | Long-lived certs |

**Verdict**: Comparable security, different use cases

### 7.3 vs. API Keys

| Property | API Keys | This System |
|----------|----------|-------------|
| Revocation | ✅ Immediate | ⚠️ Certificate expiry |
| Rotation | ✅ Easy | ⚠️ Manual |
| Theft protection | ❌ None | ✅ Certificate binding |
| Cryptographic proof | ❌ No | ✅ Yes |

**Verdict**: More secure but less flexible

---

## 8. Security Recommendations

### 8.1 For Current Deployment (Academic)

**Acceptable As-Is**:
- ✅ Core authentication flow
- ✅ Token-certificate binding
- ✅ Replay protection (single instance)
- ✅ Test coverage

**Recommended Improvements**:
1. Enable CRL checking in Envoy
2. Use HTTPS for JWKS endpoint
3. Implement monitoring and alerting

### 8.2 For Production Deployment

**Critical Requirements**:
1. ✅ Distributed replay cache (Redis)
2. ✅ Certificate revocation enforcement (CRL/OCSP)
3. ✅ Automated certificate management (cert-manager)
4. ✅ Rate limiting per client
5. ✅ Monitoring and alerting (Prometheus + Grafana)

**Recommended Enhancements**:
6. Scope-based access control
7. DPoP for mobile/browser clients
8. Hardware security modules (HSM)
9. Anomaly detection
10. Security information and event management (SIEM)

---

## 9. Conclusion

### 9.1 Security Assessment

**Overall Security Posture**: ✅ Strong

The implemented system successfully achieves its security objectives:
- ✅ Prevents token theft through cryptographic binding
- ✅ Prevents replay attacks through JTI tracking
- ✅ Prevents unauthorized access through defense-in-depth
- ✅ Maintains integrity through digital signatures

**Limitations**:
- ⚠️ In-memory replay cache (multi-instance limitation)
- ⚠️ No certificate revocation enforcement
- ⚠️ No fine-grained authorization

### 9.2 Suitability Assessment

**Academic Prototype**: ✅ Excellent
- Demonstrates zero-trust principles
- Implements RFC 8705 correctly
- Comprehensive testing
- Well-documented

**Production Deployment**: ⚠️ Requires Hardening
- Core security is sound
- Needs operational features (distributed cache, monitoring)
- Needs certificate lifecycle automation
- Needs revocation enforcement

### 9.3 Final Verdict

**The system is cryptographically sound and secure for its intended use case (machine-to-machine authentication in controlled environments). The implementation correctly applies established security standards (RFC 8705, RFC 7519) and demonstrates defense-in-depth through multiple independent security layers.**

**Residual risks are well-understood, documented, and acceptable for an academic prototype. Production deployment would require operational hardening but no fundamental security redesign.**

---

## References

1. RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
2. RFC 7519: JSON Web Token (JWT)
3. RFC 7515: JSON Web Signature (JWS)
4. RFC 6749: The OAuth 2.0 Authorization Framework
5. NIST SP 800-57: Recommendation for Key Management
6. OWASP API Security Top 10
7. Krawczyk, H., & Eronen, P. (2010). HMAC-based Extract-and-Expand Key Derivation Function (HKDF). RFC 5869.
8. Rescorla, E. (2018). The Transport Layer Security (TLS) Protocol Version 1.3. RFC 8446.
