# Attack Scenarios and Countermeasures

**Document Type**: Security Analysis  
**Purpose**: Demonstrate system resilience through concrete attack scenarios  
**Audience**: Security reviewers and academic evaluators

---

## Overview

This document presents detailed attack scenarios against the zero-trust API authentication system, demonstrating how the defense-in-depth architecture prevents each attack vector. Each scenario includes attack steps, system response, and mathematical/cryptographic justification.

---

## Scenario 1: Token Theft via Network Eavesdropping

### Attack Description

**Attacker Goal**: Gain unauthorized API access by intercepting JWT tokens.

**Attacker Capabilities**:
- Passive network monitoring
- Ability to capture TLS-encrypted traffic
- Access to network logs

### Attack Execution

**Step 1**: Attacker positions network sniffer
```
Attacker → [Network Tap] → Client ↔ Gateway
```

**Step 2**: Attacker captures encrypted TLS traffic
```
Captured: TLS 1.3 encrypted packets containing:
- Client certificate (public)
- JWT token (encrypted in TLS)
```

**Step 3**: Attacker attempts TLS decryption
```
Attack vector: Break TLS encryption
Required: Private key of client or server
Result: FAIL (attacker has neither private key)
```

**Step 4**: Attacker assumes token leaked via logs
```
Stolen token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Contains: cnf.x5t#S256 = "5238b8ba24419fd472ecebe18010e0d2..."
```

**Step 5**: Attacker attempts API call with stolen token
```bash
curl -H "Authorization: Bearer <stolen-token>" \
     --cert attacker-cert.crt --key attacker-key.key \
     https://api.example.com/resource
```

### System Response

**Defense Layer 1**: Envoy validates attacker's certificate
```
✓ Certificate signature valid (signed by CA)
✓ Certificate not expired
→ TLS handshake succeeds
```

**Defense Layer 2**: ext_authz validates JWT
```
✓ JWT signature valid (signed by Keycloak)
✓ Claims valid (iss, aud, exp, sub)
→ JWT verification succeeds
```

**Defense Layer 3**: ext_authz validates binding
```
Token thumbprint: 5238b8ba24419fd472ecebe18010e0d2...
Attacker cert thumbprint: SHA256(attacker-cert) = a1b2c3d4...

Comparison: 5238b8ba... ≠ a1b2c3d4...
→ BINDING MISMATCH
```

**Final Response**: `403 Forbidden - token not bound to presented certificate`

### Why Attack Fails

**Mathematical Proof**:
```
Let H = SHA-256 hash function
Let C_victim = victim's certificate
Let C_attacker = attacker's certificate

Token contains: cnf.x5t#S256 = H(C_victim)
Attacker presents: C_attacker

Authorization requires: H(C_attacker) == H(C_victim)

By collision resistance of SHA-256:
P(H(C_attacker) == H(C_victim) | C_attacker ≠ C_victim) ≈ 2^-256

Conclusion: Attack succeeds with negligible probability
```

**Countermeasure**: RFC 8705 certificate-bound tokens

---

## Scenario 2: Certificate Theft from Compromised System

### Attack Description

**Attacker Goal**: Impersonate legitimate client using stolen certificate.

**Attacker Capabilities**:
- Access to compromised client filesystem
- Ability to extract certificate and private key
- Network access to API gateway

### Attack Execution

**Step 1**: Attacker compromises client system
```
Attack vector: Malware, phishing, or insider threat
Result: Access to filesystem
```

**Step 2**: Attacker locates and extracts certificate
```bash
# Attacker finds certificate files
/etc/ssl/certs/client.crt
/etc/ssl/private/client.key

# Attacker copies files
scp client.crt client.key attacker-system:/tmp/
```

**Step 3**: Attacker attempts API call with stolen certificate
```bash
curl --cert /tmp/client.crt --key /tmp/client.key \
     https://api.example.com/resource
```

### System Response

**Defense Layer 1**: Envoy validates certificate
```
✓ Certificate signature valid
✓ Certificate not expired
✓ Certificate signed by trusted CA
→ TLS handshake succeeds
```

**Defense Layer 2**: ext_authz checks for JWT
```
Authorization header: (missing)
→ NO BEARER TOKEN FOUND
```

**Final Response**: `401 Unauthorized - missing bearer token`

### Why Attack Fails

**Security Property**: Certificate alone is insufficient for authentication.

**Required Factors**:
1. Valid certificate + private key (attacker has)
2. Valid JWT bound to certificate (attacker lacks)

**Token Acquisition Barrier**:
```
To obtain valid JWT, attacker must:
1. Know client_id and client_secret (stored separately)
2. Authenticate to Keycloak
3. Present same certificate during token request
4. Receive JWT with matching cnf.x5t#S256

Even if attacker obtains token:
- Token expires (5-15 minutes)
- Token can only be used once (replay protection)
```

**Countermeasure**: Two-factor authentication (certificate + token)

---

## Scenario 3: Man-in-the-Middle Attack

### Attack Description

**Attacker Goal**: Intercept and modify API requests in transit.

**Attacker Capabilities**:
- Network position between client and gateway
- Ability to intercept and modify packets
- Cannot forge CA signatures

### Attack Execution

**Step 1**: Attacker positions MITM proxy
```
Client → [Attacker Proxy] → Gateway
```

**Step 2**: Client initiates TLS handshake
```
Client → ClientHello → Attacker
```

**Step 3**: Attacker attempts to impersonate gateway
```
Attacker → ServerHello + Server Certificate → Client

Server Certificate:
- Issued to: api.example.com
- Signed by: Attacker's CA (not trusted)
```

**Step 4**: Client validates server certificate
```
Certificate chain validation:
1. Check signature: Signed by unknown CA
2. Check trust store: CA not in trust store
→ CERTIFICATE VALIDATION FAILS
```

### System Response

**Client-Side Defense**: TLS certificate validation
```
Error: SSL certificate problem: unable to get local issuer certificate
Connection: REFUSED
```

**Alternative Attack**: Attacker uses valid certificate

If attacker somehow obtains valid server certificate:
```
Client → ClientCertificateRequest → Attacker
Attacker must present valid client certificate
→ Attacker lacks client private key
→ TLS handshake fails
```

### Why Attack Fails

**Mutual TLS Properties**:
1. Client validates server certificate (prevents server impersonation)
2. Server validates client certificate (prevents client impersonation)
3. Both validations must succeed for connection establishment

**Attack Requirements** (all must be satisfied):
- Forge CA signature (computationally infeasible)
- OR compromise CA private key (out of scope)
- OR compromise both client and server private keys (out of scope)

**Countermeasure**: Mutual TLS with certificate validation

---

## Scenario 4: Replay Attack

### Attack Description

**Attacker Goal**: Reuse captured valid request to gain unauthorized access.

**Attacker Capabilities**:
- Capture complete valid request (certificate + JWT)
- Replay request multiple times

### Attack Execution

**Step 1**: Attacker captures valid request
```http
GET /api/resource HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
[TLS client certificate: client.crt]
```

**Step 2**: Attacker extracts JWT
```json
{
  "iss": "http://keycloak:8080/realms/zero-trust",
  "sub": "demo-client",
  "aud": "api-gateway",
  "exp": 1715443200,
  "jti": "unique-id-12345",
  "cnf": {
    "x5t#S256": "5238b8ba24419fd472ecebe18010e0d2..."
  }
}
```

**Step 3**: Attacker replays request (1st time)
```bash
# First replay attempt
curl --cert client.crt --key client.key \
     -H "Authorization: Bearer <captured-token>" \
     https://api.example.com/resource
```

### System Response (First Replay)

**Defense Layer 1-3**: Pass (valid certificate + valid token + valid binding)

**Defense Layer 4**: Replay cache check
```
jti = "unique-id-12345"
Replay cache lookup: NOT FOUND
→ Store jti with timestamp
→ Allow request
```

**Response**: `200 OK` (first use succeeds)

**Step 4**: Attacker replays request (2nd time)
```bash
# Second replay attempt (same token)
curl --cert client.crt --key client.key \
     -H "Authorization: Bearer <captured-token>" \
     https://api.example.com/resource
```

### System Response (Second Replay)

**Defense Layer 4**: Replay cache check
```
jti = "unique-id-12345"
Replay cache lookup: FOUND (timestamp: 2 seconds ago)
→ REPLAY DETECTED
```

**Response**: `403 Forbidden - replay detected`

### Why Attack Fails (After First Use)

**Replay Protection Mechanism**:
```
Replay cache: Map[jti → timestamp]
TTL: 10 minutes (configurable)

On each request:
1. Extract jti from JWT
2. Check if jti exists in cache
3. If exists: DENY (replay)
4. If not exists: ALLOW and store jti
```

**Attack Window**:
- First use: Succeeds (by design)
- Subsequent uses: Fail (replay detected)
- After TTL expiry: Token expired anyway (exp claim)

**Limitation**: In-memory cache (single instance only)

**Countermeasure**: JWT ID tracking with TTL-based eviction

---

## Scenario 5: Token Forgery

### Attack Description

**Attacker Goal**: Create fake JWT to bypass authentication.

**Attacker Capabilities**:
- Knowledge of JWT structure
- Ability to create and sign JWTs
- Access to public JWKS endpoint

### Attack Execution

**Step 1**: Attacker crafts malicious JWT
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "keycloak-key-id"
}
{
  "iss": "http://keycloak:8080/realms/zero-trust",
  "sub": "attacker",
  "aud": "api-gateway",
  "exp": 9999999999,
  "jti": "attacker-jti",
  "cnf": {
    "x5t#S256": "<attacker-cert-thumbprint>"
  }
}
```

**Step 2**: Attacker signs with own private key
```
Signature = RSA-Sign(Header + Payload, attacker_private_key)
Forged JWT = Base64(Header).Base64(Payload).Base64(Signature)
```

**Step 3**: Attacker attempts API call
```bash
curl --cert attacker.crt --key attacker.key \
     -H "Authorization: Bearer <forged-token>" \
     https://api.example.com/resource
```

### System Response

**Defense Layer 1**: Envoy validates certificate (succeeds)

**Defense Layer 2**: ext_authz validates JWT signature
```
1. Extract kid from JWT header: "keycloak-key-id"
2. Fetch public key from JWKS cache
3. Verify signature: RSA-Verify(JWT, keycloak_public_key)
4. Result: SIGNATURE INVALID
   (JWT signed with attacker key, not Keycloak key)
```

**Response**: `401 Unauthorized - invalid token`

### Why Attack Fails

**Cryptographic Barrier**:
```
Valid signature requires:
  Signature = RSA-Sign(Message, keycloak_private_key)

Attacker has:
  - keycloak_public_key (from JWKS)
  - attacker_private_key

Attacker needs:
  - keycloak_private_key (unknown)

Attack succeeds iff:
  Attacker can forge RSA signature without private key
  → Requires breaking RSA-2048 (computationally infeasible)
```

**Alternative Attack**: Algorithm substitution
```
Attacker changes alg to "none" or "HS256"
→ Blocked by algorithm whitelist (RS256/RS384/RS512 only)
```

**Countermeasure**: RSA signature verification with algorithm whitelist

---

## Scenario 6: Combined Credential Compromise

### Attack Description

**Attacker Goal**: Use both stolen certificate AND stolen token together.

**Attacker Capabilities**:
- Compromised client system (certificate + private key)
- Intercepted or leaked JWT
- Both credentials match (same client)

### Attack Execution

**Step 1**: Attacker obtains both factors
```
Stolen certificate: client.crt + client.key
Stolen JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Binding: cnf.x5t#S256 matches certificate
```

**Step 2**: Attacker uses both credentials
```bash
curl --cert client.crt --key client.key \
     -H "Authorization: Bearer <stolen-token>" \
     https://api.example.com/resource
```

### System Response

**Defense Layer 1**: Envoy validates certificate ✓
**Defense Layer 2**: ext_authz validates JWT ✓
**Defense Layer 3**: ext_authz validates binding ✓
**Defense Layer 4**: Replay cache check

```
If jti not seen before:
  → 200 OK (ATTACK SUCCEEDS)

If jti already used:
  → 403 Forbidden (replay detected)
```

### Why Attack Can Succeed

**Security Analysis**:
```
This attack succeeds because:
1. Attacker has both required factors
2. Token not yet used (no replay)
3. Token not expired
4. Certificate not revoked

This is equivalent to:
  Attacker fully compromised client system
```

**Risk Assessment**: Acceptable

**Justification**:
- Requires compromise of TWO independent systems
- Limited time window (token TTL: 5-15 minutes)
- Single use only (replay protection)
- Detectable through monitoring

### Mitigations

**Preventive**:
1. Short-lived tokens (5-15 minutes)
2. Short-lived certificates (24-48 hours)
3. Hardware security modules (HSM) for key storage
4. Secure key management practices

**Detective**:
1. Anomaly detection (unusual access patterns)
2. Monitoring and alerting
3. Audit logging

**Responsive**:
1. Certificate revocation (CRL/OCSP)
2. Token revocation (if implemented)
3. Incident response procedures

**Countermeasure**: Defense-in-depth + operational security

---

## Summary Matrix

| Attack Scenario | Success | Countermeasure | Test Verification |
|----------------|---------|----------------|-------------------|
| Token theft | ❌ Fails | Certificate binding | Test D: 403 Forbidden |
| Certificate theft | ❌ Fails | Two-factor auth | Test B: 401 Unauthorized |
| MITM | ❌ Fails | Mutual TLS | TLS handshake validation |
| Replay (2nd use) | ❌ Fails | JTI tracking | Test E: 403 Forbidden |
| Token forgery | ❌ Fails | RSA signature | Test C: 401 Unauthorized |
| Combined compromise | ⚠️ Succeeds* | Operational security | N/A (acceptable risk) |

*Succeeds only if both factors compromised AND token not yet used

---

## Conclusion

The zero-trust API authentication system successfully prevents all single-factor attacks through defense-in-depth architecture. The only successful attack scenario requires compromise of multiple independent systems simultaneously, which is:

1. **Difficult**: Requires breaching two separate security boundaries
2. **Limited**: Constrained by short token TTL and single-use replay protection
3. **Detectable**: Leaves audit trail for incident response
4. **Acceptable**: Risk level appropriate for academic prototype

The system demonstrates strong security properties suitable for machine-to-machine authentication in controlled environments.
