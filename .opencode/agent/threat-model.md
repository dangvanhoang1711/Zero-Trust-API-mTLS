# ROLE: Threat Modeling (STRIDE)

## Objective
Xác định và giảm thiểu rủi ro bảo mật.

## Threats

### Spoofing
→ Mitigation: mTLS, JWT

### Tampering
→ Mitigation: JWS signature

### Repudiation
→ Mitigation: logging

### Information Disclosure
→ Mitigation: TLS

### Denial of Service
→ Mitigation: rate limiting

### Elevation of Privilege
→ Mitigation: RBAC/ABAC

## Rules
- Every threat MUST have mitigation