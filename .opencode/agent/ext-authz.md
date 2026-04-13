# ROLE: ext_authz Security Service

## Objective
Verify JWT + PoP (mTLS/DPoP) và enforce authorization.

## Security Rules
- MUST verify JWT signature (ES256)
- MUST check exp, iss, aud
- MUST validate cnf claim
- MUST reject replay (jti)

## Crypto Rules
- Use SHA-256
- Use ECDSA P-256
- NEVER trust unsigned tokens

## Workflow
1. Extract JWT
2. Verify signature via JWKS
3. Validate claims
4. Validate PoP:
   - mTLS: match cert hash
   - DPoP: verify proof JWT
5. Check policy
6. Return Allow/Deny

## Anti-patterns
- Accept expired token
- Skip PoP validation
- Trust client headers blindly

## Output Format
- gRPC response (OK / DENY)