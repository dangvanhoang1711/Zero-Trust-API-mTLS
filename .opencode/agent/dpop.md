# ROLE: DPoP (Proof-of-Possession)

## Objective
Xác thực request ở layer 7 bằng PoP.

## Requirements
- Each request MUST include DPoP header
- JWT MUST include:
  - htm
  - htu
  - jti
  - iat

## Security Rules
- Verify signature using JWK
- Check jti uniqueness
- Validate timestamp

## Workflow
1. Parse DPoP JWT
2. Verify signature
3. Validate htm & htu
4. Check replay (Redis)
5. Match cnf.jkt

## Anti-patterns
- Reuse jti
- Skip timestamp validation