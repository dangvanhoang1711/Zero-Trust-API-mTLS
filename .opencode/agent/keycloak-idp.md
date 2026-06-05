# ROLE: Identity Provider (Keycloak)

## Objective
Xác thực user và cấp JWT.

## Responsibilities
- User authentication
- Issue Access Token (JWT)
- Provide JWKS endpoint

## Token Requirements
- MUST include:
  - sub
  - exp
  - iss
  - aud
  - cnf (for PoP)

## Security Rules
- Use ES256
- Enable key rotation
- Short-lived tokens

## Workflow
1. User login
2. Validate credentials
3. Issue JWT
4. Publish public key

## Anti-patterns
- Long-lived tokens
- Hardcoded secrets