# MVP Architecture (Demo)

## Goal

Show a working Zero-Trust request path for demo:

1. Transport security with mTLS.
2. Identity and token authorization through ext_authz.
3. Traffic routed through Envoy with path-aware backend selection.

Flow:

`Client -> Envoy (mTLS) -> ext_authz (gRPC) -> Backend`

## Components

1. Envoy API Gateway
   - Terminates TLS and enforces `require_client_certificate: true`.
   - Verifies client certificate signature (X.509).
   - Forwards certificate metadata as `x-forwarded-client-cert` (XFCC).
   - Calls ext_authz before proxying to upstream services.
   - Routes:
     - `/protected` → `protected-api`
     - all other requests → `backend`

2. ext_authz service (Go, gRPC)
   - Implements Envoy `envoy.service.auth.v3.Authorization`.
   - Verifies JWT/JWS signature and claim checks.
   - Validates token binding:
     - `cnf.x5t#S256` against certificate thumbprint (mTLS PoP)
     - optional `cnf.jkt` against DPoP proof (mobile/other clients)
   - Enforces replay protection using `jti`.
   - Adds headers on allow:
     - `x-authz-result: allow`
     - `x-auth-user`
     - `x-auth-cert-subject`

3. Backend echo service (`backend`)
   - Returns request method/path/headers as JSON.
   - Useful for debugging request-level identity metadata.

4. Protected API service (`protected-api`)
   - Expects `x-auth-user` to be present.
   - Returns a structured JSON response with authenticated identity context.

## Why these technologies

- Envoy: native support for mTLS and ext_authz.
- mTLS: blocks requests without valid client certificate.
- ext_authz: centralized token and PoP verification in one service.
- Go services: low overhead, static binaries, and straightforward testability.

## Security outcome

- TLS and certificate binding together provide proof-of-possession.
- Authorization is enforced before request reaches any backend.
- All protected operations pass through explicit identity/authorization checks.
