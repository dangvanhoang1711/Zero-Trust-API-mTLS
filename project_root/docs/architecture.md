# MVP Architecture (Demo)

## Goal

Show a working Zero-Trust request path for demo:

1. Transport security with mTLS.
2. Identity check with ext_authz.
3. Routed traffic through Envoy to backend.

Flow:

`Client -> Envoy (mTLS) -> ext_authz (gRPC) -> Backend echo service`

## Components

1. Envoy API Gateway
   - Terminates TLS and enforces `require_client_certificate: true`.
   - Verifies client certificate against trusted CA.
   - Forwards client certificate details as `x-forwarded-client-cert` (XFCC).
   - Calls ext_authz before proxying to backend.

2. ext_authz service (Go, gRPC)
   - Implements Envoy `envoy.service.auth.v3.Authorization`.
   - Rule for MVP:
     - `x-test-auth == ok` -> ALLOW
     - otherwise -> DENY (403)

3. Backend echo service (Go)
   - Returns request method/path/headers as JSON.
   - Used to prove which headers reached upstream.

## Why these technologies

- Envoy: native support for mTLS and ext_authz in one gateway.
- mTLS: rejects clients without valid certificate at transport layer.
- ext_authz: central place for request authorization logic.
- Go services: single binary, low overhead, simple container builds.

## Out of scope for MVP

- JWKS rotation/caching
- DPoP full implementation
- replay protection
- ABAC/policy engine
- cert-manager/Kubernetes automation
- HTTP Signatures RFC 9421
