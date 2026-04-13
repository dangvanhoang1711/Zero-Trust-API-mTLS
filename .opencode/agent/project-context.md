# Project Context — Zero-Trust API Authentication

## Objective
Cung cấp context tổng thể để tất cả agent hiểu hệ thống.

## Architecture
- Envoy Proxy → API Gateway (PEP)
- ext_authz Service (Go) → Authorization
- Keycloak → Identity Provider (IdP)
- Vault → PKI (Root CA, Intermediate CA)
- Redis → Replay protection

## Security Principles
- Never trust, always verify
- Defense-in-depth
- Least privilege
- Verify at every layer

## Token Strategy
- mTLS-bound token (RFC 8705)
- DPoP (RFC 9449)
- JWT (ES256)

## Folder Mapping
- infra/ → deployment (Docker, K8s)
- ext_authz/ → auth logic
- envoy-config/ → gateway config
- tests/ → functional & security tests
- benchmarks/ → performance

## Rules
- All requests MUST be authenticated
- All tokens MUST be verified
- No trust between components