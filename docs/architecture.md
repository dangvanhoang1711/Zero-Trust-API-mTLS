# Architecture - Zero Trust API Gateway with mTLS

## System Overview

The deployed topology uses one VPC (`10.0.0.0/16`) and one public subnet (`10.0.0.0/20`). Both EC2 instances have public IPs for administration, but application traffic between them uses private IPs.

| Instance | Private IP | Public IP | Components | Role |
|----------|------------|-----------|------------|------|
| EC2-Envoy | `10.0.5.131` | `13.238.159.245` | Envoy Gateway, Backend (Flask API), Frontend (React SPA) | Public ingress, HTTPS termination, UI serving, backend routing |
| EC2-Services | `10.0.2.27` | `3.106.196.141` | ext_authz (Go gRPC), Keycloak, Vault, Redis, `pki-init` | Authorization, identity, PKI, replay cache |

## Component Descriptions

### 1. Frontend (React SPA)

- Location: EC2-Envoy
- Tech: React 19, TypeScript, Vite, Nginx
- Browser entrypoint: `https://13.238.159.245/login`
- Routes: `/login`, `/register`, `/dashboard`, `/abac`
- API calls: Same-origin requests to `/api/*` through Envoy on port `443`

### 2. Backend (Flask API)

- Location: EC2-Envoy, reachable only behind Envoy
- Tech: Python Flask
- Responsibilities:
  - `POST /api/auth/login` and `POST /api/auth/register`
  - Public and protected demo endpoints such as `/api/public`, `/api/profile`, and `/protected`
  - Keycloak token exchange and JWT-aware session handling

### 3. Envoy Gateway

- Location: EC2-Envoy
- Public listeners:
  - Port `443`: Main HTTPS entrypoint for browser and API traffic
  - Port `10001`: Health and baseline TLS checks
- Features:
  - TLS termination with the Vault-issued server certificate
  - Optional client certificate acceptance and XFCC forwarding
  - `ext_authz` gRPC filter before routing
  - Route split:
    - `/api/*`, `/protected`, `/health` -> backend
    - everything else -> frontend
- Upstream clusters: ext_authz (over the service host private IP), backend, frontend

### 4. ext_authz (Authorization Service)

- Location: EC2-Services
- Tech: Go, implements `envoy.service.auth.v3.Authorization`
- Authorization pipeline:
  1. Parse the forwarded client certificate if Envoy received one
  2. Verify JWT signature and registered claims when a bearer token is present
  3. Enforce `cnf.x5t#S256` certificate binding when the token carries a thumbprint claim
  4. Evaluate YAML policy for route access
  5. Reject replayed `jti` values through Redis or the in-memory fallback
- Output headers on allow: `x-authz-result`, `x-auth-user`, `x-auth-cert-subject`

### 5. Keycloak

- Location: EC2-Services
- Realm: `zero-trust`
- Responsibilities:
  - User and client management
  - OIDC discovery and JWKS publication
  - ES256-signed JWT issuance
  - Certificate-bound client tokens for `demo-client` style Postman flows

### 6. Vault PKI

- Location: EC2-Services
- Responsibilities:
  - Root CA and intermediate CA management
  - Server certificate issuance for Envoy, backend, Keycloak, and ext_authz
  - Client certificate issuance for Postman and replay/certificate-binding demos
  - Regeneration of Keycloak thumbprint bindings to match the latest issued client certificates

### 7. Redis

- Location: EC2-Services
- Purpose: Replay cache for `jti` tracking and optional shared policy state

## Network Topology

```text
Internet
    |
    v
+-------------------------------------------------------------------+
| VPC 10.0.0.0/16                                                   |
|   Public Subnet 10.0.0.0/20                                       |
|                                                                   |
|   EC2-Envoy                                                       |
|   10.0.5.131 / 13.238.159.245                                     |
|   +-------------------+    +-------------------+                  |
|   | Envoy             |--->| Frontend (Nginx)  |                  |
|   | 443 / 10001       |--->| Backend (Flask)   |                  |
|   +---------+---------+    +-------------------+                  |
|             |                                                     |
|             | private east-west traffic                           |
|             v                                                     |
|   EC2-Services                                                    |
|   10.0.2.27 / 3.106.196.141                                       |
|   +-------------------+  +----------+  +-------+  +-------+       |
|   | ext_authz :50051  |  | Keycloak |  | Vault |  | Redis |       |
|   +-------------------+  +----------+  +-------+  +-------+       |
+-------------------------------------------------------------------+
```

## Data Flows

### Scenario 1: Browser Login and Dashboard

```text
Browser -> Envoy : GET /login over HTTPS
Envoy -> Frontend : Serve SPA assets
Browser -> Envoy : POST /api/auth/login
Envoy -> Backend : Login request
Backend -> Keycloak : Token request over private IP 10.0.2.27
Keycloak -> Backend : ES256 JWT
Backend -> Browser : Login response
Browser -> Envoy : GET /api/profile with bearer token
Envoy -> ext_authz : Authorization check
Envoy -> Backend : Allowed protected request
```

### Scenario 2: Postman mTLS and Certificate-Bound Token

```text
Postman -> Envoy : HTTPS request with client certificate and bearer token
Envoy -> ext_authz : Forward HTTP headers plus XFCC client-cert details
ext_authz :
  1. Verify JWT via Keycloak JWKS
  2. Compare cnf.x5t#S256 to the presented client certificate thumbprint
  3. Apply policy
  4. Check replay cache
Envoy -> Backend : Forward only if allow
```

## Security Layers

| Layer | Component | Protection |
|-------|-----------|------------|
| 1. TLS | Envoy on `443` | Public HTTPS entrypoint |
| 2. Client certificate | Envoy + ext_authz | Client certificate can be presented and is forwarded in XFCC for token binding checks |
| 3. JWT | Keycloak -> ext_authz | ES256 JWT verification against JWKS plus `iss` and `aud` checks |
| 4. Certificate binding | ext_authz | `cnf.x5t#S256` must match the presented client certificate thumbprint |
| 5. Policy | ext_authz | YAML route policy and identity-based access decisions |
| 6. Replay | ext_authz + Redis | Duplicate `jti` values are rejected |

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Gateway | Envoy Proxy | TLS termination, routing, ext_authz integration |
| Authorization | Go gRPC service | JWT verify, certificate binding, policy, replay |
| Identity Provider | Keycloak 26+ | OIDC discovery, user and client token issuance |
| PKI | HashiCorp Vault | Root and intermediate CA, server and client certificates |
| Replay Cache | Redis 7 | Shared replay detection |
| Frontend | React 19 + TypeScript + Vite | Browser UI |
| Backend | Python Flask | Auth endpoints and protected demo APIs |
| Infrastructure | AWS EC2, Docker Compose | Split-host deployment |
