# Architecture — Zero Trust API Gateway with mTLS

## System Overview

The system is deployed across **2 EC2 instances** in a public/private subnet topology:

| EC2 | Subnet | Components | Role |
|-----|--------|------------|------|
| EC2-1 | Public subnet | Envoy Gateway, Backend (Flask API), Frontend (React SPA) | Ingress, API routing, UI serving |
| EC2-2 | Private subnet | ext_authz (Go gRPC), Keycloak, Vault, Redis | Authorization, identity, PKI, replay cache |

---

## Component Descriptions

### 1. Frontend (React SPA)

- **Location**: EC2-1, served as static files by Nginx through Envoy
- **Tech**: React 19 + TypeScript + Vite
- **Routes**: `/login`, `/register`, `/dashboard`
- **Auth flow**: Browser redirects to backend login endpoint; session-based with JWT stored in memory
- **API calls**: Dashboard buttons call `/api/*` endpoints with session JWT via fetch()

### 2. Backend (Flask API)

- **Location**: EC2-1, behind Envoy
- **Tech**: Python Flask
- **Responsibilities**:
  - Login/register form handling
  - JWT validation (ES256 via cryptography library)
  - Keycloak proxy: forwards login to Keycloak token endpoint
  - Mock data endpoints for role-based demo (`/api/user-data`, `/api/admin-data`)
  - Session management (server-side sessions)
- **Endpoints**:
  - `POST /login`, `POST /register` — auth
  - `/api/public` — no auth required
  - `/api/profile` — valid JWT required
  - `/api/user-data` — requires `user` role
  - `/api/admin-data` — requires `admin` role

### 3. Envoy Gateway

- **Location**: EC2-1, public-facing edge proxy
- **Tech**: Envoy Proxy with TLS, ext_authz, routing
- **Listeners**:
  - Port `10000` — mTLS gateway (requires client certificate)
  - Port `10001` — Baseline TLS (no client cert, for benchmarking)
- **Features**:
  - TLS termination with server certificate
  - `require_client_certificate: true` on port 10000
  - XFCC header forwarding (`x-forwarded-client-cert`)
  - ext_authz gRPC filter before routing to upstream
  - Route: `/protected` → protected-api, `/` → backend
- **Upstream clusters**: ext_authz (gRPC), backend, protected-api, keycloak

### 4. ext_authz (Authorization Service)

- **Location**: EC2-2, gRPC server
- **Tech**: Go, implements `envoy.service.auth.v3.Authorization`
- **Authorization pipeline** (in order):
  1. **JWT Verify**: Validate signature (ES256/RS256) using JWKS from Keycloak, check `exp`, `nbf`, `iss`, `aud`
  2. **Cert Binding**: Compare `cnf.x5t#S256` JWT claim against SHA-256 thumbprint of client certificate from XFCC header (mTLS PoP)
  3. **Policy (ABAC)**: Optional YAML-based route scope checks; per-identity rate limiting
  4. **Replay**: Check `jti` against replay cache (in-memory or Redis); reject duplicates
- **Output headers on allow**: `x-authz-result: allow`, `x-auth-user`, `x-auth-cert-subject`

### 5. Keycloak (Identity Provider)

- **Location**: EC2-2
- **Tech**: Keycloak with OpenID Connect
- **Responsibilities**:
  - User/role management (realm: `zero-trust`)
  - JWT signing with **ES256** (ECDSA P-256)
  - JWKS endpoint for token verification
  - Token endpoint for OIDC password grant
- **Default users**: `admin` (role: admin), `demo-user` (role: user)
- **Clients**: `web-app` (public), `demo-client` (confidential)

### 6. Vault (PKI)

- **Location**: EC2-2
- **Tech**: HashiCorp Vault PKI engine
- **PKI Hierarchy**:
  ```
  Root CA (pki-root, self-signed, 10yr)
    └── signs ──► Intermediate CA (pki-int, 5yr)
                    ├── signs ──► Server certificate (CN=localhost, SAN=envoy, backend, ...)
                    └── signs ──► Client certificates (CN=demo-client, CN=revoked-client, ...)
  ```
- **Artifacts**: Root CA cert, Intermediate CA cert, server cert+key, client certs+keys, CRL
- **Key type**: EC P-256 (ECDSA) for all certificates

### 7. Redis (Replay Cache)

- **Location**: EC2-2
- **Tech**: Redis (optional, fallback to in-memory)
- **Purpose**: Distributed JTI replay cache for multi-instance ext_authz deployments
- **Key pattern**: `zero-trust:replay:<jti>` with TTL matching token expiry

---

## Network Topology

```
Internet
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│  EC2-1 — Public Subnet                                           │
│                                                                   │
│  ┌──────────────┐    ┌──────────┐    ┌───────────────────────┐  │
│  │   Envoy       │───▶│  Backend │    │  Frontend             │  │
│  │  (mTLS/TLS)   │    │ (Flask)  │    │  (React SPA, static)  │  │
│  │  port 10000   │    │ port 8080│    │  served by Nginx      │  │
│  └──────┬───────┘    └──────────┘    └───────────────────────┘  │
│         │                                                        │
│         │ gRPC (ext_authz)                                       │
└─────────┼────────────────────────────────────────────────────────┘
          │
          │ (internal network / private subnet)
          │
┌─────────▼────────────────────────────────────────────────────────┐
│  EC2-2 — Private Subnet                                          │
│                                                                   │
│  ┌────────────┐  ┌──────────┐  ┌───────┐  ┌─────┐              │
│  │  ext_authz  │  │ Keycloak│  │ Vault │  │Redis│              │
│  │  (Go gRPC)  │  │  (IdP)  │  │ (PKI) │  │(JTI)│              │
│  └────────────┘  └──────────┘  └───────┘  └─────┘              │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Data Flows

### Scenario 1: Browser Login & Dashboard

```
Browser                     Frontend/React          Backend/Flask          Keycloak
   │                             │                      │                    │
   │  ── GET /login ─────────────▶                      │                    │
   │  ◀── login.html ─────────────                      │                    │
   │                             │                      │                    │
   │  ── POST /login ───────────────────────────────────▶                    │
   │   (username+password)        │                      │                    │
   │                             │                      │  ── POST /token ──▶│
   │                             │                      │  ◀── JWT (ES256) ──│
   │                             │                      │                    │
   │                             │                      │  Validates JWT     │
   │                             │                      │  signature via JWKS │
   │                             │                      │                    │
   │  ◀── Set session cookie ────                      │                    │
   │  ── GET /dashboard ─────────▶                      │                    │
   │  ◀── dashboard.html ────────                      │                    │
   │                             │                      │                    │
   │  ── fetch(/api/user-data) ───────────────────────▶│                    │
   │  ◀── JSON (mock data) ──────                      │                    │
```

### Scenario 2: API Call (Postman with mTLS)

```
Postman                     Envoy (EC2-1)            ext_authz (EC2-2)     Backend
   │                            │                        │                    │
   │  mTLS handshake            │                        │                    │
   │  (client cert + server)    │                        │                    │
   │────────────────────────────▶                        │                    │
   │                            │                        │                    │
   │  GET /protected             │                        │                    │
   │  Authorization: Bearer JWT │                        │                    │
   │────────────────────────────▶                        │                    │
   │                            │                        │                    │
   │                            │  gRPC Check(Request)   │                    │
   │                            │────────────────────────▶                    │
   │                            │                        │                    │
   │                            │    1. Verify JWT sig   │                    │
   │                            │    2. Check cnf.x5t    │                    │
   │                            │       vs cert thumbprint│                    │
   │                            │    3. Check policy     │                    │
   │                            │    4. Check replay jti │                    │
   │                            │                        │                    │
   │                            │  ◀── gRPC OK + headers  │                    │
   │                            │                        │                    │
   │                            │  ── HTTP ──────────────▶                    │
   │                            │  (x-auth-user, etc.)   │                    │
   │  ◀── Response ─────────────                        │                    │
```

---

## Security Architecture (6 Layers)

| Layer | Component | Protection |
|-------|-----------|------------|
| 1. mTLS | Envoy (port 10000) | Mutual TLS authentication; blocks requests without valid client certificate |
| 2. JWT | Keycloak → ext_authz | ES256-signed JWT; signature verified via JWKS; standard claim validation |
| 3. Cert Binding | ext_authz | `cnf.x5t#S256` claim matches client cert SHA-256 thumbprint; prevents token theft |
| 4. DPoP | ext_authz (optional) | `cnf.jkt` claim for DPoP proof of possession; mobile/keyless clients |
| 5. Policy (ABAC) | ext_authz (optional) | YAML-based route authorization; scope/role requirements; per-identity rate limiting |
| 6. Replay | ext_authz + Redis | JTI tracking prevents token reuse; in-memory or distributed Redis cache |

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Gateway | Envoy Proxy v1.32+ | TLS termination, mTLS, ext_authz, routing |
| Authorization | Go (ext_authz gRPC) | JWT verify, cert binding, policy, replay |
| Identity Provider | Keycloak 26+ | OIDC, ES256 JWT signing, user/role mgmt |
| PKI | HashiCorp Vault 1.18+ | Root CA → Intermediate CA → cert issuance, CRL |
| Replay Cache | Redis 7+ | Distributed JTI deduplication |
| Frontend | React 19 + TypeScript + Vite | User interface |
| Backend | Python Flask 3.x | API routes, session management, mock data |
| Infrastructure | AWS EC2, Docker Compose | Deployment |
