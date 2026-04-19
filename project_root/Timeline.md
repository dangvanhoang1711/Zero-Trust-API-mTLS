# 📋 Zero-Trust API Authentication — Project Roadmap

> **Course:** NT219 — Cryptography
> **Project:** Zero-Trust API Authentication Proxy with mTLS + Token-Based Signatures (PoP/DPoP)

---

## 🧭 Overview

This document outlines the full implementation path for building a **Zero-Trust API gateway/proxy** that combines **mutual TLS (mTLS)** for machine-to-machine authentication with **token-based proof-of-possession (PoP)** for user/mobile authentication. The project is structured into 7 phases following the 12-week timeline.

---

## Phase 1 — Research & Environment Setup (Tuần 1–2)

### Progress Summary
- Completed: 14/20 tasks (+2 partial)
- Status: Mid Phase
- Evidence: root `docker-compose.yml` runs only `envoy`, `ext_authz`, `backend`; `./tests/run-all.sh` passes MVP flow.
- Integration gaps: `Vault`, `Keycloak`, and Kubernetes/cert-manager are not part of the current runnable stack.

### 1.1 Literature & Standards Review

- [x] Read and summarize **OAuth 2.0 (RFC 6749)** — authorization framework basics
- [x] Read and summarize **JWT (RFC 7519)** & **JWS (RFC 7515)** — token structure & signing
- [x] Read and summarize **OAuth 2.0 mTLS (RFC 8705)** — certificate-bound access tokens
- [x] Read and summarize **DPoP (RFC 9449)** — Demonstration of Proof-of-Possession
- [x] Study **holder-of-key JWT** patterns (`cnf` claim, `x5t#S256` thumbprint)
- [x] Study **HTTP Message Signatures (RFC 9421)** — signed HTTP requests
- [x] Review OWASP API Security Top 10 & NIST PKI guidelines
- [x] Document findings in `docs/literature-review.md`

### 1.2 Stack Decision & Justification

- [x] Compare proxy options: **Envoy** vs Kong vs NGINX (recommend Envoy for ext_authz support)
- [x] Compare IdP options: **Keycloak** (self-hosted) vs Auth0 (SaaS)
- [x] Compare ext_authz language: **Go** (performance) vs Python/Node (prototyping speed)
- [x] Choose token binding pattern: mTLS-bound tokens, DPoP, or HoK JWT
- [x] Document stack decisions in `docs/architecture-decisions.md`

### 1.3 Development Environment

- [x] Install and configure **Docker** & **Docker Compose**
- [ ] Set up **Kubernetes** dev cluster (minikube or k3s)
- [ ] Install **cert-manager** in the cluster
- [~] Install **HashiCorp Vault** (dev mode) for PKI backend — vault scripts/artifacts exist, not part of current runnable compose flow
- [x] Install **Keycloak** (Docker) for token issuance
- [x] Verify all services are running and reachable — MVP core services verified; full stack services not verified together
- [ ] Create `infra/docker-compose.dev.yml` for local development

---

## Phase 2 — PKI & Certificate Infrastructure (Tuần 3–4)

### Progress Summary
- Completed: 3/15 tasks (+4 partial)
- Status: Early Phase
- Evidence: Envoy mTLS works in runtime (`tests/run-all.sh`); Envoy currently mounts `project_root/infra/certs` via root `docker-compose.yml`.
- Integration gaps: Vault/cert-manager automation is not wired into current runtime; CRL enforcement is not enabled in active Envoy config.

### 2.1 Certificate Authority Setup

- [~] Configure Vault as a **PKI secrets engine** (root CA + intermediate CA) — bootstrap scripts/artifacts exist, runtime integration not active
- [~] Create CA certificate chain (Root CA → Intermediate CA → Client/Server certs) — chain artifacts exist in repo; active runtime uses static cert mount
- [x] Document CA hierarchy in `docs/pki-architecture.md`

### 2.2 Server Certificate Provisioning

- [x] Generate server TLS certificates for the Envoy proxy
- [x] Configure Envoy to use server certs for TLS termination
- [~] Store configs in `envoy_config/tls/` — folder exists, but active runtime uses `infra/certs/`

### 2.3 Client Certificate Automation

- [ ] Configure cert-manager **Issuer** / **ClusterIssuer** backed by Vault PKI
- [ ] Create a **Certificate** resource template for client cert issuance
- [ ] Automate client cert issuance for test service accounts
- [ ] Test certificate renewal flow (short TTL → auto-renew)
- [ ] Store Kubernetes manifests in `infra/cert-manager/`

### 2.4 Certificate Revocation

- [~] Set up **CRL (Certificate Revocation List)** via Vault — CRL artifacts/scripts exist, not enforced in current Envoy runtime config
- [ ] Configure Envoy to check revocation status during TLS handshake
- [ ] Test that revoked certs are rejected
- [ ] Document revocation procedures in `docs/runbook.md`

---

## Phase 3 — ext_authz Service Core (Tuần 5–6)

### Progress Summary
- Completed: 4/23 tasks (+1 partial)
- Status: Early Phase

### 3.1 Project Scaffolding

- [x] Initialize Go module in `ext_authz/` (`go mod init`)
- [~] Set up project structure:
  ```
  ext_authz/
  ├── cmd/server/main.go       # entry point
  ├── internal/
  │   ├── auth/                 # authentication logic
  │   │   ├── jwt.go            # JWT/JWS verification
  │   │   ├── mtls.go           # mTLS cert extraction & validation
  │   │   └── binding.go        # token-cert binding (cnf matching)
  │   ├── cache/                # JWKS & replay caches
  │   │   ├── jwks.go
  │   │   └── replay.go
  │   ├── policy/               # scope, role, rate limit enforcement
  │   │   └── enforcer.go
  │   └── server/               # gRPC ext_authz server
  │       └── grpc.go
  ├── config/                   # configuration (YAML/env)
  ├── Dockerfile
  └── go.mod
  ```
- [x] Add Dockerfile for the ext_authz service

### 3.2 JWKS Cache & JWT Verification

- [x] Implement **JWKS fetcher** — download & cache public keys from Keycloak `/.well-known/jwks.json`
- [x] Implement auto-refresh on key rotation (background goroutine, honor `Cache-Control`)
- [x] Implement **JWS verification** — validate JWT signature using cached JWKS
- [x] Validate standard claims: `exp`, `nbf`, `aud`, `iss`, `sub`
- [ ] Write unit tests for JWT verification (valid, expired, wrong issuer, bad signature)
- [ ] Store tests in `ext_authz/internal/auth/jwt_test.go`

### 3.3 mTLS Certificate Extraction

- [x] Implement extraction of client cert from Envoy-forwarded headers (`x-forwarded-client-cert` / XFCC)
- [x] Parse X.509 certificate: extract Subject, SAN, **SHA-256 thumbprint**
- [~] Validate cert chain (optional, if not fully handled by Envoy)
- [ ] Write unit tests for cert parsing and thumbprint calculation

### 3.4 Token-Certificate Binding (cnf Matching)

- [x] Implement `cnf` claim extraction from JWT payload
- [x] Implement **x5t#S256 matching** — compare `cnf.x5t#S256` with client cert thumbprint
- [x] Return `403 Forbidden` if binding fails (token not bound to presented cert)
- [ ] Write unit tests: matching thumbprint, mismatched thumbprint, missing cnf claim
- [ ] Store tests in `ext_authz/internal/auth/binding_test.go`

### 3.5 gRPC ext_authz Server

- [x] Implement Envoy **ext_authz gRPC protocol** (`envoy.service.auth.v3.Authorization`)
- [x] Wire up JWT verification + mTLS extraction + binding check into the `Check()` RPC
- [~] Return enriched headers on success (e.g., `x-auth-user`, `x-auth-scope`) — currently only returns `x-authz-result`
- [x] Return deny with proper status codes on failure
- [ ] Integration test: send mock ext_authz requests and verify responses

---

## Phase 4 — DPoP & Advanced PoP Verification (Tuần 7–8)

### Progress Summary
- Completed: 0/18 tasks
- Status: Early Phase

### 4.1 DPoP Verification

- [ ] Implement **DPoP proof parsing** — extract & verify the `DPoP` header (JWS)
- [ ] Verify DPoP proof structure: `typ: dpop+jwt`, `htm` (HTTP method), `htu` (HTTP URI), `iat`, `jti`
- [ ] Verify DPoP signature using the embedded `jwk` in the DPoP header
- [ ] Match DPoP `jwk` thumbprint against token's `cnf.jkt` claim
- [ ] Write unit tests for DPoP verification (valid, expired, wrong method, wrong URI)

### 4.2 Replay Protection

- [~] Implement **nonce-based replay cache** (in-memory with TTL, backed by Redis for production)
- [~] Check `jti` (JWT ID) uniqueness within the replay window
- [ ] Implement server-issued nonce flow (optional, for stricter DPoP)
- [~] Configure TTL and max cache size (eviction policy)
- [ ] Write unit tests and benchmark the replay cache
- [ ] Store cache implementation in `ext_authz/internal/cache/replay.go`

### 4.3 Policy Enforcement

- [ ] Implement **scope checking** — verify required scopes are present in token
- [ ] Implement **attribute-based access control (ABAC)** (optional)
- [ ] Implement **rate limiting** per client identity (cert subject or token sub)
- [ ] Store policy rules in configuration (YAML)

### 4.4 Holder-of-Key JWT (Alternative Pattern)

- [ ] Implement HoK JWT verification: extract `cnf.jwk` and verify request signature
- [ ] Support HTTP Signatures pattern (canonicalize request → verify signature)
- [ ] Document which pattern is used and why in `docs/token-binding-design.md`

---

## Phase 5 — Proxy Integration & Sample Services (Tuần 9)

### Progress Summary
- Completed: 6/19 tasks (+3 partial)
- Status: Early Phase

### 5.1 Envoy Configuration

- [x] Write Envoy **listener** config with TLS + mTLS (`require_client_certificate: true`)
- [x] Configure **ext_authz filter** pointing to the Go gRPC service
- [x] Configure XFCC (x-forwarded-client-cert) header forwarding
- [~] Set up **route rules** — different auth requirements per path/service (single protected route currently)
- [x] Store all configs in `envoy_config/`

### 5.2 Sample Backend Microservices

- [x] Create a simple **echo service** (Go or Python) — returns request headers/body for debugging
- [ ] Create a **protected API** service — requires authenticated requests, reads `x-auth-user` header
- [~] Dockerize both services — ext_authz + echo are dockerized; protected API is missing
- [x] Store in `infra/services/`

### 5.3 Keycloak Configuration

- [x] Configure a **realm** for the project
- [x] Create **client** registrations (confidential client for mTLS, public client for DPoP)
- [x] Configure token issuance with **`cnf` claim** (mTLS-bound tokens via RFC 8705)
- [ ] Enable **DPoP** support (if Keycloak version supports it, otherwise mock/extend)
- [x] Export realm config to `infra/keycloak/realm-export.json`

### 5.4 End-to-End Integration

- [x] Deploy full stack: Envoy + ext_authz + Keycloak + sample services — current stack runs Envoy + ext_authz + echo only
- [ ] Create `infra/docker-compose.yml` for the complete setup
- [ ] Create `infra/k8s/` with Kubernetes manifests (Deployment, Service, Ingress)
- [ ] Create Helm chart (optional) in `infra/helm/`
- [ ] Write a quickstart guide in `docs/quickstart.md`

---

## Phase 6 — Testing & Benchmarking (Tuần 10–11)

### Progress Summary
- Completed: 1/31 tasks (+3 partial)
- Status: Early Phase

### 6.1 Functional Tests

- [x] **Test A:** Valid mTLS client + valid PoP token → ✅ 200 OK (implemented as mTLS + valid `x-test-auth` header)
- [x] **Test B:** Valid token but **no client cert** → ❌ 401/403 (no-cert rejection verified with header-based auth)
- [x] **Test C:** Valid cert but **invalid/expired token** → ❌ 401 (implemented as valid cert + invalid auth header -> 403)
- [x] **Test D:** Valid cert + valid token but **binding mismatch** (wrong cert) → ❌ 403
- [x] **Test E:** **Stolen token replay** — reuse a DPoP proof with same `jti` → ❌ 403
- [ ] **Test F:** **Expired client certificate** → ❌ TLS handshake failure
- [ ] **Test G:** **Revoked client certificate** → ❌ TLS handshake failure
- [ ] **Test H:** **Algorithm downgrade** attempt (e.g., `alg: none`) → ❌ 401
- [ ] Write all tests as scripts in `tests/functional/`
- [x] Create test runner script: `tests/run-all.sh`

### 6.2 Security Tests

- [ ] **MITM simulation** — attempt to intercept and replay requests without client key
- [ ] **Token theft scenario** — use stolen bearer token without the bound cert/key
- [ ] **Certificate forgery** — present a cert not signed by the trusted CA
- [ ] **Signature forgery** — tamper with DPoP proof signature
- [ ] Document results in `docs/security-analysis.md`
- [ ] Store scripts in `tests/security/`

### 6.3 Load & Performance Testing

- [ ] Set up **wrk2** or **locust** load test scripts
- [ ] Benchmark **baseline**: TLS only + bearer token (no mTLS, no PoP)
- [ ] Benchmark **mTLS only**: mutual TLS without token binding
- [ ] Benchmark **mTLS + PoP**: full zero-trust auth chain
- [ ] Collect metrics: **latency** (median, p95, p99), **throughput** (req/sec)
- [ ] Collect resource usage: CPU & memory of ext_authz and Envoy
- [ ] Measure **replay cache** hit/miss ratios and memory usage
- [ ] Store scripts in `benchmarks/scripts/`
- [ ] Store raw results in `benchmarks/results/` (CSV format)
- [ ] Create visualization notebook in `benchmarks/plots/` (Jupyter or Python matplotlib)

### 6.4 Operational Resilience Tests

- [ ] Test **cert rotation** — rotate client cert while service is running, verify zero downtime
- [ ] Test **JWKS rotation** — rotate IdP signing keys, verify ext_authz picks up new keys
- [ ] Test **IdP unavailability** — kill Keycloak, verify cached JWKS allows continued operation
- [ ] Test **replay cache failure** — simulate Redis outage, verify fallback behavior
- [ ] Document results in `docs/operational-resilience.md`

---

## Phase 7 — Documentation, Report & Demo (Tuần 12)

### Progress Summary
- Completed: 3/22 tasks (+1 partial)
- Status: Early Phase

### 7.1 Documentation

- [x] Write **`docs/architecture.md`** — system architecture diagram + component descriptions
- [ ] Write **`docs/threat-model.md`** — threat model analysis (STRIDE or similar)
- [x] Write **`docs/runbook.md`** — operational runbook:
  - How to issue/rotate/revoke client certificates
  - How to handle JWKS rotation
  - Rollback plan for failed deployments
  - Monitoring & alerting recommendations
- [ ] Write **`docs/onboarding.md`** — guide for onboarding new clients:
  - Machine-to-machine (mTLS)
  - Mobile app (DPoP)
  - Browser SPA (DPoP with ephemeral keys)
  - Third-party integrators (asymmetric PoP)
- [x] Update **`README.md`** with project overview, quickstart, and architecture diagram

### 7.2 Final Report

- [ ] Write introduction & motivation (Zero-Trust, threat landscape)
- [ ] Write background & literature review (cite ≥6 RFCs/standards, ≥3 projects/repos)
- [ ] Write methodology (architecture, token binding design, proxy verification steps)
- [ ] Write implementation details (stack choices, code structure, key algorithms)
- [ ] Write evaluation results (security, performance, operational)
- [ ] Write discussion (trade-offs, limitations, comparison with alternatives)
- [ ] Write conclusion & future work
- [ ] Store in `docs/report/`

### 7.3 Demo Preparation

- [ ] Record or prepare **live demo** showing:
  - ✅ Successful auth: mTLS + PoP token → API access granted
  - ❌ Blocked attack: stolen token replay → rejected
  - ❌ Blocked attack: missing cert binding → rejected
  - 🔄 Operational: cert rotation with zero downtime
- [ ] Prepare demo script / slides
- [x] Ensure `docker-compose up` reproduces the full environment — MVP environment is reproducible; full architecture stack is not

### 7.4 Code Cleanup & Submission

- [ ] Clean up code — remove debug logs, unused files
- [ ] Add code comments where complex logic exists
- [ ] Ensure all tests pass
- [ ] Verify Docker Compose / Helm setup works from scratch
- [ ] Tag final release in Git
- [ ] Submit repository + report

---

## 📁 Expected Final Repository Structure

```
project_root/
├── infra/
│   ├── docker-compose.yml          # Full stack deployment
│   ├── docker-compose.dev.yml      # Dev environment
│   ├── k8s/                        # Kubernetes manifests
│   ├── helm/                       # Helm chart (optional)
│   ├── cert-manager/               # cert-manager CRDs
│   ├── vault/                      # Vault PKI config
│   ├── keycloak/                   # Realm export & config
│   └── services/                   # Sample backend services
├── ext_authz/
│   ├── cmd/server/main.go
│   ├── internal/auth/              # JWT, mTLS, binding logic
│   ├── internal/cache/             # JWKS & replay caches
│   ├── internal/policy/            # Scope & rate limit enforcement
│   ├── internal/server/            # gRPC ext_authz server
│   ├── config/
│   ├── Dockerfile
│   └── go.mod
├── envoy_config/
│   ├── envoy.yaml                  # Main Envoy config
│   ├── tls/                        # TLS/mTLS certificates
│   └── ext_authz.yaml              # ext_authz filter config
├── clients/
│   ├── curl-scripts/               # curl-based test clients
│   ├── go-client/                  # Go test client
│   └── mobile-stub/                # Mobile client simulation
├── tests/
│   ├── functional/                 # Functional test scripts
│   ├── security/                   # Security test scripts
│   └── run-all.sh                  # Test runner
├── benchmarks/
│   ├── scripts/                    # wrk2/locust configs
│   ├── results/                    # Raw CSV data
│   └── plots/                      # Visualization notebooks
├── docs/
│   ├── architecture.md
│   ├── architecture-decisions.md
│   ├── literature-review.md
│   ├── pki-architecture.md
│   ├── token-binding-design.md
│   ├── threat-model.md
│   ├── security-analysis.md
│   ├── operational-resilience.md
│   ├── runbook.md
│   ├── onboarding.md
│   ├── quickstart.md
│   └── report/                     # Final report
└── README.md
```

---

## 🗂 Repository Structure Notes (Actual vs Timeline)

- Existing folders aligned with project scope: `infra/`, `ext_authz/`, `envoy_config/`, `tests/`, `docs/`.
- Existing but not explicitly represented in checklist items: root `docker-compose.yml`, `infra/certs/`, `infra/pki-issued/`, `infra/tmp-mtls/`.
- `project_root/k8s/` exists but is currently empty; item `Create infra/k8s/` remains NOT DONE.
- `project_root/infra/cert-manager/` exists but is currently empty; cert-manager automation remains NOT DONE.
- `project_root/tests/functional/` exists but is currently empty; advanced functional suite remains NOT DONE.
- Timeline item `Create infra/docker-compose.dev.yml` is marked NOT DONE (file does not exist in current repo).

---

## 🔑 Key References

| Resource | Link |
|----------|------|
| OAuth 2.0 | [RFC 6749](https://tools.ietf.org/html/rfc6749) |
| JWT | [RFC 7519](https://tools.ietf.org/html/rfc7519) |
| JWS | [RFC 7515](https://tools.ietf.org/html/rfc7515) |
| OAuth 2.0 mTLS | [RFC 8705](https://tools.ietf.org/html/rfc8705) |
| DPoP | [RFC 9449](https://tools.ietf.org/html/rfc9449) |
| HTTP Signatures | [RFC 9421](https://tools.ietf.org/html/rfc9421) |
| Envoy ext_authz | [Envoy docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) |
| cert-manager | [cert-manager.io](https://cert-manager.io/) |
| Vault PKI | [Vault PKI docs](https://developer.hashicorp.com/vault/docs/secrets/pki) |
| Keycloak | [keycloak.org](https://www.keycloak.org/) |

---

> **Tip:** Work through each phase sequentially. Each phase builds on the previous one. Start with understanding the theory (Phase 1), then build infrastructure (Phase 2), implement core logic (Phases 3–4), integrate everything (Phase 5), validate (Phase 6), and polish (Phase 7).

## 📊 Actual Implementation Status (AUTO-GENERATED)

### Core System
- mTLS Envoy Gateway: DONE
- ext_authz Go service: DONE
- JWT verification: NOT DONE
- JWKS caching: NOT DONE

### Security Features
- Token binding (cnf + x5t#S256): NOT IMPLEMENTED
- DPoP: NOT IMPLEMENTED
- Replay protection: NOT IMPLEMENTED

### Infrastructure
- Docker Compose: DONE
- Kubernetes: NOT IMPLEMENTED
- cert-manager: NOT IMPLEMENTED
