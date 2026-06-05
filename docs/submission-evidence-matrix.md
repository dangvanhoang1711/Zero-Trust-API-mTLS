# Submission Evidence Matrix

Tài liệu này gom nhanh các bằng chứng để chấm điểm theo `Timeline.md`.

## Phase 1

- 1.1, 1.2:  
  - `docs/literature-review.md`  
  - `docs/architecture-decisions.md`  
  - `docs/architecture.md`
- 1.3 (completed): Docker/Compose + Keycloak runnable:  
  - `docker-compose.yml` (repo root)  
  - `project_root/infra/docker-compose.yml`  
  - `docs/quickstart.md`

## Phase 2

- 2.1, 2.2:  
  - `docs/pki-architecture.md`  
  - CA artifacts trong `project_root/infra/certs`, `project_root/infra/pki-issued`, `project_root/tests/functional/fixtures*`
- 2.3: `cert-manager` automation path exists (`--bootstrap-vault` flow) and runtime manifests are available.
  - `project_root/infra/cert-manager/*`
  - `project_root/scripts/setup-k8s-cluster.sh`
  - `project_root/docs/k8s-cert-manager-bootstrap.md`
- 2.4: CRL enforcement is configured in Envoy runtime config; runtime validity depends on loaded `ca.crl` from mounted TLS volume.
  - `project_root/infra/vault/artifacts/ca.crl`
  - `project_root/infra/certs/ca.crl`
  - `project_root/envoy_config/envoy.yaml`

## Phase 3

- 3.1, 3.2, 3.3, 3.4, 3.5:  
  - `project_root/ext_authz/internal/auth/*.go`
  - `project_root/ext_authz/main.go`
  - `project_root/ext_authz/main_test.go`
  - `project_root/ext_authz/internal/auth/*_test.go`

## Phase 4

- 4.1: DPoP parser/verifier + tests  
  - `project_root/ext_authz/internal/auth/dpop.go`  
  - `project_root/ext_authz/internal/auth/dpop_test.go`
- 4.2: Replay cache + replay tests/benchmarks  
  - `project_root/ext_authz/internal/cache/replay.go`  
  - `project_root/ext_authz/main.go` (factory `newReplayCache`)  
  - `project_root/ext_authz/main_test.go`
- 4.2 (server-issued nonce flow):  
  - `project_root/ext_authz/internal/auth/dpop.go` (nonce-aware DPoP validation)  
  - `project_root/ext_authz/main.go` (`DPoP_REQUIRE_NONCE`, `DPoP_NONCE_TTL`, `x-dpop-nonce` response)  
  - `project_root/ext_authz/internal/auth/dpop_test.go` (nonce valid/missing/mismatch cases)
- 4.3: Scope policy  
  - `project_root/ext_authz/internal/auth/jwt.go`  
  - `project_root/ext_authz/internal/auth/policy.go` (ABAC + YAML policy evaluator)  
  - `project_root/ext_authz/internal/cache/rate.go` (rate limiting limiter)  
  - `project_root/ext_authz/config/authz-policy.yaml`  
  - `project_root/ext_authz/main.go` (`AUTHZ_POLICY_FILE`, scope merge, rate-limit enforcement)  
  - `project_root/docs/quickstart.md`
- 4.4: HoK/HTTP signature comparison  
  - `project_root/docs/token-binding-design.md` (decision rationale: mTLS-bound RFC 8705 vs DPoP/HTTP Signatures)
  - `project_root/ext_authz/internal/auth/hok.go` (cnf.jwk/HTTP Signature verifier)
  - `project_root/ext_authz/internal/auth/hok_test.go` (unit tests for HoK verification/parsing)
  - `project_root/ext_authz/main.go` (`cnf.jwk` branch in `Check()` call chain)
  - `project_root/ext_authz/main_test.go` (integration coverage for HoK allow/deny cases)

## Phase 5

- Envoy + ext_authz + services + Keycloak integration  
  - `project_root/envoy_config/envoy.yaml`  
  - `project_root/ext_authz/Dockerfile`  
  - `project_root/infra/services/*`  
  - `project_root/infra/docker-compose.yml`  
  - `project_root/infra/keycloak/realm-export.json`
- 5.3 DPoP enablement via mock/extend path  
  - `project_root/infra/keycloak/realm-export.json` (`demo-client-dpop` with static `cnf.jkt`)  
  - `project_root/clients/keys/dpop-mock/*` (mock key material and generated `jkt`)  
  - `project_root/clients/curl-scripts/06-ok-dpop-mock.sh`
- Helm chart (optional deployment path)  
  - `project_root/infra/helm/zero-trust-mtls/Chart.yaml`  
  - `project_root/infra/helm/zero-trust-mtls/values.yaml`  
  - `project_root/infra/helm/zero-trust-mtls/templates/*`

## Phase 6

- Functional, security, resilience, và load test evidence  
  - `project_root/tests/run-all.sh`  
  - `project_root/tests/security/run-all-security.sh`  
  - `project_root/tests/functional/run-all-resilience.sh`  
  - `project_root/benchmarks/scripts/*`  
  - `project_root/benchmarks/results/*`
  - `project_root/benchmarks/plots/plot-benchmarks.py`

## Phase 7

- 7.1, 7.2, 7.3:  
  - `docs/architecture.md`  
  - `docs/threat-model.md`  
  - `docs/runbook.md`  
  - `docs/onboarding.md`  
  - `docs/report/final-report.md`  
  - `docs/demo-script.md`
- 7.4: 
  - Code comment cleanup: `project_root/ext_authz/internal/cache/replay.go`  
  - Code organization cleanup: `project_root/ext_authz/internal/cache/replay.go` + `project_root/ext_authz/main.go` refactor
- 7.5:  
  - `project_root/scripts/verify-submission.sh`  
  - `README.md` submission evidence section
  - `project_root/Timeline.md` submission gate status

## Live demo checklist

1. `docker-compose up --build -d`
2. `source clients/curl-scripts/lib-keycloak.sh && wait_for_keycloak`
3. `project_root/tests/run-all.sh`
4. `project_root/docs/demo-script.md`

## Pre-submission verification

```bash
bash project_root/scripts/verify-submission.sh
```
