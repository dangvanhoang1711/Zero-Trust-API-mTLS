# Zero-Trust API Authentication Gateway (mTLS + PoP)

This repository implements a zero-trust API gateway prototype using:

- Envoy as API gateway + external auth filter
- Go `ext_authz` service for authorization policy
- Keycloak as identity provider
- Client-certificate + token proof-of-possession checks
- Protected example microservice

## Project structure

- `project_root/envoy_config/` — Envoy listener/filter/route configuration
- `project_root/ext_authz/` — Go ext_authz service (JWT verification, mTLS binding, DPoP, replay cache)
- `project_root/infra/services/` — demo backend services (`echo`, `protected-api`)
- `project_root/tests/` — functional, resilience and security test scripts
- `project_root/benchmarks/` — load scripts and plotting helpers
- `project_root/docs/` — architecture, threat model, runbook, final report

## Quick start

From repository root:

```bash
git clone ...
cd /home/nhuhoang/Crypto/Zero-Trust-API-mTLS

docker-compose up --build -d
```

Then follow:

- [Quickstart Guide](project_root/docs/quickstart.md)
- [Final Report](project_root/docs/report/final-report.md)
- [Kubernetes bootstrap (minikube/k3d + cert-manager)](project_root/docs/k8s-cert-manager-bootstrap.md)

## Useful checks

```bash
docker-compose ps
docker-compose logs -f --tail=80 envoy ext_authz backend protected-api
```

## Submission evidence

- [Submission evidence matrix](project_root/docs/submission-evidence-matrix.md)
- [Submission verifier](project_root/scripts/verify-submission.sh)
- [DPoP mock/extend setup](project_root/docs/keycloak-dpop-mock.md)

## Test entrypoints

```bash
cd project_root
./tests/run-all.sh
cd tests/security
./run-all-security.sh
```

## Notes

The full architecture folder (`project_root/infra/k8s`) contains Kubernetes manifests for reference; the current reproducible execution path for grading is Docker Compose.

Security note: `ext_authz` can optionally verify inbound client certificate chains when `CLIENT_CA_BUNDLE` is set to a PEM CA bundle.

### Optional ABAC / Policy + Rate Limiting

You can enable policy-driven authorization by setting:

```bash
AUTHZ_POLICY_FILE=project_root/ext_authz/config/authz-policy.yaml docker-compose up --build -d
```

- Sample policy file: `project_root/ext_authz/config/authz-policy.yaml`
- Supports route-based scope checks and per-identity request rate limiting.

## Kubernetes deployment option

- Helm chart: `project_root/infra/helm/zero-trust-mtls`  
- Bootstrap script: `project_root/scripts/setup-k8s-cluster.sh`

## Submission gate

Run before handing in:

```bash
cd /home/nhuhoang/Crypto/Zero-Trust-API-mTLS
bash project_root/scripts/verify-submission.sh
```

Then do:

```bash
cd /home/nhuhoang/Crypto/Zero-Trust-API-mTLS
git tag -a v1.0-submission -m "Zero-Trust API Auth submission"
```

If `git tag` fails in a read-only filesystem, create the tag in your normal writable workspace before submitting.
