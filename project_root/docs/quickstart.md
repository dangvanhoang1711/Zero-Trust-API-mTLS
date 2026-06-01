# Quickstart Guide

## Prerequisites

- Docker
- Docker Compose
- curl
- openssl (optional, for certificate inspection)

## Start the Full Stack

From repository root:

```bash
cd /home/nhuhoang/Crypto/Zero-Trust-API-mTLS

docker-compose up --build -d
```

### Reproduce from clean start

```bash
docker-compose down -v
docker-compose up --build -d
```

Wait for Keycloak token endpoint to become ready:

```bash
cd project_root
source clients/curl-scripts/lib-keycloak.sh
wait_for_keycloak
```

Check services:

```bash
docker-compose ps
```

Expected services:

- `keycloak` — Identity provider
- `ext_authz` — gRPC authorization service
- `backend` — echo service
- `protected-api` — protected demo API
- `envoy` — mTLS gateway

## Run End-to-End Security Tests

```bash
cd project_root
./tests/run-all.sh
```

Expected output:

```text
✓ All security tests passed
```

## Security Attack Scenarios

```bash
cd project_root
tests/security/run-all-security.sh
```

Expected output:

```text
✓ Security scenario tests passed
```

## Live Demo Script

Use the prepared demo checklist for presentation:
- Open [`demo-script.md`](demo-script.md) and run each command section manually.

## Run Performance Benchmarks

```bash
cd project_root/benchmarks
REQUESTS=200 SAMPLE_INTERVAL=1 INCLUDE_RESOURCE_SAMPLING=1 ./scripts/run-load-benchmarks.sh
```

Generated outputs:

- `project_root/benchmarks/results/baseline-latency.csv`
- `project_root/benchmarks/results/mtls-only-latency.csv`
- `project_root/benchmarks/results/mtls-pop-latency.csv`
- `project_root/benchmarks/results/benchmark-summary.csv`
- `project_root/benchmarks/results/*-resource.csv`

Baseline profile in benchmark suite runs against `https://localhost:10001`:
- listener uses TLS-only (no client cert required)
- no mTLS binding checks
- valid bearer token is still sent for realistic request shape

## Protected API Smoke Check

Use `tests/security/` or run this custom check:

```bash
cd project_root
source clients/curl-scripts/lib-keycloak.sh
TOKEN="$(get_access_token demo-client)"

# protected endpoint call (requires mTLS + bound token)
curl --cert infra/certs/client.crt --key infra/certs/client.key --cacert infra/certs/root-ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/protected
```

Without the `x-auth-user`/PoP headers, this endpoint returns `401`.

### Optional: enable simple scope enforcement

```bash
# one variable supports space-separated scopes (or pass comma-separated in REQUIRED_SCOPES)
REQUIRED_SCOPE="api:read api:write" docker-compose up -d --force-recreate ext_authz
```

If enabled, ensure issued token contains the required scope claim before calling protected endpoint.

### Optional: validate client certificate chain in ext_authz

```bash
CLIENT_CA_BUNDLE=project_root/infra/certs/root-ca.crt docker-compose up -d --force-recreate ext_authz
```

When set, `ext_authz` validates the presented client certificate against the provided CA bundle before token binding.

### Optional: enable policy/rate-limiting with YAML

```bash
AUTHZ_POLICY_FILE=ext_authz/config/authz-policy.yaml docker-compose up -d --force-recreate ext_authz
```

Sample rules:
- Route-based ABAC (`token_subjects`, `required_scopes`)
- Optional per-route rate limit (`rate_limit`)

### Optional: enable Redis-backed replay cache

```bash
REPLAY_BACKEND=redis \
REPLAY_REDIS_URL=redis://replay-cache:6379/0 \
REPLAY_REDIS_KEY_PREFIX=zero-trust:replay \
docker-compose up -d --force-recreate ext_authz
```

If you do not have Redis in your environment, keep `REPLAY_BACKEND=memory` (default).

### Optional: run Keycloak DPoP mock flow (if native DPoP not enabled)

```bash
cd project_root
source clients/curl-scripts/lib-keycloak.sh
wait_for_keycloak
./clients/curl-scripts/06-ok-dpop-mock.sh
```

Notes:
- This uses `demo-client-dpop` and a local mock key pair in `project_root/clients/keys/dpop-mock/`.
- The client issue uses static `cnf.jkt`; it is a controlled mock flow for this project, not a production DPoP deployment pattern.

## Resilience Automation

Operational scenarios in `tests/functional`:

```bash
cd project_root/tests/functional
./run-all-resilience.sh
```

## Optional Visualization

```bash
cd project_root/benchmarks
python3 benchmarks/plots/plot-benchmarks.py \
  --results-dir results \
  --output-dir plots
```

## Endpoints

- **Envoy API Gateway**: `https://localhost:10000`
- **Baseline benchmark endpoint (TLS-only, no mTLS required)**: `https://localhost:10001/`
- **Protected API**: `https://localhost:10000/protected`
- **Keycloak Admin Console**: `http://localhost:18080`
  - Username: `admin`
  - Password: `admin`
- **Keycloak Realm**: `zero-trust`
- **Token Endpoint**: `http://localhost:18080/realms/zero-trust/protocol/openid-connect/token`

## Troubleshooting

### Services not starting

```bash
docker-compose logs keycloak ext_authz envoy
```

### Wait for warm-up

Keycloak may need 10–20 seconds before first token request.

### Certificate files

```bash
ls -la project_root/infra/certs/
```

Expected files:

- `client.crt`
- `client.key`
- `root-ca.crt`
- `server-chain.crt`
- `server.key`
- runtime TLS assets:
  - `project_root/envoy_config/tls/tls.crt`
  - `project_root/envoy_config/tls/tls.key`
  - `project_root/envoy_config/tls/trust/intermediate-ca.crt`
  - `project_root/envoy_config/tls/trust/ca.crl`

### Inspect token binding

```bash
openssl x509 -in project_root/infra/certs/client.crt -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256
```

This thumbprint should match token `cnf.x5t#S256`.
