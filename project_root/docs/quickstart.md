# Quickstart Guide

## Prerequisites

- Docker
- Docker Compose
- curl
- openssl (optional, for certificate inspection)

## Start the Stack

From the repository root:

```bash
docker-compose up --build -d
```

Check that all services are running:

```bash
docker-compose ps
```

Expected services:

- `keycloak` — Identity provider for JWT issuance
- `ext_authz` — gRPC authorization service
- `backend` — Echo service backend
- `envoy` — mTLS gateway and proxy

## Run End-to-End Tests

```bash
cd project_root
./tests/run-all.sh
```

Expected output:

```
All MVP demo tests passed
```

## Endpoints

- **Envoy API Gateway**: `https://localhost:10000`
- **Keycloak Admin Console**: `http://localhost:18080`
  - Username: `admin`
  - Password: `admin`
- **Keycloak Realm**: `zero-trust`
- **Token Endpoint**: `http://localhost:18080/realms/zero-trust/protocol/openid-connect/token`

## Architecture Overview

```
Client (mTLS cert + JWT)
    ↓
Envoy (TLS termination + mTLS verification)
    ↓
ext_authz (JWT verification + token-cert binding + replay check)
    ↓
Backend (echo service)
```

## Security Behavior

The system enforces zero-trust authorization:

| Scenario | Expected Result |
|----------|----------------|
| Valid mTLS cert + valid bound JWT | `200 OK` |
| Missing bearer token | `401 Unauthorized` |
| Invalid or expired JWT | `401 Unauthorized` |
| Valid JWT with wrong `cnf.x5t#S256` binding | `403 Forbidden` |
| Replayed JWT ID (`jti`) | `403 Forbidden` |

## Useful Commands

### View logs

```bash
docker-compose logs -f envoy ext_authz keycloak
```

### Restart after config changes

```bash
docker-compose up --build -d
```

### Stop and remove containers

```bash
docker-compose down
```

### Inspect client certificate

```bash
openssl x509 -in project_root/infra/certs/client.crt -noout -text
```

### Calculate certificate thumbprint

```bash
openssl x509 -in project_root/infra/certs/client.crt -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256
```

This thumbprint must match the `cnf.x5t#S256` claim in the JWT for authorization to succeed.

## Troubleshooting

### Services not starting

Check logs:

```bash
docker-compose logs keycloak
docker-compose logs ext_authz
```

### Tests failing

Ensure services are fully ready:

```bash
docker-compose ps
```

Wait 10-15 seconds after startup for Keycloak to initialize.

### Certificate errors

Verify certificate files exist:

```bash
ls -la project_root/infra/certs/
```

Expected files:
- `client.crt`
- `client.key`
- `root-ca.crt`
- `server-chain.crt`
- `server.key`

## Next Steps

- Read `docs/architecture.md` for system design details
- Read `docs/security-analysis.md` for security properties
- Read `docs/threat-model.md` for threat analysis
- Read `docs/token-binding-design.md` for cryptographic binding details
