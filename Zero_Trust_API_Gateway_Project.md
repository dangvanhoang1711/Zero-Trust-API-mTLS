# Zero Trust API Gateway Project

## Team Management, Repository Structure, and AWS Deployment Plan

## 1. Project Overview

### Architecture

```text
AWS VPC 10.0.0.0/16
|
+-- Public Subnet 10.0.0.0/20
    |
    +-- EC2-Envoy
    |   private: 10.0.5.131
    |   public:  13.238.159.245
    |   workloads:
    |     - Envoy Gateway
    |     - Frontend (React + Nginx)
    |     - Backend API
    |
    +-- EC2-Services
        private: 10.0.2.27
        public:  3.106.196.141
        workloads:
          - ext_authz
          - Keycloak
          - Vault
          - Redis
          - pki-init
```

### Runtime Access Model

- Public browser and API entrypoint: `https://13.238.159.245/`
- Frontend pages are served by Envoy on `443`, then routed to the frontend container
- `/api/*`, `/protected`, and `/health` are routed by Envoy to the backend
- Envoy reaches Keycloak, ext_authz, Vault, and Redis on EC2-Services over the private IP `10.0.2.27`
- EC2-Services has a public IP for administration, but its service ports should remain closed to the public internet

## 2. Team Members and Responsibilities

### Hoang Minh Hieu

Main responsibilities:

- Identity and PKI layer

Modules:

- Keycloak
- Vault
- mTLS
- Certificate lifecycle
- JWT issuance
- Certificate issuance

Deliverables:

```text
/keycloak
/vault
/docs/pki
```

Tasks:

- Configure Keycloak realm
- Configure OAuth2 and OIDC
- Configure clients and roles
- Set up Vault PKI engine
- Generate root and intermediate CAs
- Generate client and server certificates
- Maintain the mTLS trust chain

### Nhu Hoang

Main responsibilities:

- Authorization layer and backend

Modules:

- ext_authz
- Backend
- Redis
- Replay protection

Deliverables:

```text
/ext_authz
/backend
```

Tasks:

- JWT validation
- OIDC discovery
- JWKS retrieval
- `cnf.x5t#S256` validation
- Replay protection
- Redis integration
- Backend API development
- Business logic

### Van Hoang

Main responsibilities:

- Infrastructure and deployment

Modules:

- AWS
- Docker
- Envoy
- Networking
- Frontend deployment

Deliverables:

```text
/infrastructure
/envoy
/frontend
```

Tasks:

- Create AWS infrastructure
- Create VPC, subnet, and security groups
- Configure EC2 hosts
- Configure Docker and Docker Compose
- Deploy Envoy, frontend, and backend
- Configure routing and DNS

## 3. Git Workflow

### Main Branches

```text
main
develop
feature/hieu-keycloak-vault
feature/nhuhoang-authz-backend
feature/vanhoang-infrastructure
```

### Merge Flow

```text
feature/* -> develop -> main
```

Rules:

- Never commit directly to `main`
- Merge feature branches into `develop`
- Test before promoting to `main`

## 4. Repository Structure

```text
Zero-Trust-API-mTLS/
|
+-- frontend/
+-- backend/
+-- ext_authz/
+-- envoy/
+-- keycloak/
+-- vault/
+-- infrastructure/
+-- scripts/
+-- docs/
+-- README.md
```

## 5. Deployment Plan

### EC2-Envoy

Workloads:

```text
frontend
backend
envoy
```

Host networking:

```text
private IP: 10.0.5.131
public IP:  13.238.159.245
published ports:
  443    -> Envoy HTTPS entrypoint
  10001  -> Envoy health and baseline TLS
  9901   -> Envoy admin (localhost only)
```

### EC2-Services

Workloads:

```text
keycloak
ext-authz
vault
redis
pki-init
```

Host networking:

```text
private IP: 10.0.2.27
public IP:  3.106.196.141
application ports used from EC2-Envoy:
  8443   -> Keycloak HTTPS
  50051  -> ext_authz gRPC
  8200   -> Vault HTTPS
  6379   -> Redis
```

Operational rule:

- Use the private IP `10.0.2.27` for all application traffic from EC2-Envoy
- Keep public access on EC2-Services limited to SSH or explicit operator-only maintenance flows

## 6. Docker Compose Summary

### `docker-compose.public.yml`

Purpose:

- Runs the browser-facing edge stack on EC2-Envoy

Current shape:

```yaml
services:
  frontend:
    build: ../../frontend

  backend:
    build: ../../backend

  envoy:
    image: envoyproxy/envoy:v1.31-latest
    ports:
      - "443:10000"
      - "10001:10001"
      - "127.0.0.1:9901:9901"
```

### `docker-compose.private.yml`

Purpose:

- Runs the identity and authorization stack on EC2-Services

Current shape:

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    ports:
      - "${KEYCLOAK_HTTP_HOST_PORT:-8081}:8080"
      - "${KEYCLOAK_HTTPS_HOST_PORT:-18080}:8443"

  vault:
    image: hashicorp/vault:1.15
    ports:
      - "8200:8200"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  ext-authz:
    build: ../../ext_authz
    ports:
      - "50051:50051"
```

## 7. Authentication Flow

### Browser Flow

```text
Browser
  -> Envoy on EC2-Envoy
  -> Frontend
  -> /api/auth/login via Envoy
  -> Backend
  -> Keycloak on EC2-Services
  -> JWT returned to the browser session
```

### Protected API Flow

```text
Client
  -> Envoy on EC2-Envoy
  -> ext_authz on EC2-Services
     - JWT verification
     - certificate thumbprint binding
     - route policy check
     - replay detection
  -> Backend
```

## 8. Core Security Components

### Vault PKI

- Issues the root and intermediate CA hierarchy
- Issues server and client certificates
- Regenerates Keycloak thumbprint bindings to match current client certificates

### Keycloak

- Acts as the OIDC identity provider
- Publishes discovery and JWKS endpoints
- Issues ES256 JWTs
- Supports certificate-bound client tokens for Postman demos

### Redis Replay Cache

- Stores used `jti` values
- Rejects the same JWT on replay
- Falls back to in-memory replay protection if Redis is unavailable

### Envoy Gateway

- Terminates public HTTPS on `443`
- Serves browser routes through the frontend container
- Sends API traffic through `ext_authz` before routing to backend
- Forwards client-certificate details in XFCC when a certificate is presented

## 9. Deployment Commands

Preferred end-to-end deployment from your workstation:

```bash
bash scripts/deploy-ec2-split.sh
```

Direct SSH paths:

```bash
ssh -i ./my_private.pem ubuntu@13.238.159.245
ssh -i ./ec2_key.pem ubuntu@3.106.196.141
```

Or hop from EC2-Envoy to EC2-Services over the private IP:

```bash
ssh -i ./my_private.pem ubuntu@13.238.159.245
ssh -i ~/ec2_key.pem ubuntu@10.0.2.27
```

## 10. Demo Endpoints

- Frontend: `https://13.238.159.245/login`
- Public API: `https://13.238.159.245/api/public`
- Protected API: `https://13.238.159.245/api/profile`
- Health: `https://13.238.159.245:10001/health`

For certificate-binding demos, use:

- `demo-client` token with `client-chain.crt`
- `demo-client-mismatch` token with the normal client certificate to trigger binding failure
- the same JWT twice to trigger replay detection
