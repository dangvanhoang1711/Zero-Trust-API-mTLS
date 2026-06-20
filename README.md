# Zero Trust API Gateway with mTLS

A zero-trust API gateway prototype implementing mutual TLS authentication, ES256 JWT-based authorization, token-certificate proof-of-possession, and replay protection. Deployed across two EC2 instances with Envoy as the edge proxy, a Go ext_authz service for authorization, Keycloak as the identity provider, and HashiCorp Vault for PKI.

```
VPC: 10.0.0.0/16
Public Subnet: 10.0.0.0/20

EC2-Envoy (10.0.5.131)
  ├── Envoy (mTLS edge proxy)
  └── Frontend (React SPA)

     │ HTTPS │ gRPC
     ▼       ▼
EC2-Services (10.0.2.27)
  ├── Backend (Flask API)
  ├── ext-authz (Go authorization)
  ├── Keycloak (IdP, ES256 JWT)
  ├── Vault (PKI Root→Int→Certs)
  └── Redis (JTI replay cache)
```

## Repository Structure

```
zero-trust-api-gateway/
├── backend/                  # Flask API server (routes, services, app)
├── benchmarks/               # Load test scripts and visualization
├── docs/                     # Architecture, threat model, deployment, demo
├── envoy/                    # Envoy proxy config + TLS certs
│   ├── envoy.yaml            # Local dev config (Docker DNS)
│   └── envoy.ec2.yaml        # EC2 config (upstream → 10.0.2.27)
├── ext_authz/                # Go gRPC authorization service
├── frontend/                 # React SPA (TypeScript + Vite)
├── infrastructure/
│   └── docker/
│       ├── docker-compose.envoy.yml    # EC2-Envoy: envoy + frontend
│       ├── docker-compose.service.yml  # EC2-Services: all backends
│       └── docker-compose.test.yml     # Local dev: all services
├── keycloak/                 # Realm export, client configs
├── scripts/
│   ├── deploy-service.sh     # Deploy EC2-Services stack
│   └── deploy-envoy.sh       # Deploy EC2-Envoy stack (after service)
├── tests/                    # Functional + security test suites
└── vault/                    # Vault PKI scripts + artifacts
```

## Quickstart (2 EC2 Deployment)

1. **Provision** two EC2 instances in the same VPC:
   - **EC2-Envoy** (public subnet, 10.0.5.131): Envoy + Frontend
   - **EC2-Services** (private subnet, 10.0.2.27): Backend + ext-authz + Keycloak + Vault + Redis

2. **Install Docker + docker-compose-plugin** on both instances.

3. **Clone** this repo on both instances.

4. **Deploy services** on EC2-Services:
   ```bash
   bash scripts/deploy-service.sh
   ```
   This generates TLS certs and uploads them to S3.

5. **Deploy envoy** on EC2-Envoy:
   ```bash
   bash scripts/deploy-envoy.sh
   ```
   This downloads certs from S3 and starts envoy + frontend.

6. **Test**:
   ```bash
   curl -sk --cert envoy/certs/client.crt --key envoy/certs/client.key \
     https://13.238.159.245/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin"}'
   ```

## Local Development

```bash
docker compose -f infrastructure/docker/docker-compose.test.yml up -d --build
```

## Branches

| Branch | Purpose |
|--------|---------|
| `dev` | Active development |
| `feature/*` | Individual feature branches |

## License

MIT
