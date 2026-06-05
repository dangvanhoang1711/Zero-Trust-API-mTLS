# Zero Trust API Gateway with mTLS

A zero-trust API gateway prototype implementing mutual TLS authentication, ES256 JWT-based authorization, token-certificate proof-of-possession, and replay protection. Deployed across two EC2 instances with Envoy as the edge proxy, a Go ext_authz service for authorization, Keycloak as the identity provider, and HashiCorp Vault for PKI.

```
Internet → EC2-1: Envoy (mTLS/tls) ──gRPC──→ EC2-2: ext_authz (authorization)
                ├── Backend (Flask API)              ├── Keycloak (IdP, ES256 JWT)
                └── Frontend (React SPA)             ├── Vault (PKI Root→Int→Certs)
                                                     └── Redis (JTI replay cache)
```

## Repository Structure

```
zero-trust-api-gateway/
├── backend/                  # Flask API server (routes, services, app)
├── benchmarks/               # Load test scripts and visualization
├── docs/                     # Architecture, threat model, deployment, demo
├── envoy/                    # Envoy proxy config + TLS certs
├── ext_authz/                # Go gRPC authorization service
├── frontend/                 # React SPA (TypeScript + Vite)
│   └── legacy-flask/         # Old Flask frontend (reference only)
├── infrastructure/           # AWS, Docker, K8s deployment files
├── keycloak/                 # Realm export, client configs
├── scripts/                  # Deploy, client, PKI helper scripts
├── tests/                    # Functional + security test suites
├── vault/                    # Vault PKI scripts + artifacts
├── docker-compose.yml        # Compose file (private stack)
├── docker-compose.public.yml # Compose file (public stack)
└── .gitignore
```

## Quickstart (2 EC2 Deployment)

1. **Provision** two t3.medium+ EC2 instances (Ubuntu 24.04):
   - EC2-1 (public subnet): Envoy + Backend + Frontend
   - EC2-2 (private subnet): ext_authz + Keycloak + Vault + Redis

2. **Install Docker + docker-compose-plugin** on both instances.

3. **Clone** this repo on both instances.

4. **Deploy private stack** on EC2-2:
   ```bash
   docker compose -f docker-compose.yml up --build -d
   bash vault/scripts/gen-pki-vault.sh
   ```

5. **Deploy public stack** on EC2-1:
   ```bash
   docker compose -f docker-compose.public.yml up --build -d
   ```

6. **Test**:
   ```bash
   bash tests/run-all.sh
   ```

## Branches

| Branch | Purpose |
|--------|---------|
| `dev` | Active development |
| `feature/*` | Individual feature branches |

## Team Members

- (Add team members here)

## License

MIT
