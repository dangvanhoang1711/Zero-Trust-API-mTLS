# Deployment Guide — Zero Trust API Gateway

## Prerequisites

- **AWS Account** with permissions to create EC2, VPC, subnets, security groups
- **Two EC2 instances** (recommended: `t3.medium` or larger)
  - EC2-1: Public subnet (Envoy + Backend + Frontend)
  - EC2-2: Private subnet (ext_authz + Keycloak + Vault + Redis)
- **Docker** 24+ and **docker-compose-plugin** on both instances
- **OpenSSL** for certificate verification
- **curl** for API testing
- **git** for cloning the repository

## AWS Infrastructure Setup

### Step 1: VPC and Networking

Reference the CloudFormation/Terraform templates in `infrastructure/aws/` (or create manually):

- **VPC**: 10.0.0.0/16
- **Public subnet (EC2-1)**: 10.0.1.0/24
- **Private subnet (EC2-2)**: 10.0.2.0/24
- **Internet Gateway**: Attached to public subnet route table
- **NAT Gateway**: In public subnet, for private subnet outbound traffic
- **Security Group - Public (EC2-1)**:
  - Inbound: TCP 443 (HTTPS), TCP 22 (SSH from bastion)
  - Outbound: All traffic
- **Security Group - Private (EC2-2)**:
  - Inbound: TCP 22 (SSH from jumpbox/bastion), TCP 50051 (gRPC from EC2-1 SG)
  - Outbound: All traffic (via NAT Gateway)

### Step 2: Launch EC2 Instances

| Instance | AMI | Type | Subnet | Security Group | Storage |
|----------|-----|------|--------|----------------|---------|
| EC2-1 | Ubuntu 24.04 LTS | t3.medium | Public | sg-public | 20 GB gp3 |
| EC2-2 | Ubuntu 24.04 LTS | t3.medium | Private | sg-private | 20 GB gp3 |

Use SSH key pairs for access. EC2-2 access requires a bastion/jumpbox in the public subnet.

**Install prerequisites on both instances**:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-plugin git openssl curl
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
```

Log out and back in for group changes to take effect.

### Step 3: Clone Repository on Both Instances

```bash
git clone <repository-url> /home/ubuntu/zero-trust-api-gateway
cd /home/ubuntu/zero-trust-api-gateway
```

---

## Deployment

### Step 4: Deploy Private Stack (EC2-2)

SSH to EC2-2 (via bastion):

```bash
ssh -J ubuntu@<bastion-ip> ubuntu@<ec2-2-private-ip>
cd /home/ubuntu/zero-trust-api-gateway
```

Run the private deployment script:

```bash
bash scripts/legacy/setup-private.sh
# OR manually:
docker compose -f docker-compose.private.yml up --build -d
```

This starts:
- **Keycloak** on port 8080
- **Vault** on port 8200
- **Redis** on port 6379
- **ext_authz** on port 50051 (gRPC)

**Verify private stack**:

```bash
docker compose -f docker-compose.private.yml ps

# Check Keycloak
curl -sf http://localhost:8080/realms/zero-trust/.well-known/openid-configuration | head -c 200

# Check Vault
curl -sf http://localhost:8200/v1/sys/health | python3 -m json.tool

# Check ext_authz (gRPC health)
docker compose -f docker-compose.private.yml logs --tail=20 ext-authz

# Bootstrap PKI
bash vault/scripts/bootstrap-pki.sh
```

### Step 5: Deploy Public Stack (EC2-1)

SSH to EC2-1:

```bash
ssh ubuntu@<ec2-1-public-ip>
cd /home/ubuntu/zero-trust-api-gateway
```

Run the public deployment script:

```bash
bash scripts/legacy/setup-public.sh
# OR manually:
docker compose -f docker-compose.public.yml up --build -d
```

This starts:
- **Envoy** on ports 10000 (mTLS), 10001 (TLS baseline), 18080 (Keycloak proxy)
- **Backend (Flask)** on port 8080
- **Frontend (React)** served via Nginx

**Verify public stack**:

```bash
docker compose -f docker-compose.public.yml ps

# Check Envoy admin
curl -sf http://localhost:9901/server_info

# Check backend health
curl -sf --insecure https://localhost:10000/api/public
```

### Step 6: Verify End-to-End

```bash
# Get a JWT from Keycloak
TOKEN=$(curl -sf -X POST http://<ec2-2-private-ip>:8080/realms/zero-trust/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-app&username=admin&password=admin" | \
  python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# Test mTLS API call with client certificate
curl --cert vault/artifacts/client.crt \
     --key vault/artifacts/client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://<ec2-1-public-ip>:10000/protected
```

Expected response: `{"authenticated": true, "user": "admin", ...}`

### Step 7: Deploy Frontend

```bash
# Build React frontend
cd frontend
npm install && npm run build
# Static files served by Nginx container (already configured in docker-compose)
```

---

## Post-Deployment

### DNS Setup

- Create an **A record** (e.g., `api.example.com`) pointing to EC2-1 public IP
- Update Envoy server certificate SAN to include the domain
- Re-issue server cert via Vault:

```bash
CERT_SAN_DNS="api.example.com" bash vault/scripts/gen-pki-vault.sh
```

### SSL Certificate

For production, replace Vault-issued server certificate with a publicly trusted certificate (Let's Encrypt, AWS Certificate Manager, etc.):

```bash
# Example with Let's Encrypt
sudo apt install -y certbot
sudo certbot certonly --standalone -d api.example.com
# Copy to Envoy TLS directory
sudo cp /etc/letsencrypt/live/api.example.com/{fullchain.pem,privkey.pem} envoy/certs/
```

### Monitoring

- **Envoy Admin**: `http://localhost:9901` (stats, config dump, logging)
- **Docker logs**: `docker compose logs -f --tail=80 envoy ext-authz backend`
- **Health check**: `curl -sf --insecure https://localhost:10000/api/public`
- **ext_authz metrics**: Prometheus metrics on port 9000 (if enabled)

---

## Troubleshooting

### Services not starting

```bash
# Check logs
docker compose logs envoy ext-authz backend keycloak vault redis

# Check for port conflicts
sudo netstat -tlnp | grep -E '10000|10001|8080|8200|6379|50051'
```

### Connection refused on Envoy port 10000

- Ensure EC2-1 security group allows inbound TCP 443/10000
- Verify Envoy container is running: `docker compose ps envoy`
- Check TLS certificates exist: `ls -la envoy/certs/`

### ext_authz gRPC connection failures

- EC2-1 → EC2-2 connectivity: check VPC peering / security group rules
- ext_authz must be reachable on port 50051 from EC2-1
- Verify in Envoy logs: `docker compose logs --tail=50 envoy | grep ext_authz`

### JWT validation failures

- Ensure Keycloak realm `zero-trust` is correctly imported (check `keycloak/realm-export.json`)
- Verify Keycloak uses ES256 signing algorithm
- Check JWKS endpoint: `curl -sf http://<ec2-2-ip>:8080/realms/zero-trust/protocol/openid-connect/certs`
- Verify ext_authz `ISSUER` environment variable matches Keycloak realm URL

### Certificate errors

```bash
# Verify certificate chain
openssl verify -CAfile vault/artifacts/root_ca.crt -untrusted vault/artifacts/intermediate_ca.crt vault/artifacts/client.crt

# Check certificate thumbprint (should match JWT cnf.x5t#S256)
openssl x509 -in vault/artifacts/client.crt -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256
```

### mTLS handshake failures

- Envoy requires client certificate on port 10000 (`require_client_certificate: true`)
- Ensure client cert is signed by the Intermediate CA trusted by Envoy
- Envoy trusted CA: `envoy/certs/trust/intermediate-ca.crt`

### Replay protection issues

- Check Redis connectivity if using Redis backend: `docker compose exec redis redis-cli ping`
- For in-memory cache, verify cache is shared (single-instance ext_authz only)
- Reset cache: `docker compose restart ext-authz`

### Common Commands

```bash
# Restart all services
docker compose down && docker compose up --build -d

# Reset everything (including volumes)
docker compose down -v && docker compose up --build -d

# Tail specific service logs
docker compose logs -f --tail=100 <service-name>

# Check container resource usage
docker stats

# Run functional tests
cd tests && bash run-all.sh

# Run security tests
cd tests/security && bash run-all-security.sh
```
