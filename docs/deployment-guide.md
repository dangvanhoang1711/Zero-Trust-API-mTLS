# Deployment Guide - Zero Trust API Gateway

## Target Topology

| Instance | Role | Private IP | Public IP |
|----------|------|------------|-----------|
| EC2-Envoy | Envoy, backend, frontend | `10.0.5.131` | `13.238.159.245` |
| EC2-Services | ext_authz, Keycloak, Vault, Redis | `10.0.2.27` | `3.106.196.141` |

The deployment uses one VPC (`10.0.0.0/16`) and one public subnet (`10.0.0.0/20`). Both instances have public IPs for administration. Application traffic should still use the private addresses shown above.

## Prerequisites

- AWS account with EC2, VPC, subnet, and security group permissions
- Two Ubuntu 24.04 EC2 instances sized at least `t3.medium`
- Local access to both SSH keys:
  - `my_private.pem` for EC2-Envoy
  - `ec2_key.pem` for EC2-Services
- Docker Engine and `docker compose` on both hosts
- Local `git`, `curl`, and `openssl`

Install the host prerequisites on both EC2 instances:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git curl openssl
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
```

## AWS Networking

- VPC CIDR: `10.0.0.0/16`
- Public subnet CIDR: `10.0.0.0/20`
- Route `0.0.0.0/0` from the subnet to an Internet Gateway
- Restrict security groups as described in `infrastructure/aws/security-groups.md`
- Keep application traffic on private IPs:
  - EC2-Envoy -> EC2-Services `10.0.2.27:8443` for Keycloak
  - EC2-Envoy -> EC2-Services `10.0.2.27:50051` for ext_authz
  - EC2-Envoy -> EC2-Services `10.0.2.27:8200` for Vault
  - EC2-Envoy -> EC2-Services `10.0.2.27:6379` for Redis

## Preferred Deployment Path

The repo now includes a split-host deploy helper whose defaults match the current topology:

```bash
bash scripts/deploy-ec2-split.sh
```

What it does:

- archives the local repo
- uploads it to EC2-Envoy
- hops from EC2-Envoy to EC2-Services with `ec2_key.pem`
- deploys the service stack first
- copies the generated certificate bundle back to EC2-Envoy
- deploys the edge stack and runs baseline HTTPS checks

Useful overrides:

```bash
PUBLIC_HOST=13.238.159.245 \
PUBLIC_PRIVATE_IP=10.0.5.131 \
PRIVATE_HOST=10.0.2.27 \
PUBLIC_USER=ubuntu \
PRIVATE_USER=ubuntu \
bash scripts/deploy-ec2-split.sh
```

## Manual Host Access

SSH to EC2-Envoy from your workstation:

```bash
ssh -i ./my_private.pem ubuntu@13.238.159.245
```

SSH from EC2-Envoy to EC2-Services over the private address:

```bash
ssh -i ~/ec2_key.pem ubuntu@10.0.2.27
```

If your security group allows direct admin access to the service host, you can also connect from your workstation:

```bash
ssh -i ./ec2_key.pem ubuntu@3.106.196.141
```

## Runtime Endpoints

- Browser UI: `https://13.238.159.245/login`
- Public API: `https://13.238.159.245/api/public`
- Protected API: `https://13.238.159.245/api/profile`
- Envoy health: `https://13.238.159.245:10001/health`
- Keycloak discovery from inside the VPC: `https://10.0.2.27:8443/realms/zero-trust/.well-known/openid-configuration`
- Vault health from inside the VPC: `https://10.0.2.27:8200/v1/sys/health`

## Verification

Baseline HTTPS checks from EC2-Envoy:

```bash
cd /home/ubuntu/zero-trust
curl --cacert envoy/certs/root-ca.crt https://localhost:10001/health
curl --cacert envoy/certs/root-ca.crt https://localhost/login -I
curl --cacert envoy/certs/root-ca.crt https://localhost/api/public
```

Protected API check with a certificate-bound client token:

```bash
ssh -i ./my_private.pem -L 18443:10.0.2.27:8443 ubuntu@13.238.159.245
```

In another shell:

```bash
TOKEN=$(curl --silent --show-error --cacert envoy/certs/root-ca.crt \
  -X POST https://localhost:18443/realms/zero-trust/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=demo-client \
  -d client_secret=demo-client-secret | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl --cert envoy/certs/client-chain.crt \
  --key envoy/certs/client.key \
  --cacert envoy/certs/root-ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://13.238.159.245/api/profile
```

Expected result: `HTTP 200` with the backend status payload.

## DNS and TLS Notes

- `https://13.238.159.245` uses a Vault-issued certificate, so browsers will warn unless you trust the project root CA
- For production, replace the server certificate with one issued for your real DNS name by a public CA
- If you add a DNS name, reissue the Envoy and backend server certificates with the domain in SAN

## Troubleshooting

### Public site works but protected requests fail

- Confirm EC2-Envoy can reach `10.0.2.27` on `8443`, `50051`, `8200`, and `6379`
- Check Envoy logs: `docker compose -f infrastructure/docker/docker-compose.public.yml logs --tail=80 envoy`
- Check ext_authz logs: `docker compose -f infrastructure/docker/docker-compose.private.yml logs --tail=80 ext-authz`

### Browser shows certificate warnings

- The deployment uses a private CA
- Import `envoy/certs/root-ca.crt` into the client trust store, or replace the server certificate with a public CA certificate

### Postman certificate-binding demos fail

- Make sure Postman presents `envoy/certs/client-chain.crt` and `envoy/certs/client.key` to `13.238.159.245:443`
- Use a `demo-client` or `demo-client-mismatch` token, not the browser `web-app` token
- Do not reuse the same JWT twice unless you are intentionally testing replay detection

### Service stack is healthy locally but unavailable from EC2-Envoy

- Recheck the EC2-Services security group rules for `8443`, `50051`, `8200`, and `6379`
- Recheck NACLs if you use custom ones
- Verify EC2-Envoy is targeting the private IP `10.0.2.27`, not the public IP
