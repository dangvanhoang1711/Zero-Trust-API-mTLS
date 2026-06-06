# Security Groups

The current topology uses two security groups in the same public subnet:

- `sg-ec2-envoy` for EC2-Envoy (`10.0.5.131`, `13.238.159.245`)
- `sg-ec2-services` for EC2-Services (`10.0.2.27`, `3.106.196.141`)

## sg-ec2-envoy

This group protects the public HTTPS entrypoint.

### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | `443` | `0.0.0.0/0` | Public HTTPS entrypoint |
| TCP | `10001` | `<admin-or-monitor-ip>/32` | Envoy health and baseline checks |
| TCP | `22` | `<admin-ip>/32` | Operator SSH |

### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| TCP | `8443` | `sg-ec2-services` | Keycloak discovery and token exchange |
| TCP | `50051` | `sg-ec2-services` | ext_authz gRPC |
| TCP | `8200` | `sg-ec2-services` | Vault API |
| TCP | `6379` | `sg-ec2-services` | Redis replay cache |
| TCP | `80,443` | `0.0.0.0/0` | OS updates and image pulls |

## sg-ec2-services

This group protects Keycloak, Vault, Redis, and ext_authz. The instance has a public IP, so the group is the main barrier preventing accidental exposure.

### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | `22` | `<admin-ip>/32` | Direct operator SSH, if needed |
| TCP | `22` | `sg-ec2-envoy` | Optional SSH hop from EC2-Envoy |
| TCP | `8443` | `sg-ec2-envoy` | Keycloak HTTPS |
| TCP | `50051` | `sg-ec2-envoy` | ext_authz gRPC |
| TCP | `8200` | `sg-ec2-envoy` | Vault API |
| TCP | `6379` | `sg-ec2-envoy` | Redis |

### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| TCP | `80,443` | `0.0.0.0/0` | OS updates and image pulls |
| TCP | `1024-65535` | `sg-ec2-envoy` | Return traffic |

## Security Group Architecture

```text
Internet -> sg-ec2-envoy -> EC2-Envoy
                          |
                          | private IP traffic
                          v
                    sg-ec2-services -> EC2-Services
```

## Recommendations

1. Keep `8443`, `50051`, `8200`, and `6379` closed to the public internet even though EC2-Services has a public IP.
2. Use security-group-to-security-group rules instead of broad CIDR rules for service ports.
3. Restrict SSH to admin IPs and prefer Session Manager if you later automate access.
4. Treat port `10001` as an operator-only endpoint, not a public health endpoint.
5. Monitor security group drift because subnet-level isolation is minimal in this layout.
