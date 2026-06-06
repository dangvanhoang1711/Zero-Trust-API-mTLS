# Subnet Configuration

## Public Subnet - `10.0.0.0/20`

| Setting | Value |
|---------|-------|
| Auto-assign public IP | Enabled |
| Route `0.0.0.0/0` | Internet Gateway |
| Associated instances | EC2-Envoy, EC2-Services |

Both instances are in the same subnet:

| Instance | Private IP | Public IP | Workload |
|----------|------------|-----------|----------|
| EC2-Envoy | `10.0.5.131` | `13.238.159.245` | Envoy, backend, frontend |
| EC2-Services | `10.0.2.27` | `3.106.196.141` | ext_authz, Keycloak, Vault, Redis |

This is a management-friendly layout, but it pushes more responsibility onto security groups because the subnet itself no longer separates edge and service workloads.

## Operational Guidance

- Use the public IP on EC2-Envoy for browser traffic and normal operator SSH access
- Use the public IP on EC2-Services only for tightly controlled administration if you need it
- Keep all application dependencies on private IPs, especially the EC2-Envoy to EC2-Services calls

## Recommended NACL Approach

Because both hosts share one subnet, keep the NACL relatively simple and let security groups enforce host-level policy. A restrictive NACL that tries to model per-host policy in a shared subnet is easy to get wrong.

### Example Inbound Rules

| Rule # | Protocol | Port Range | Source | Action |
|--------|----------|------------|--------|--------|
| 100 | All | All | `10.0.0.0/20` | Allow |
| 110 | TCP | `443` | `0.0.0.0/0` | Allow |
| 120 | TCP | `22` | `<admin-ip>/32` | Allow |
| 130 | TCP | `1024-65535` | `0.0.0.0/0` | Allow |
| * | All | All | `0.0.0.0/0` | Deny |

### Example Outbound Rules

| Rule # | Protocol | Port Range | Destination | Action |
|--------|----------|------------|-------------|--------|
| 100 | All | All | `10.0.0.0/20` | Allow |
| 110 | TCP | `80` | `0.0.0.0/0` | Allow |
| 120 | TCP | `443` | `0.0.0.0/0` | Allow |
| 130 | TCP | `1024-65535` | `0.0.0.0/0` | Allow |
| * | All | All | `0.0.0.0/0` | Deny |

Notes:

- NACLs are stateless, so return traffic needs the ephemeral-port rules
- The NACL above does not differentiate EC2-Envoy from EC2-Services
- Do not rely on the subnet NACL to keep Keycloak, Vault, Redis, or ext_authz private; use security groups for that
