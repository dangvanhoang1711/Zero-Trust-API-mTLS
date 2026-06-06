# VPC Architecture

## CIDR and Subnet Layout

| Resource | CIDR | Description |
|----------|------|-------------|
| VPC | `10.0.0.0/16` | Zero Trust VPC |
| Public subnet | `10.0.0.0/20` | Hosts both EC2-Envoy and EC2-Services |

The current deployment keeps both instances in the same public subnet and gives both hosts public IPs, but service-to-service traffic should still stay on private IPs.

## Instances in the VPC

| Instance | Private IP | Public IP | Purpose |
|----------|------------|-----------|---------|
| EC2-Envoy | `10.0.5.131` | `13.238.159.245` | Public HTTPS ingress, frontend, backend |
| EC2-Services | `10.0.2.27` | `3.106.196.141` | Keycloak, Vault, Redis, ext_authz |

## Internet Gateway

Attach an Internet Gateway to the VPC and associate the public subnet route table with it. Both hosts need outbound internet access for package and container image pulls.

## Route Table

| Destination | Target |
|-------------|--------|
| `10.0.0.0/16` | `local` |
| `0.0.0.0/0` | Internet Gateway |

## East-West Connectivity

- EC2-Envoy reaches EC2-Services over private IP `10.0.2.27`
- Key application ports are `8443`, `50051`, `8200`, and `6379`
- Security groups, not subnet structure, provide the main isolation boundary in this layout

## VPC Flow Logs

Enable VPC Flow Logs for the VPC or the subnet to capture accepted and rejected traffic. This is especially useful here because both instances are in the same subnet and most policy separation happens at the security group layer.

Recommended defaults:

- capture both accepted and rejected traffic
- keep at least 30 days in CloudWatch Logs
- alert on unexpected public probes against the EC2-Services public ENI
