# VPC Architecture

## CIDR and Subnet Layout

| Resource         | CIDR           | Description              |
|------------------|----------------|--------------------------|
| VPC              | 10.0.0.0/16   | Zero-Trust mTLS VPC      |
| Public Subnet    | 10.0.1.0/24   | EC2-1 (Envoy, Backend, Frontend) |
| Private Subnet   | 10.0.2.0/24   | EC2-2 (Keycloak, Vault, Redis, ext-authz) |

## Internet Gateway

An Internet Gateway (IGW) is attached to the VPC and associated with the public subnet route table. This enables EC2-1 to receive inbound HTTPS traffic from the internet and to reach external services (e.g., package repositories, container registries).

## NAT Gateway

A NAT Gateway is provisioned in the public subnet with an Elastic IP. The private subnet route table directs `0.0.0.0/0` traffic to the NAT Gateway, allowing EC2-2 to download updates and container images without exposing a public IP.

## Route Tables

### Public Route Table (associated with public subnet)

| Destination     | Target     |
|-----------------|------------|
| 10.0.0.0/16    | local      |
| 0.0.0.0/0      | IGW        |

### Private Route Table (associated with private subnet)

| Destination     | Target         |
|-----------------|----------------|
| 10.0.0.0/16    | local          |
| 0.0.0.0/0      | NAT Gateway    |

## VPC Flow Logs

Enable VPC Flow Logs for the VPC, all subnets, or individual ENIs to capture IP traffic metadata. Deliver logs to CloudWatch Logs or S3 for security analysis and anomaly detection.

Recommendations:

- Capture all accepted and rejected traffic.
- Set a reasonable retention period (e.g., 30 days in CloudWatch, archive to S3 Glacier after 90 days).
- Monitor for unexpected rejected connection attempts (indicates scanning or misconfiguration).
- Use Athena or CloudWatch Logs Insights to query flow logs for forensic investigations.

## Peering / Connectivity

- No VPC peering or VPN is required for this two-tier architecture.
- EC2-1 communicates with EC2-2 over the VPC internal network using private IPs.
- Security Groups (not NACLs alone) provide the primary traffic filtering boundary between tiers.
