# Security Groups

## EC2-1 Security Group (Public Subnet)

Controls traffic to the public-facing Envoy proxy, backend API, and frontend.

### Inbound Rules

| Type      | Protocol | Port    | Source                    | Description                         |
|-----------|----------|---------|---------------------------|-------------------------------------|
| HTTPS     | TCP      | 443     | 0.0.0.0/0                | Envoy mTLS endpoint (production)   |
| HTTP      | TCP      | 80      | 0.0.0.0/0                | Envoy plain-text endpoint           |
| Custom TCP| TCP      | 10001   | 0.0.0.0/0                | Envoy baseline TLS port             |
| Custom TCP| TCP      | 10002   | 0.0.0.0/0                | Envoy HTTP fallback                 |
| SSH       | TCP      | 22      | <your-ip>/32             | Administrative access               |

### Outbound Rules

| Type      | Protocol | Port Range | Destination            | Description                         |
|-----------|----------|------------|------------------------|-------------------------------------|
| All TCP   | TCP      | 0-65535    | sg-ec2-2 (sg-xxxxxxx) | Communication to private services   |
| HTTPS     | TCP      | 443        | 0.0.0.0/0             | Package updates, container registries|
| HTTP      | TCP      | 80         | 0.0.0.0/0             | OS package repos                    |

> **Note:** Outbound to EC2-2 uses the security group ID as the destination, not the subnet CIDR. This ensures traffic is only permitted to instances in the EC2-2 security group.

## EC2-2 Security Group (Private Subnet)

Controls traffic to the sensitive infrastructure services. Only accepts traffic from EC2-1.

### Inbound Rules

| Type      | Protocol | Port    | Source                    | Description                         |
|-----------|----------|---------|---------------------------|-------------------------------------|
| Custom TCP| TCP      | 8080    | sg-ec2-1 (sg-xxxxxxx)    | Keycloak OIDC / admin API           |
| Custom TCP| TCP      | 50051   | sg-ec2-1 (sg-xxxxxxx)    | ext-authz gRPC service              |
| Custom TCP| TCP      | 8200    | sg-ec2-1 (sg-xxxxxxx)    | Vault API (PKI, secrets)            |
| Custom TCP| TCP      | 6379    | sg-ec2-1 (sg-xxxxxxx)    | Redis (replay cache, rate limiting) |
| SSH       | TCP      | 22      | <your-ip>/32             | Administrative access               |

### Outbound Rules

| Type      | Protocol | Port Range | Destination  | Description                         |
|-----------|----------|------------|--------------|-------------------------------------|
| HTTPS     | TCP      | 443        | 0.0.0.0/0   | Package updates, container registries|
| HTTP      | TCP      | 80         | 0.0.0.0/0   | OS package repos                    |

## Security Group Architecture

```
Internet ──► [SG-EC2-1] ──► EC2-1 (Envoy + Backend + Frontend)
                              │
                              │ (traffic to sg-ec2-1)
                              ▼
                   [SG-EC2-2] ──► EC2-2 (Keycloak + Vault + Redis + ext-authz)
```

- Traffic flows **only** from EC2-1 → EC2-2 (not the reverse).
- EC2-2 has **no inbound access from the internet** — all administrative access is through EC2-1 (SSH from your IP only).
- Security Groups are stateful: return traffic is automatically allowed without explicit outbound rules.
- Using security group IDs as source/destination (rather than CIDR) enables dynamic instance membership.

## Security Considerations

1. **Least privilege**: EC2-2 inbound rules reference sg-ec2-1 instead of the subnet CIDR, ensuring only EC2-1 instances can reach private services.
2. **No direct internet for EC2-2**: Outbound internet access goes through the NAT Gateway, and outbound SSH is not permitted from EC2-2.
3. **SSH access**: Restrict SSH to your bastion IP (/32). Consider using AWS Systems Manager Session Manager as an alternative to SSH.
4. **Monitoring**: Enable VPC Flow Logs and Security Group change notifications via AWS Config.
5. **Automation**: Manage Security Group rules with Infrastructure as Code (Terraform, CloudFormation, or CDK) to prevent drift.
