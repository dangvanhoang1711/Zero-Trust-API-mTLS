# Subnet Configuration

## Public Subnet — EC2-1 (10.0.1.0/24)

| Setting                  | Value                         |
|--------------------------|-------------------------------|
| Auto-assign public IP    | Enabled                       |
| Route 0.0.0.0/0         | Internet Gateway (igw-*)      |
| Associated instances     | EC2-1                         |

EC2-1 hosts the public-facing components:

- **Envoy Proxy** — TLS termination, mTLS enforcement, routing (ports 443/80/10001)
- **Backend API** — FastAPI application handling business logic (port 8080)
- **Frontend** — Vite/React SPA served on port 3000

Since this subnet requires direct internet access for HTTPS clients and outbound package downloads, instances receive a public IP and route default traffic through the IGW.

## Private Subnet — EC2-2 (10.0.2.0/24)

| Setting                  | Value                         |
|--------------------------|-------------------------------|
| Auto-assign public IP    | Disabled                      |
| Route 0.0.0.0/0         | NAT Gateway (nat-*)           |
| Associated instances     | EC2-2                         |

EC2-2 hosts the sensitive infrastructure components:

- **Keycloak** — Identity provider, OIDC token issuance (port 8080)
- **Vault** — PKI engine, secrets management (port 8200)
- **Redis** — Replay cache, rate-limiting state (port 6379)
- **ext-authz** — Envoy external authorization gRPC service (port 50051)

No public IP is assigned. Outbound internet access is routed through the NAT Gateway in the public subnet.

## Network ACLs

Network ACLs (NACLs) provide a stateless layer of defense at the subnet boundary. The following rules are recommended:

### Public Subnet NACL

| Rule # | Type      | Protocol | Port Range | Source/Dest     | Allow/Deny |
|--------|-----------|----------|------------|-----------------|------------|
| 100    | Inbound   | TCP      | 443        | 0.0.0.0/0       | Allow      |
| 110    | Inbound   | TCP      | 80         | 0.0.0.0/0       | Allow      |
| 120    | Inbound   | TCP      | 22         | <your-ip>/32    | Allow      |
| 130    | Inbound   | TCP      | 1024-65535 | 0.0.0.0/0       | Allow      |
| *      | Inbound   | All      | All        | 0.0.0.0/0       | Deny       |
| 100    | Outbound  | TCP      | 1024-65535 | 0.0.0.0/0       | Allow      |
| 110    | Outbound  | TCP      | 443        | 0.0.0.0/0       | Allow      |
| 120    | Outbound  | TCP      | 80         | 0.0.0.0/0       | Allow      |
| *      | Outbound  | All      | All        | 0.0.0.0/0       | Deny       |

### Private Subnet NACL

| Rule # | Type      | Protocol | Port Range | Source/Dest     | Allow/Deny |
|--------|-----------|----------|------------|-----------------|------------|
| 100    | Inbound   | TCP      | 8080       | 10.0.1.0/24     | Allow      |
| 110    | Inbound   | TCP      | 50051      | 10.0.1.0/24     | Allow      |
| 120    | Inbound   | TCP      | 8200       | 10.0.1.0/24     | Allow      |
| 130    | Inbound   | TCP      | 6379       | 10.0.1.0/24     | Allow      |
| 140    | Inbound   | TCP      | 22         | <your-ip>/32    | Allow      |
| 150    | Inbound   | TCP      | 1024-65535 | 10.0.1.0/24     | Allow      |
| *      | Inbound   | All      | All        | 0.0.0.0/0       | Deny       |
| 100    | Outbound  | TCP      | 1024-65535 | 0.0.0.0/0       | Allow      |
| 110    | Outbound  | TCP      | 443        | 0.0.0.0/0       | Allow      |
| 120    | Outbound  | TCP      | 80         | 0.0.0.0/0       | Allow      |
| *      | Outbound  | All      | All        | 0.0.0.0/0       | Deny       |

> **Note:** NACLs are stateless, so ephemeral ports (1024-65535) must be explicitly allowed for return traffic. Security Groups are the preferred mechanism for stateful traffic filtering between EC2 instances.
