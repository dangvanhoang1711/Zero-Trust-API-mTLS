# Zero Trust API Gateway Project

## Team Management, Repository Structure & AWS Deployment Plan

---

# 1. Project Overview

## Architecture

```text
AWS VPC
│
├── Public Subnet (10.0.1.0/24)
│
│    └── EC2-Public
│         ├── Frontend (React + Nginx)
│         └── Envoy Gateway (PEP)
│
└── Private Subnet (10.0.2.0/24)
     │
     ├── Keycloak (Identity Provider)
     ├── ext_authz (Policy Decision Point)
     ├── Backend API Service
     ├── Redis (Replay Cache)
     └── Vault (PKI / Certificate Authority)
```

---

# 2. Team Members & Responsibilities

## Hoàng Minh Hiếu

### Main Responsibilities

Identity & PKI Layer

### Modules

* Keycloak
* Vault
* mTLS
* Certificate Lifecycle
* JWT Issuance
* Certificate Issuance

### Deliverables

```text
/keycloak
/vault
/docs/pki
```

### Tasks

* Configure Keycloak Realm
* Configure OAuth2/OIDC
* Configure Clients
* Configure Roles
* Setup Vault PKI Engine
* Generate Root CA
* Generate Intermediate CA
* Generate Client Certificates
* Generate Envoy Certificates
* Configure mTLS Trust Chain

---

## Như Hoàng

### Main Responsibilities

Authorization Layer & Backend

### Modules

* ext_authz
* Backend
* Redis
* Replay Protection

### Deliverables

```text
/ext_authz
/backend
```

### Tasks

* JWT Validation
* OIDC Discovery
* JWKS Retrieval
* cnf.x5t#S256 Validation
* Replay Protection
* Redis Integration
* Backend API Development
* Business Logic

---

## Văn Hoàng

### Main Responsibilities

Infrastructure & Deployment

### Modules

* AWS
* Docker
* Envoy
* Networking
* Frontend Deployment

### Deliverables

```text
/infrastructure
/envoy
/frontend deployment
```

### Tasks

* Create AWS Infrastructure
* Create VPC
* Create Subnets
* Create Security Groups
* Configure EC2
* Configure Docker
* Configure Docker Compose
* Deploy Frontend
* Deploy Envoy
* Configure Routing
* Configure DNS

---

# 3. Git Workflow

## Main Branches

```text
main

develop

feature/hieu-keycloak-vault

feature/nhuhoang-authz-backend

feature/vanhoang-infrastructure
```

---

## Branch Ownership

### Hiếu

```bash
git checkout -b feature/hieu-keycloak-vault
```

Owns:

```text
keycloak/
vault/
docs/pki/
```

---

### Như Hoàng

```bash
git checkout -b feature/nhuhoang-authz-backend
```

Owns:

```text
backend/
ext_authz/
```

---

### Văn Hoàng

```bash
git checkout -b feature/vanhoang-infrastructure
```

Owns:

```text
frontend/
envoy/
infrastructure/
```

---

## Merge Flow

```text
feature/*
     ↓

develop
     ↓

main
```

Rules:

* Never commit directly to main
* Merge feature → develop
* Test
* Merge develop → main

---

# 4. Repository Structure

```text
Zero-Trust-API-mTLS/
│
├── frontend/
│
├── backend/
│
├── ext_authz/
│
├── envoy/
│
├── keycloak/
│
├── vault/
│
├── infrastructure/
│
├── scripts/
│
├── docs/
│
└── README.md
```

---

# 5. Detailed Repository Layout

```text
frontend/
│
├── src/
├── public/
├── package.json
└── Dockerfile

backend/
│
├── app/
├── routes/
├── services/
├── requirements.txt
└── Dockerfile

ext_authz/
│
├── app/
├── auth/
├── mtls/
├── replay/
├── oidc/
├── requirements.txt
└── Dockerfile

envoy/
│
├── envoy.yaml
├── certs/
└── Dockerfile

keycloak/
│
├── realm-export.json
└── README.md

vault/
│
├── policies/
├── scripts/
├── init.sh
└── README.md

infrastructure/
│
├── docker/
│
├── aws/
│
└── diagrams/

docs/
│
├── architecture.md
├── deployment.md
├── threat-model.md
└── demo-guide.md
```

---

# 6. EC2 Deployment Plan

## EC2-Public

### Containers

```text
frontend
envoy
```

### Public IP

```text
44.x.x.x
```

### Exposed Ports

```text
80
443
10000
```

---

## EC2-Private

### Containers

```text
keycloak
ext_authz
backend
redis
vault
```

### No Public IP

Only accessible via:

```text
10.0.1.10
```

(EC2-Public)

---

# 7. Docker Compose

## docker-compose.public.yml

```yaml
services:

  frontend:
    build:
      context: ../../frontend
    container_name: frontend

  envoy:
    image: envoyproxy/envoy
    container_name: envoy
    ports:
      - "80:80"
      - "443:443"
      - "10000:10000"
```

---

## docker-compose.private.yml

```yaml
services:

  keycloak:
    image: quay.io/keycloak/keycloak

  redis:
    image: redis

  vault:
    image: hashicorp/vault

  ext_authz:
    build:
      context: ../../ext_authz

  backend:
    build:
      context: ../../backend
```

---

# 8. Authentication Flow

```text
User
 ↓
Frontend
 ↓
Envoy
 ↓
Keycloak
 ↓
JWT
 ↓
Frontend
```

---

# 9. Protected API Flow

```text
User
 ↓
Frontend
 ↓
Envoy
 ↓
ext_authz

JWT Verification
Certificate Verification
cnf Validation
Replay Check

 ↓

Backend
```

---
# 10. Security Components Specification

## Vault PKI

### Purpose

Internal Certificate Authority.

Vault chịu trách nhiệm quản lý toàn bộ vòng đời certificate trong hệ thống.

### Responsibilities

#### Root CA

```text
Generate Root CA
```

#### Intermediate CA

```text
Generate Intermediate CA
```

#### Certificate Issuance

Issue:

```text
Client Certificates

Envoy Certificates

Backend Certificates

ext_authz Certificates

Test Certificates
```

#### Certificate Revocation

Maintain:

```text
CRL
(Certificate Revocation List)
```

#### Trust Distribution

Provide certificates to:

```text
Client Device

Envoy Gateway

Backend Service

ext_authz Service
```

### APIs

```text
Issue Certificate

Revoke Certificate

Fetch CRL

Renew Certificate
```

---

## Keycloak

### Purpose

Identity Provider (IdP)

Responsible for authentication and token issuance.

### Responsibilities

#### Authentication

```text
User Authentication

Client Authentication
```

#### Authorization

Manage:

```text
Realm Roles

Users

Groups

Clients
```

### JWT Issuance

Issue:

```text
ES256 Signed JWT
```

### JWKS

Expose:

```text
/.well-known/openid-configuration

/protocol/openid-connect/certs
```

for JWT verification.

### Certificate Binding

Protocol Mapper injects:

```json
{
  "cnf": {
    "x5t#S256": "certificate-thumbprint"
  }
}
```

### Demo Users

```text
admin
demo-user
```

### Demo Roles

```text
admin

user
```

### Admin API

Used for:

```text
Create User

Delete User

Assign Role

Update Configuration
```

---

## Redis Replay Cache

### Purpose

Replay Attack Prevention

### Storage

Store:

```text
JWT jti
```

after first successful usage.

### Logic

Use:

```text
SETNX
```

Example:

```text
SETNX(jwt_jti)
```

If exists:

```text
Replay Attack Detected
```

Return:

```text
HTTP 403
```

### Expiration

Use:

```text
TTL
```

equal to token expiration.

### Fallback

If Redis unavailable:

```text
In-Memory Replay Cache
```

is used.

---

## Envoy Gateway

### Purpose

Policy Enforcement Point (PEP)

Single Entry Point of the system.

### Responsibilities

#### TLS Termination

```text
TLS

mTLS
```

#### Client Certificate Validation

Verify:

```text
Certificate Chain

Trusted CA
```

#### Routing

Forward requests to:

```text
Backend

Keycloak

ext_authz
```

#### External Authorization

Call:

```text
gRPC ext_authz Filter
```

before forwarding.

### Listeners

#### Listener 1

```text
HTTPS + mTLS

Protected APIs
```

#### Listener 2

```text
HTTPS

Public Access
```

#### Listener 3

```text
Reverse Proxy

Keycloak Login
```

---

## ext_authz

### Purpose

Policy Decision Point (PDP)

Core Zero-Trust Authorization Engine.

Every protected request must pass ext_authz.

### Authorization Pipeline

Request processing pipeline:

#### Step 1

```text
Parse Client Certificate
```

Extract:

```text
XFCC
```

from Envoy.

---

#### Step 2

```text
Certificate Revocation Check
```

Check:

```text
CRL
```

from Vault.

---

#### Step 3

```text
JWT Verification
```

Validate:

```text
Signature

iss

aud

exp

nbf
```

using Keycloak JWKS.

---

#### Step 4

```text
Certificate Binding Validation
```

Compute:

```text
SHA256 Thumbprint
```

Compare against:

```text
cnf.x5t#S256
```

inside JWT.

Mismatch:

```text
HTTP 403
```

---

#### Step 5

```text
DPoP Verification
```

Validate:

```text
DPoP Proof

ath

htu

htm

iat

jti
```

Reject if invalid.

---

#### Step 6
```text
ABAC Policy Evaluation

Attributes:

Subject Attributes
- role
- department
- clearance
- user_id

Device Attributes
- certificate_cn
- certificate_ou
- device_id

Resource Attributes
- api_path
- resource_type

Action Attributes
- GET
- POST
- PUT
- DELETE

Environment Attributes
- source_ip
- request_time
- network_zone

```

---

#### Step 7

```text
Scope Validation
```

Verify:

```text
read

write

admin
```

against API requirements.

---

#### Step 8

```text
Rate Limiting
```

Apply:

```text
Per User

Per Client

Per IP
```

limits.

---

#### Step 9

```text
Replay Protection
```

Check:

```text
jti
```

against Redis.

If already used:

```text
HTTP 403
```

---

### Final Decision

All checks pass:

```text
ALLOW
```

Return:

```text
HTTP 200
```

to Envoy.

Any check fails:

```text
DENY
```

Return:

```text
401
or
403
```

---

# 13. End-to-End Request Flow

## Authentication Flow

```text
User
 ↓
Frontend
 ↓
Envoy
 ↓
Keycloak
 ↓
JWT + cnf.x5t#S256
 ↓
Frontend
```

---

## Protected API Flow

```text
User
 ↓
Frontend
 ↓
Envoy
 ↓
ext_authz

Certificate Check
CRL Check
JWT Verify
Binding Verify
DPoP Verify
ABAC
Scope Check
Rate Limit
Replay Check

 ↓

Backend
```

---

# 14. Security Goals

System protects against:

```text
Token Theft

Certificate Theft

Replay Attack

Token Replay

Certificate Replay

Unauthorized Access

Privilege Escalation

Man-in-the-Middle

Invalid Client Device
```

### Zero Trust Principle

Never Trust

Always Verify

Continuous Verification

Strong Identity

Least Privilege Access

