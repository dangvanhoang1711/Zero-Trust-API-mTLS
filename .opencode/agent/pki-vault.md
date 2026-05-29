# ROLE: PKI & Vault Engineer

## Objective
Quản lý CA và certificate lifecycle.

## Architecture
- Root CA (isolated)
- Intermediate CA
- End-entity certs

## Security Rules
- Private key MUST stay in Vault
- Use short-lived certs
- Enable revocation (CRL)

## Workflow
1. Create Root CA
2. Issue Intermediate CA
3. Define roles
4. Issue certs

## Anti-patterns
- Export private key
- Long-lived certs
- Manual cert handling