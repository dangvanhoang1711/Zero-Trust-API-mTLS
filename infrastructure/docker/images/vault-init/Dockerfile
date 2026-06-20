FROM hashicorp/vault:1.15 AS vaultbin

FROM python:3.12-slim

COPY --from=vaultbin /bin/vault /usr/local/bin/vault

COPY infrastructure/docker/images/vault-init/vault-tls-init.sh /usr/local/bin/vault-tls-init.sh
COPY infrastructure/docker/images/vault-init/pki-init.sh /usr/local/bin/pki-init.sh

RUN chmod +x /usr/local/bin/vault-tls-init.sh /usr/local/bin/pki-init.sh

RUN apt-get update && apt-get install -y openssl ca-certificates curl && rm -rf /var/lib/apt/lists/*
