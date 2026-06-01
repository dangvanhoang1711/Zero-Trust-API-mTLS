# Kubernetes manifests (reference)

This directory contains Kubernetes manifests for the same architecture used by the compose stack:

- `keycloak-db.yaml` — PostgreSQL for Keycloak
- `keycloak-server.yaml` — Keycloak Deployment + Service
- `ext-authz-deploy.yaml` — ext_authz Deployment + Service
- `protected-api-deploy.yaml` — protected API service Deployment + Service
- `backend-deploy.yaml` — echo service Deployment + Service
- `envoy-deploy.yaml` — Envoy Deployment + Service

The files are intended as a **starting point** for manual Kubernetes deployment
and are not validated by CI in this repository.
