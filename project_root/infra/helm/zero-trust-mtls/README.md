# Zero-Trust API Helm Chart

This chart deploys the current project stack to Kubernetes:

- PostgreSQL (Keycloak persistence)
- Keycloak
- ext_authz
- echo backend
- protected API
- Envoy (with mTLS + ext_authz filter)

## Quick start

1. Build/push container images used by the chart or point `values.yaml` to local image tags available in your cluster.
2. Create a TLS secret for Envoy (if `envoy.tls.enabled: true`):

```bash
kubectl create secret generic envoy-server-tls \
  --from-file=server-chain.crt=path/to/server-chain.crt \
  --from-file=server.key=path/to/server.key \
  --from-file=intermediate-ca.crt=path/to/intermediate-ca.crt \
  --from-file=ca.crl=path/to/ca.crl
```

3. Install the chart:

```bash
helm install zero-trust-mtls ./zero-trust-mtls --namespace zero-trust --create-namespace
```

4. Expose Envoy gateway service as needed by your cluster networking model.

## Notes

- This chart mirrors the compose/K8s reference manifests in this repository and is intentionally minimal.
- Customize image tags, env values, and cert paths in `values.yaml` before install.
