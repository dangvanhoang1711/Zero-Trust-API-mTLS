# Kubernetes + cert-manager bootstrap

This project ships Kubernetes manifests and a Helm chart. If you want an end-to-end local cluster setup:

1. Install one local cluster tool (`minikube` or `k3d`).
2. Run:

```bash
./project_root/scripts/setup-k8s-cluster.sh
```

To bootstrap Vault artifacts at the same time:

```bash
VAULT_ADDR="http://127.0.0.1:8200" \
VAULT_TOKEN="root" \
BOOTSTRAP_VAULT=true \
./project_root/scripts/setup-k8s-cluster.sh --bootstrap-vault
```

Notes:

- The script bootstraps:
  - local cluster (minikube or k3s via k3d),
  - `cert-manager` installation,
  - manifests from `project_root/infra/cert-manager/`.
- `project_root/scripts/setup-k8s-cluster.sh --bootstrap-vault` will create/update:
  - `vault-ca-bundle` secret in namespace `cert-manager` from `infra/vault/artifacts/root_ca.crt`
  - `envoy-client-trust` secret in namespace `default` from
    `infra/vault/artifacts/intermediate_ca.crt` and `infra/vault/artifacts/ca.crl`

3. Deploy the project Helm chart:

```bash
helm upgrade --install zero-trust-mtls \
  project_root/infra/helm/zero-trust-mtls -n zero-trust --create-namespace
```

4. Optionally verify:

```bash
kubectl get pods,svc -n zero-trust
```
