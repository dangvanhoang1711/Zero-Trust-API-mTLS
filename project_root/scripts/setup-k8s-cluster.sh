#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../" && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-zero-trust-mtls}"
K8S_CONTEXT="${K8S_CONTEXT:-$CLUSTER_NAME}"
NAMESPACE="${NAMESPACE:-zero-trust}"
CERT_MANAGER_NAMESPACE="${CERT_MANAGER_NAMESPACE:-cert-manager}"
VAULT_OUTPUT_DIR="${VAULT_OUTPUT_DIR:-$PROJECT_ROOT/infra/vault/artifacts}"
VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
VAULT_PUBLIC_ADDR="${VAULT_PUBLIC_ADDR:-${VAULT_ADDR:-https://vault.default.svc.cluster.local:8200}}"
BOOTSTRAP_VAULT="${BOOTSTRAP_VAULT:-false}"
SETUP_K8S_MANIFESTS="${SETUP_K8S_MANIFESTS:-true}"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
}

run_vault_bootstrap_if_requested() {
  if [ "$BOOTSTRAP_VAULT" != "true" ]; then
    return
  fi

  if [ -z "$VAULT_ADDR" ] || [ -z "$VAULT_TOKEN" ]; then
    echo "SKIP: VAULT_ADDR and VAULT_TOKEN required for --bootstrap-vault mode."
    echo "Set VAULT_ADDR and VAULT_TOKEN, or disable BOOTSTRAP_VAULT."
    exit 1
  fi

  require_cmd vault

  echo "Running Vault PKI bootstrap..."
  mkdir -p "$VAULT_OUTPUT_DIR"

  # Run with explicit environment so output location is deterministic.
  (
    cd "$PROJECT_ROOT/infra/vault"
    VAULT_ADDR="$VAULT_ADDR" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    VAULT_PUBLIC_ADDR="$VAULT_PUBLIC_ADDR" \
    OUTPUT_DIR="$VAULT_OUTPUT_DIR" \
    bash bootstrap-pki.sh
  )
}

ensure_minikube() {
  if command -v minikube >/dev/null 2>&1; then
    if minikube status -p "$CLUSTER_NAME" >/dev/null 2>&1; then
      echo "Using existing minikube cluster '$CLUSTER_NAME'"
      minikube start -p "$CLUSTER_NAME" --driver=docker >/dev/null
    else
      echo "Creating minikube cluster '$CLUSTER_NAME'"
      minikube start -p "$CLUSTER_NAME" --driver=docker
    fi
    minikube profile "$CLUSTER_NAME"
    return
  fi

  if command -v k3d >/dev/null 2>&1; then
    echo "Creating k3d cluster '$CLUSTER_NAME'"
    k3d cluster create "$CLUSTER_NAME" --wait --agents 1
    return
  fi

  echo "No supported local cluster tool found (minikube/k3d)."
  echo "Install one of: minikube, k3d, or point KUBECONFIG to your cluster and run only manifest steps."
  exit 1
}

ensure_kubectl_context() {
  kubectl config use-context "$K8S_CONTEXT" >/dev/null 2>&1 || true
  if ! kubectl get ns >/dev/null 2>&1; then
    echo "Cannot access cluster using context '$K8S_CONTEXT'."
    exit 1
  fi
}

install_cert_manager() {
  if command -v helm >/dev/null 2>&1; then
    if ! helm repo list | awk '{print $1}' | grep -q '^jetstack$'; then
      helm repo add jetstack https://charts.jetstack.io
    fi

    helm repo update
    if kubectl get ns cert-manager >/dev/null 2>&1 && kubectl get deployment -n cert-manager cert-manager >/dev/null 2>&1; then
      echo "cert-manager appears installed"
    else
      kubectl create namespace "$CERT_MANAGER_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
      helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace "$CERT_MANAGER_NAMESPACE" \
        --set installCRDs=true \
        --wait
    fi
  else
    echo "helm not found, skip automatic install. You can install cert-manager manually."
  fi
}

apply_cert_manager_manifests() {
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f "$PROJECT_ROOT/infra/cert-manager/issuer.yaml"
  kubectl apply -f "$PROJECT_ROOT/infra/cert-manager/certificate.yaml"

  echo "Applied manifest files under $PROJECT_ROOT/infra/cert-manager"
}

check_placeholders() {
  if rg -q "REPLACE_WITH_" "$PROJECT_ROOT/infra/cert-manager/issuer.yaml" "$PROJECT_ROOT/infra/cert-manager/certificate.yaml"; then
    echo "INFO: cert-manager manifests still contain placeholders."
    echo "This bootstrap flow syncs these values into Kubernetes secrets from artifact files:"
    echo "- REPLACE_WITH_VAULT_SERVER_CA_CERT"
    echo "- REPLACE_WITH_INTERMEDIATE_CA_CERT"
    echo "- REPLACE_WITH_CURRENT_PEM_CRL"
  fi
}

sync_cert_manager_secrets() {
  local root_ca="$VAULT_OUTPUT_DIR/root_ca.crt"
  local intermediate_ca="$VAULT_OUTPUT_DIR/intermediate_ca.crt"
  local ca_crl="$VAULT_OUTPUT_DIR/ca.crl"

  if [ ! -f "$root_ca" ] || [ ! -f "$intermediate_ca" ] || [ ! -f "$ca_crl" ]; then
    echo "WARN: Vault trust artifacts missing in $VAULT_OUTPUT_DIR"
    echo "Expected files:"
    echo " - $root_ca"
    echo " - $intermediate_ca"
    echo " - $ca_crl"
    echo "Run bootstrap with BOOTSTRAP_VAULT=true first."
    return
  fi

  kubectl create namespace "$CERT_MANAGER_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

  kubectl create secret generic vault-ca-bundle \
    --from-file=ca.crt="$root_ca" \
    --namespace="$CERT_MANAGER_NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl create secret generic envoy-client-trust \
    --from-file=intermediate-ca.crt="$intermediate_ca" \
    --from-file=ca.crl="$ca_crl" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -
}

parse_arguments() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --bootstrap-vault)
        BOOTSTRAP_VAULT=true
        shift
        ;;
      --no-bootstrap-vault)
        BOOTSTRAP_VAULT=false
        shift
        ;;
      --skip-manifests)
        SETUP_K8S_MANIFESTS=false
        shift
        ;;
      --namespace)
        NAMESPACE="${2:?missing value for --namespace}"
        shift 2
        ;;
      --help|-h)
        cat <<EOF
Usage: setup-k8s-cluster.sh [options]

Options:
  --bootstrap-vault      Run infra/vault/bootstrap-pki.sh using VAULT_ADDR/VAULT_TOKEN.
  --skip-manifests       Apply only cluster bootstrap steps, skip cert-manager manifests.
  --namespace <name>     Target namespace for test client workload (default: zero-trust).
  --help                 Show this help.
EOF
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        echo "Try --help"
        exit 1
        ;;
    esac
  done
}

main() {
  parse_arguments "$@"
  require_cmd kubectl

  ensure_minikube
  ensure_kubectl_context
  install_cert_manager
  if [ "$SETUP_K8S_MANIFESTS" = true ]; then
    run_vault_bootstrap_if_requested
    apply_cert_manager_manifests
    sync_cert_manager_secrets
    check_placeholders
  else
    echo "SKIP: cert-manager manifest setup."
  fi

  echo "Bootstrap complete."
  echo "Next: run 'helm upgrade --install' for the project chart:"
  echo "  helm upgrade --install zero-trust-mtls \"$PROJECT_ROOT/infra/helm/zero-trust-mtls\" -n \"$NAMESPACE\""
}

main "$@"
