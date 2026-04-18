#!/usr/bin/env bash

set -euo pipefail

: "${NAMESPACE:=default}"
: "${SECRET_NAME:=client-mtls}"

before=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.resourceVersion}')
printf 'initial resourceVersion: %s\n' "$before"
printf 'wait for cert-manager to renew the 24h certificate before the 6h threshold, then rerun:\n'
printf 'kubectl get secret %s -n %s -o jsonpath={.metadata.resourceVersion}\n' "$SECRET_NAME" "$NAMESPACE"
