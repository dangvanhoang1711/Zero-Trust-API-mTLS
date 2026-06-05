#!/usr/bin/env bash

set -euo pipefail

: "${NAMESPACE:=default}"
: "${SECRET_NAME:=client-mtls}"
: "${CHECK_TIMEOUT_SECONDS:=0}"

before=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.resourceVersion}')
printf 'initial resourceVersion: %s\n' "$before"
if [ "$CHECK_TIMEOUT_SECONDS" -le 0 ]; then
  printf 'wait for cert-manager to renew the 24h certificate before the 6h threshold, then rerun:\n'
  printf '  kubectl get secret %s -n %s -o jsonpath={.metadata.resourceVersion}\n' "$SECRET_NAME" "$NAMESPACE"
  exit 0
fi

echo "Monitoring renewal for ${CHECK_TIMEOUT_SECONDS}s (use kubectl edit secret or cert-manager issuance trigger to start renewal)."
start_ts=$(date +%s)

while :; do
  now=$(date +%s)
  if (( now - start_ts >= CHECK_TIMEOUT_SECONDS )); then
    echo "TIMEOUT: resourceVersion did not change within CHECK_TIMEOUT_SECONDS=$CHECK_TIMEOUT_SECONDS"
    exit 1
  fi

  current=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.resourceVersion}')
  if [ "$current" != "$before" ]; then
    echo "PASS: certificate secret was renewed (old=$before -> new=$current)"
    exit 0
  fi
  sleep 5
done
