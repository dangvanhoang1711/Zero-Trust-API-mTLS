#!/bin/bash
# Detect EC2 metadata for certificate SAN (IMDSv2)
# Called by pki-init in docker-compose.yml
# Sets CERT_SAN_DNS and CERT_SAN_IP if not already set

EC2_TOKEN=$(curl -sf -X PUT --connect-timeout 2 --max-time 3 \
  "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)

EC2_PUBLIC_HOSTNAME=$(curl -sf --connect-timeout 2 --max-time 3 \
  -H "X-aws-ec2-metadata-token: $EC2_TOKEN" \
  http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null || true)

EC2_PUBLIC_IP=$(curl -sf --connect-timeout 2 --max-time 3 \
  -H "X-aws-ec2-metadata-token: $EC2_TOKEN" \
  http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)

export CERT_SAN_DNS="${CERT_SAN_DNS:-$EC2_PUBLIC_HOSTNAME}"
export CERT_SAN_IP="${CERT_SAN_IP:-$EC2_PUBLIC_IP}"

[ -n "$CERT_SAN_DNS" ] && echo "  EC2 public DNS: $CERT_SAN_DNS" || true
[ -n "$CERT_SAN_IP" ] && echo "  EC2 public IP: $CERT_SAN_IP" || true
