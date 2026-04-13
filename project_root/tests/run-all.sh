#!/usr/bin/env bash

set -euo pipefail

./tests/functional/phase2-valid-cert.sh
./tests/functional/phase2-expired-cert.sh
./tests/functional/phase2-revoked-cert.sh
