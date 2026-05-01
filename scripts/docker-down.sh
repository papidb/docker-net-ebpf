#!/usr/bin/env bash
set -euo pipefail

echo "Stopping and removing containers..."

docker rm -f lab-web lab-egress lab-internal >/dev/null 2>&1 || true

echo "Removing network..."

docker network rm ebpf-lab >/dev/null 2>&1 || true

echo "Done."