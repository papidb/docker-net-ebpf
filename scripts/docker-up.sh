#!/usr/bin/env bash
set -euo pipefail

echo "Creating network (if not exists)..."
docker network inspect ebpf-lab >/dev/null 2>&1 || docker network create ebpf-lab

echo "Starting lab-web..."
docker run -d \
  --network ebpf-lab \
  --name lab-web \
  nginx:alpine >/dev/null 2>&1 || true

echo "Starting lab-egress..."
docker run -d \
  --network ebpf-lab \
  --name lab-egress \
  curlimages/curl sh -c '
while true; do
  curl -L -o /dev/null https://speed.cloudflare.com/__down?bytes=10000000;
  sleep 2;
done
' >/dev/null 2>&1 || true

echo "Starting lab-internal..."
docker run -d \
  --network ebpf-lab \
  --name lab-internal \
  alpine sh -c '
apk add --no-cache curl;
while true; do
  for i in $(seq 1 200); do
    curl -s http://lab-web/ > /dev/null;
  done;
  sleep 1;
done
' >/dev/null 2>&1 || true

echo ""
echo "Containers running:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}"