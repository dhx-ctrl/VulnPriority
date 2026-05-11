#!/usr/bin/env bash
# start_app.sh — Start DVNA for ZAP scanning.
#
# Sourced by run_pipeline.sh.
# Expects: APP_NAME, APP_URL, APP_PORT, CONTAINER_PORT, DOCKER_IMAGE_NAME

set -euo pipefail

docker pull "$DOCKER_IMAGE_NAME"
docker rm -f "target-${APP_NAME}" 2>/dev/null || true

docker pull curlimages/curl:8.6.0

CONTAINER_HOST=$(get_hostname_from_url "$APP_URL")

docker run -d \
  --name "target-${APP_NAME}" \
  --network zapnet \
  --network-alias "${CONTAINER_HOST}" \
  -p "${APP_PORT}:${CONTAINER_PORT}" \
  "$DOCKER_IMAGE_NAME"
