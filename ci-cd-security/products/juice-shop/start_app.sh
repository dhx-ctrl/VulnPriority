#!/usr/bin/env bash
# start_app.sh — Start Juice Shop for ZAP scanning.
#
# Sourced by run_pipeline.sh.
# Expects: APP_NAME, APP_URL, APP_PORT, CONTAINER_PORT, DOCKER_IMAGE_NAME

set -euo pipefail

if [[ -z "${DOCKER_IMAGE_NAME:-}" ]]; then
  echo "DOCKER_IMAGE_NAME is empty — assuming ${APP_URL} is already reachable."
  echo "NOTE: The target must be accessible from inside the zapnet Docker"
  echo "      network.  If it runs on the host, connect it to zapnet or"
  echo "      use --network=host for ZAP instead."
  return 0 2>/dev/null || exit 0
fi

docker pull "$DOCKER_IMAGE_NAME"
docker rm -f "target-${APP_NAME}" 2>/dev/null || true

CONTAINER_HOST=$(get_hostname_from_url "$APP_URL")

docker run -d \
  --name "target-${APP_NAME}" \
  --network zapnet \
  --network-alias "${CONTAINER_HOST}" \
  -p "${APP_PORT}:${CONTAINER_PORT}" \
  "$DOCKER_IMAGE_NAME"
