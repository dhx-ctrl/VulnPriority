#!/usr/bin/env bash
# run_trivy_image.sh — Run Trivy image scan (SCA).
#
# Sourced by run_pipeline.sh.
# Expects: DOCKER_IMAGE_NAME, RUN_OUTPUT_DIR
# Optional: DOCKER_IMAGE_SOURCE (if "pull", pulls the image first)

set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.69.3}"

# Only pull the image if it came from a registry (not built locally).
if [[ "${DOCKER_IMAGE_SOURCE:-pull}" == "pull" ]]; then
  docker pull "$DOCKER_IMAGE_NAME"
fi

docker pull "ghcr.io/aquasecurity/trivy:${TRIVY_VERSION}"

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${RUN_OUTPUT_DIR}:/out" \
  "ghcr.io/aquasecurity/trivy:${TRIVY_VERSION}" \
  image \
  --scanners vuln,misconfig,secret \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  --format json \
  --output /out/trivy_image.json \
  "$DOCKER_IMAGE_NAME"

test -s "${RUN_OUTPUT_DIR}/trivy_image.json"
echo "trivy_image.json written ($(wc -c < "${RUN_OUTPUT_DIR}/trivy_image.json") bytes)"
