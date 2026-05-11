#!/usr/bin/env bash
# run_trivy_fs.sh — Run Trivy filesystem scan (SCA).
#
# Sourced by run_pipeline.sh.
# Expects: APP_SOURCE_DIR, RUN_OUTPUT_DIR

set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.69.3}"

docker pull "ghcr.io/aquasecurity/trivy:${TRIVY_VERSION}"

docker run --rm \
  -v "${APP_SOURCE_DIR}:/workspace:ro" \
  -v "${RUN_OUTPUT_DIR}:/out" \
  "ghcr.io/aquasecurity/trivy:${TRIVY_VERSION}" \
  fs \
  --scanners vuln,misconfig,secret,license \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  --format json \
  --output /out/trivy_fs.json \
  /workspace

test -s "${RUN_OUTPUT_DIR}/trivy_fs.json"
echo "trivy_fs.json written ($(wc -c < "${RUN_OUTPUT_DIR}/trivy_fs.json") bytes)"
