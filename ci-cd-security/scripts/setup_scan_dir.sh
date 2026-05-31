#!/usr/bin/env bash

set -euo pipefail

SCAN_BASE_DIR="/tmp/devsecops-scans"
RUN_OUTPUT_DIR="${SCAN_BASE_DIR}/${GITHUB_RUN_ID:-$$}"

mkdir -p "$RUN_OUTPUT_DIR"
chmod 777 "$RUN_OUTPUT_DIR"
rm -f "$RUN_OUTPUT_DIR"/* 2>/dev/null || true

echo "RUN_OUTPUT_DIR=${RUN_OUTPUT_DIR}"
echo "APP_NAME=${APP_NAME} | APP_URL=${APP_URL} | IMAGE=${DOCKER_IMAGE_NAME:-<none>}"
echo "Scanners → semgrep=${ENABLE_SEMGREP} trivy_fs=${ENABLE_TRIVY_FS} trivy_image=${ENABLE_TRIVY_IMAGE} zap=${ENABLE_ZAP}"
