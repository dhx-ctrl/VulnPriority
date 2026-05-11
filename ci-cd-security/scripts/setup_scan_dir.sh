#!/usr/bin/env bash
# setup_scan_dir.sh — Prepare the scan output directory.
#
# Sourced by run_pipeline.sh.  Expects GITHUB_RUN_ID or RUNNER_TEMP to be set.
# Sets RUN_OUTPUT_DIR for all downstream scripts.

set -euo pipefail

# Use /tmp consistently — matches the original workflows.
# On self-hosted runners RUNNER_TEMP is often NOT /tmp, so we hardcode /tmp
# to preserve the exact same paths the existing pipeline uses.
SCAN_BASE_DIR="/tmp/devsecops-scans"
RUN_OUTPUT_DIR="${SCAN_BASE_DIR}/${GITHUB_RUN_ID:-$$}"

mkdir -p "$RUN_OUTPUT_DIR"
chmod 777 "$RUN_OUTPUT_DIR"
rm -f "$RUN_OUTPUT_DIR"/* 2>/dev/null || true

echo "RUN_OUTPUT_DIR=${RUN_OUTPUT_DIR}"
echo "APP_NAME=${APP_NAME} | APP_URL=${APP_URL} | IMAGE=${DOCKER_IMAGE_NAME:-<none>}"
echo "Scanners → semgrep=${ENABLE_SEMGREP} trivy_fs=${ENABLE_TRIVY_FS} trivy_image=${ENABLE_TRIVY_IMAGE} zap=${ENABLE_ZAP}"
