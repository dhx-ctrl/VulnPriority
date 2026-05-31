#!/usr/bin/env bash

set -euo pipefail

if [[ ! -f "${RUN_OUTPUT_DIR}/scan_meta.env" ]]; then
  echo "ERROR: ${RUN_OUTPUT_DIR}/scan_meta.env not found."
  echo "       The scan output directory may be incomplete."
  return 1
fi
echo "scan_meta.env found:"
cat "${RUN_OUTPUT_DIR}/scan_meta.env"
export DOJO_URL="${DOJO_URL:-http://localhost:8080}"

export DOJO_PRODUCT_TYPE_NAME="${DOJO_PRODUCT_TYPE_NAME:-CI-CD Apps}"
export DOJO_ENGAGEMENT_NAME="${DOJO_ENGAGEMENT_NAME:-DevSecOps-CICD}"
export DOJO_ENGAGEMENT_LEAD_USERNAME="${DOJO_ENGAGEMENT_LEAD_USERNAME:-admin}"

export SCAN_TYPE_TRIVY_FS="${SCAN_TYPE_TRIVY_FS:-Trivy Scan}"
export SCAN_TYPE_TRIVY_IMAGE="${SCAN_TYPE_TRIVY_IMAGE:-Trivy Scan}"
export SCAN_TYPE_ZAP="${SCAN_TYPE_ZAP:-ZAP Scan}"
export SCAN_TYPE_SEMGREP="${SCAN_TYPE_SEMGREP:-Semgrep JSON Report}"

export BUILD_ID="${BUILD_ID:-${GITHUB_RUN_ID:-unknown}}"
export COMMIT_HASH="${COMMIT_HASH:-${GITHUB_SHA:-unknown}}"
export BRANCH_TAG="${BRANCH_TAG:-${GITHUB_REF_NAME:-unknown}}"
export REPO_URI="${REPO_URI:-${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}}"
export TEST_STRATEGY="${TEST_STRATEGY:-https://github.com/${GITHUB_REPOSITORY:-unknown}/actions}"

if [[ -z "${DOJO_TOKEN:-}" ]]; then
  echo "ERROR: DOJO_TOKEN is not set. Cannot import to DefectDojo."
  echo "       Set DOJO_TOKEN as a secret in the workflow."
  return 1
fi
export DOJO_TOKEN

echo ""
echo "Calling import_scans.sh..."
bash "${SCRIPTS_DIR}/import_scans.sh"
