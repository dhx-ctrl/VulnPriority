#!/usr/bin/env bash
# run_pipeline.sh — Main DevSecOps pipeline controller.
#
# Usage:
#   bash run_pipeline.sh <product.env> <app_source_dir>
#
# Example:
#   bash vulnpriority/ci-cd-security/scripts/run_pipeline.sh \
#     vulnpriority/ci-cd-security/products/juice-shop/product.env \
#     "$GITHUB_WORKSPACE/app"
#
# ─────────────────────────────────────────────────────────────────────────────
# This script orchestrates the full CI+CD pipeline in a single run:
#   1. Load product.env (app-specific configuration)
#   2. Prepare scan output directory
#   3. Write scan_meta.env for import_scans.sh
#   4. Build Docker image (if DOCKER_IMAGE_SOURCE=build)
#   5. Run enabled scanners (Semgrep, Trivy FS, Trivy Image)
#   6. Start target app for ZAP (via product start_app.sh)
#   7. Wait for the app to become reachable
#   8. Run post-start hooks (e.g. DVWA database init)
#   9. Run ZAP DAST scan
#  10. Stop target app
#  11. Debug-inspect scan outputs
#  12. Import results into DefectDojo
#  13. Cleanup
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

###############################################################################
#  Arguments
###############################################################################

if [[ $# -lt 2 ]]; then
  echo "Usage: run_pipeline.sh <product.env> <app_source_dir>"
  exit 1
fi

PRODUCT_ENV_FILE="$1"
APP_SOURCE_DIR="$2"

if [[ ! -f "$PRODUCT_ENV_FILE" ]]; then
  echo "ERROR: product.env not found: $PRODUCT_ENV_FILE"
  exit 1
fi
if [[ ! -d "$APP_SOURCE_DIR" ]]; then
  echo "ERROR: app source directory not found: $APP_SOURCE_DIR"
  exit 1
fi

###############################################################################
#  Resolve paths
###############################################################################

# SCRIPTS_DIR is where this script and all shared scripts live.
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# PRODUCT_DIR is the directory containing product.env and start_app.sh.
PRODUCT_DIR="$(cd "$(dirname "$PRODUCT_ENV_FILE")" && pwd)"

# Source shared helpers.
# shellcheck disable=SC1091
source "${SCRIPTS_DIR}/common.sh"

###############################################################################
#  Load product configuration
###############################################################################

log_section "Loading product configuration"
echo "Product env : ${PRODUCT_ENV_FILE}"
echo "App source  : ${APP_SOURCE_DIR}"

# shellcheck disable=SC1090
set -a
source "$PRODUCT_ENV_FILE"
set +a

# ── Workflow-dispatch overrides ───────────────────────────────────────
# product.env uses ${VAR:-default} for ENABLE_* flags, so environment
# variables set by the wrapper workflow automatically take precedence.
# No re-assignment needed here.

# Export key variables for child scripts.
export APP_NAME APP_URL APP_PORT CONTAINER_PORT DOCKER_IMAGE_NAME
export ENABLE_SEMGREP ENABLE_TRIVY_FS ENABLE_TRIVY_IMAGE ENABLE_ZAP
export SEMGREP_EXTRA_CONFIGS="${SEMGREP_EXTRA_CONFIGS:-}"
export APP_SOURCE_DIR SCRIPTS_DIR PRODUCT_DIR

###############################################################################
#  Scan output directory
###############################################################################

log_section "Preparing scan output directory"
source "${SCRIPTS_DIR}/setup_scan_dir.sh"
export RUN_OUTPUT_DIR

###############################################################################
#  Write scan_meta.env (consumed by import_scans.sh)
###############################################################################

log_section "Writing scan_meta.env"
printf '%s\n' \
  "APP_NAME=${APP_NAME}" \
  "APP_URL=${APP_URL}" \
  "DOCKER_IMAGE_NAME=${DOCKER_IMAGE_NAME}" \
  "ENABLE_SEMGREP=${ENABLE_SEMGREP}" \
  "ENABLE_TRIVY_FS=${ENABLE_TRIVY_FS}" \
  "ENABLE_TRIVY_IMAGE=${ENABLE_TRIVY_IMAGE}" \
  "ENABLE_ZAP=${ENABLE_ZAP}" \
  "GIT_COMMIT=${GIT_COMMIT:-${GITHUB_SHA:-unknown}}" \
  "GIT_BRANCH=${GIT_BRANCH:-${GITHUB_REF_NAME:-unknown}}" \
  > "${RUN_OUTPUT_DIR}/scan_meta.env"
echo "scan_meta.env written:"
cat "${RUN_OUTPUT_DIR}/scan_meta.env"

###############################################################################
#  Build Docker image (if required)
###############################################################################

DOCKER_IMAGE_SOURCE="${DOCKER_IMAGE_SOURCE:-pull}"
export DOCKER_IMAGE_SOURCE
if [[ "$DOCKER_IMAGE_SOURCE" == "build" ]]; then
  if [[ "$ENABLE_TRIVY_IMAGE" == "true" || "$ENABLE_ZAP" == "true" ]]; then
    log_section "Building Docker image from source"
    echo "Building ${DOCKER_IMAGE_NAME} from ${APP_SOURCE_DIR}..."
    docker build -t "$DOCKER_IMAGE_NAME" "$APP_SOURCE_DIR"
    echo "Image built: $(docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' "$DOCKER_IMAGE_NAME")"
  fi
fi

###############################################################################
#  Summary
###############################################################################

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Pipeline: ${APP_NAME}"
echo "  App URL        : ${APP_URL}"
echo "  Docker image   : ${DOCKER_IMAGE_NAME}"
echo "  Image source   : ${DOCKER_IMAGE_SOURCE}"
echo "  Output dir     : ${RUN_OUTPUT_DIR}"
echo "  Scanners       : semgrep=${ENABLE_SEMGREP}  trivy_fs=${ENABLE_TRIVY_FS}"
echo "                   trivy_image=${ENABLE_TRIVY_IMAGE}  zap=${ENABLE_ZAP}"
echo "════════════════════════════════════════════════════════════════"
echo ""

###############################################################################
#  SAST: Semgrep
###############################################################################

if [[ "$ENABLE_SEMGREP" == "true" ]]; then
  log_section "Semgrep SAST"
  source "${SCRIPTS_DIR}/run_semgrep.sh"
else
  echo "SKIP: Semgrep (disabled)"
fi

###############################################################################
#  SCA: Trivy filesystem
###############################################################################

if [[ "$ENABLE_TRIVY_FS" == "true" ]]; then
  log_section "Trivy filesystem scan"
  source "${SCRIPTS_DIR}/run_trivy_fs.sh"
else
  echo "SKIP: Trivy filesystem (disabled)"
fi

###############################################################################
#  SCA: Trivy image
###############################################################################

if [[ "$ENABLE_TRIVY_IMAGE" == "true" && -n "${DOCKER_IMAGE_NAME:-}" ]]; then
  log_section "Trivy image scan"
  source "${SCRIPTS_DIR}/run_trivy_image.sh"
else
  echo "SKIP: Trivy image (disabled or no DOCKER_IMAGE_NAME)"
fi

###############################################################################
#  DAST: ZAP
###############################################################################

if [[ "$ENABLE_ZAP" == "true" ]]; then
  log_section "ZAP DAST scan"

  # Create Docker network for ZAP.
  docker network create zapnet 2>/dev/null || true

  # Start the target app using the product-specific script.
  log_subsection "Starting target app: ${APP_NAME}"
  source "${PRODUCT_DIR}/start_app.sh"

  # Wait for the app to become reachable.
  log_subsection "Waiting for ${APP_NAME}"
  source "${SCRIPTS_DIR}/wait_for_app.sh"

  # Run post-start hook if it exists (e.g. DVWA database init).
  if [[ -f "${PRODUCT_DIR}/post_start.sh" ]]; then
    log_subsection "Running post-start hook"
    source "${PRODUCT_DIR}/post_start.sh"
  fi

  # Run ZAP scan.
  log_subsection "ZAP baseline scan"
  source "${SCRIPTS_DIR}/run_zap.sh"

  # Stop the target app.
  log_subsection "Stopping target app"
  if [[ -f "${PRODUCT_DIR}/stop_app.sh" ]]; then
    source "${PRODUCT_DIR}/stop_app.sh"
  else
    docker rm -f "target-${APP_NAME}" 2>/dev/null || true
  fi
else
  echo "SKIP: ZAP (disabled)"
fi

###############################################################################
#  Verify scan results
###############################################################################

log_section "Scan results"
echo "=== Scan results in $RUN_OUTPUT_DIR ==="
ls -la "$RUN_OUTPUT_DIR" || true

###############################################################################
#  DEBUG: Inspect scan outputs
###############################################################################

log_section "DEBUG: Inspect scan outputs"
source "${SCRIPTS_DIR}/debug_inspect.sh"

###############################################################################
#  Import into DefectDojo
###############################################################################

log_section "DefectDojo import"
source "${SCRIPTS_DIR}/import_defectdojo.sh"

###############################################################################
#  NOTE: No cleanup here.
#  The wrapper workflow's upload-artifact step runs AFTER this script exits.
#  Cleanup happens in a separate workflow step after artifact upload.
###############################################################################

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Pipeline complete: ${APP_NAME}"
echo "════════════════════════════════════════════════════════════════"
