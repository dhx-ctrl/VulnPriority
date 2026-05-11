#!/usr/bin/env bash
# run_semgrep.sh — Run Semgrep SAST scan.
#
# Sourced by run_pipeline.sh.
# Expects: APP_SOURCE_DIR, RUN_OUTPUT_DIR
# Optional: SEMGREP_EXTRA_CONFIGS (space-separated list, e.g. "p/nodejs")

set -euo pipefail

docker pull returntocorp/semgrep:latest

# Build the config arguments.
# Base configs are always included; extra configs come from product.env.
SEMGREP_ARGS=(
  semgrep scan
  --config=auto
  --config=p/ci
  --config=p/security-audit
)

# Add product-specific Semgrep rule packs (e.g. p/nodejs for Node.js apps).
if [[ -n "${SEMGREP_EXTRA_CONFIGS:-}" ]]; then
  for cfg in $SEMGREP_EXTRA_CONFIGS; do
    SEMGREP_ARGS+=("--config=${cfg}")
  done
fi

SEMGREP_ARGS+=(
  --json
  --output /out/semgrep.json
  /src
)

docker run --rm \
  -v "${APP_SOURCE_DIR}:/src:ro" \
  -v "${RUN_OUTPUT_DIR}:/out" \
  returntocorp/semgrep:latest \
  "${SEMGREP_ARGS[@]}"

test -s "${RUN_OUTPUT_DIR}/semgrep.json"
echo "semgrep.json written ($(wc -c < "${RUN_OUTPUT_DIR}/semgrep.json") bytes)"
