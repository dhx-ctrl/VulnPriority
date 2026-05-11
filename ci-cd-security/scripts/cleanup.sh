#!/usr/bin/env bash
# cleanup.sh — Clean up after a pipeline run.
#
# Executed by wrapper workflow AFTER artifact upload.
# Safe to run even if the pipeline failed halfway.

set +e

echo "Cleaning up DevSecOps run..."

if [[ -n "${APP_NAME:-}" ]]; then
  echo "Removing target container: target-${APP_NAME}"
  docker rm -f "target-${APP_NAME}" 2>/dev/null || true

  echo "Removing possible Mongo sidecar: mongo-${APP_NAME}"
  docker rm -f "mongo-${APP_NAME}" 2>/dev/null || true
fi

if [[ -n "${RUN_OUTPUT_DIR:-}" ]]; then
  echo "Removing run output directory: ${RUN_OUTPUT_DIR}"
  rm -rf "${RUN_OUTPUT_DIR}" 2>/dev/null || true
fi

echo "Removing zapnet network if unused..."
docker network rm zapnet 2>/dev/null || true

echo "Cleanup complete."
