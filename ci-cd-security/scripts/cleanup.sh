#!/usr/bin/env bash
# cleanup.sh — Clean up after a pipeline run.
#
# Sourced by run_pipeline.sh.
# Expects: RUN_OUTPUT_DIR

# Remove the run output directory.  Failures are non-fatal.
rm -rf "${RUN_OUTPUT_DIR}" 2>/dev/null || true

# Remove the zapnet Docker network if it exists.  Non-fatal.
docker network rm zapnet 2>/dev/null || true

echo "Cleanup complete."
