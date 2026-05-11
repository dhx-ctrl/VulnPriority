#!/usr/bin/env bash
# stop_app.sh — Stop NodeGoat and its MongoDB sidecar.
#
# Sourced by run_pipeline.sh.
# Expects: APP_NAME

docker rm -f "target-${APP_NAME}" 2>/dev/null || true
docker rm -f "mongo-${APP_NAME}" 2>/dev/null || true
