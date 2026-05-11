#!/usr/bin/env bash
# wait_for_app.sh — Wait for the target app to become reachable from zapnet.
#
# SOURCED by run_pipeline.sh after start_app.sh.
# Uses return (not exit) because this runs in the parent shell's context.
# Expects: APP_NAME, APP_URL

set -euo pipefail

WAIT_TIMEOUT="${WAIT_TIMEOUT:-90}"

echo "Waiting for ${APP_NAME} to become ready at ${APP_URL}..."

docker pull curlimages/curl:8.6.0 2>/dev/null || true

_wait_done=false
for i in $(seq 1 "$WAIT_TIMEOUT"); do
  # Check that the container is still running (catches early crashes).
  RUNNING="$(docker inspect -f '{{.State.Running}}' "target-${APP_NAME}" 2>/dev/null || echo false)"
  if [ "$RUNNING" != "true" ]; then
    echo "ERROR: target-${APP_NAME} container stopped early. Logs:"
    docker logs "target-${APP_NAME}" --tail 200 || true
    return 1
  fi

  # Check reachability from inside zapnet.
  HTTP_CODE="$(docker run --rm --network zapnet curlimages/curl:8.6.0 \
    -sS -o /dev/null -w "%{http_code}" --max-time 5 "$APP_URL" 2>/dev/null || echo 000)"

  if [[ "$HTTP_CODE" =~ ^(200|301|302)$ ]]; then
    echo "${APP_NAME} ready after ${i}×2s with HTTP ${HTTP_CODE}"
    _wait_done=true
    break
  fi

  echo "Attempt ${i}/${WAIT_TIMEOUT}: not ready yet, HTTP=${HTTP_CODE}"
  sleep 2
done

if [[ "$_wait_done" != "true" ]]; then
  echo "ERROR: ${APP_NAME} did not become ready in time. Logs:"
  docker logs "target-${APP_NAME}" --tail 200 || true
  return 1
fi
