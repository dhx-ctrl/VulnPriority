#!/usr/bin/env bash
# run_zap.sh — Run OWASP ZAP baseline DAST scan.
#
# Sourced by run_pipeline.sh after the target app is running.
# Expects: APP_NAME, APP_URL, RUN_OUTPUT_DIR
#
# Uses a dedicated ZAP work directory with open permissions to avoid
# the PermissionError that occurs when ZAP (uid 1000) writes to a
# root-owned directory.

set -euo pipefail

ZAP_WORK_DIR="${RUN_OUTPUT_DIR}/zap_wrk"
rm -rf "$ZAP_WORK_DIR"
mkdir -p "$ZAP_WORK_DIR"
chmod 777 "$ZAP_WORK_DIR"

docker pull ghcr.io/zaproxy/zaproxy:stable

# Pre-flight: confirm the target is still reachable from zapnet.
# The image pull above can take minutes; the target may have crashed
# in the meantime.  ZAP gives an unhelpful "msg is null" error when
# the target is unreachable, so we catch it early with a clear message.
echo "Pre-flight: verifying ${APP_URL} is reachable from zapnet..."
PF_CODE=$(docker run --rm --network zapnet curlimages/curl:8.6.0 \
  -sS -o /dev/null -w "%{http_code}" --max-time 10 \
  "$APP_URL" 2>/dev/null) || PF_CODE="000"

if [[ "$PF_CODE" == "000" ]]; then
  echo "ERROR: ${APP_URL} is unreachable from zapnet (HTTP ${PF_CODE})"
  echo "Target container status:"
  docker ps -a --filter "name=target-${APP_NAME}" --format "{{.Status}}" || true
  docker logs "target-${APP_NAME}" 2>&1 | tail -30 || true
  return 1
fi
echo "Pre-flight OK — ${APP_URL} returned HTTP ${PF_CODE}"

docker run --rm --network zapnet \
  -v "${ZAP_WORK_DIR}:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t "$APP_URL" \
  -x zap.xml \
  -r zap.html || true   # ZAP exits non-zero when findings exist; that's expected

if [[ ! -s "${ZAP_WORK_DIR}/zap.xml" ]]; then
  echo "ERROR: ZAP did not produce zap.xml — check ZAP logs above"
  ls -la "$ZAP_WORK_DIR"
  return 1
fi

cp "${ZAP_WORK_DIR}/zap.xml" "${RUN_OUTPUT_DIR}/zap.xml"
echo "zap.xml written ($(wc -c < "${RUN_OUTPUT_DIR}/zap.xml") bytes)"
