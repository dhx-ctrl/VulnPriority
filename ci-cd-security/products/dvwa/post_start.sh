#!/usr/bin/env bash
# post_start.sh — DVWA database initialization.
#
# DVWA serves a setup page on first boot and won't function until you
# POST to /setup.php to create its MySQL tables.  Without this, ZAP
# gets null/error responses and crashes with "msg is null".
#
# Sourced by run_pipeline.sh after wait_for_app.sh.
# Expects: APP_NAME, APP_URL

set -euo pipefail

echo "Initializing DVWA database via POST to ${APP_URL}/setup.php ..."
HTTP_CODE=$(docker run --rm --network zapnet curlimages/curl:8.6.0 \
  -sS -o /dev/null -w "%{http_code}" --max-time 15 \
  -X POST "${APP_URL}/setup.php" \
  -d "create_db=Create+%2F+Reset+Database" 2>/dev/null) || HTTP_CODE="000"
echo "DVWA setup responded HTTP ${HTTP_CODE}"

# Verify the login page is now reachable (DB tables exist).
sleep 3
HTTP_CODE=$(docker run --rm --network zapnet curlimages/curl:8.6.0 \
  -sS -o /dev/null -w "%{http_code}" --max-time 10 \
  "${APP_URL}/login.php" 2>/dev/null) || HTTP_CODE="000"

if [[ "$HTTP_CODE" =~ ^(200|302)$ ]]; then
  echo "DVWA login page reachable (HTTP ${HTTP_CODE}) — ready for ZAP"
else
  echo "WARNING: DVWA login page returned HTTP ${HTTP_CODE} — ZAP may have issues"
  docker logs "target-${APP_NAME}" 2>&1 | tail -20 || true
fi
