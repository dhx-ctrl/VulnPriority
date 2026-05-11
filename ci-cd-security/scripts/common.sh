#!/usr/bin/env bash
# common.sh — Shared helper functions for the DevSecOps pipeline.
#
# Sourced by run_pipeline.sh and other scripts.  Do NOT execute directly.

###############################################################################
#  Logging helpers
###############################################################################

log_section() {
  echo ""
  echo "══════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "══════════════════════════════════════════════════════════════"
}

log_subsection() {
  echo ""
  echo "── $1 ──────────────────────────────────────────────────────"
}

###############################################################################
#  Container hostname helper
###############################################################################
# Derive the hostname portion from a URL.
# Usage: CONTAINER_HOST=$(get_hostname_from_url "$APP_URL")

get_hostname_from_url() {
  python3 -c "from urllib.parse import urlparse; u=urlparse('$1'); print(u.hostname)"
}
