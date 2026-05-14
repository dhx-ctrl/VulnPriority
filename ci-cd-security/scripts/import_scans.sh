#!/usr/bin/env bash
# import_scans.sh — Import/reimport security-scan results into DefectDojo.

set -euo pipefail

# ─────────────────────────────────────────────────────────────
# Security: mask secrets in GitHub Actions logs
# ─────────────────────────────────────────────────────────────
if [[ -n "${DOJO_TOKEN:-}" ]]; then
  echo "::add-mask::${DOJO_TOKEN}"
fi

if [[ -n "${DEFECTDOJO_API_KEY:-}" ]]; then
  echo "::add-mask::${DEFECTDOJO_API_KEY}"
fi

# Prevent accidental shell command tracing from exposing curl headers.
set +x

# Use a private temp directory instead of global /tmp files.
SAFE_TMP_BASE="${RUNNER_TEMP:-${RUN_OUTPUT_DIR:-/tmp}}"
SAFE_TMP_DIR="${SAFE_TMP_BASE}/vulnpriority-${GITHUB_RUN_ID:-manual}"
mkdir -p "$SAFE_TMP_DIR"
chmod 700 "$SAFE_TMP_DIR" 2>/dev/null || true

cleanup_tmp() {
  rm -rf "$SAFE_TMP_DIR" 2>/dev/null || true
}
trap cleanup_tmp EXIT

# Redact secrets before printing any API error body.
redact_secrets() {
  python3 -c '
import os, re, sys
text = sys.stdin.read()
for key in ("DOJO_TOKEN", "DEFECTDOJO_API_KEY"):
    val = os.environ.get(key, "")
    if val:
        text = text.replace(val, "***REDACTED_SECRET***")
text = re.sub(r"Token\s+[A-Za-z0-9._:-]+", "Token ***REDACTED***", text)
print(text, end="")
'
}

###############################################################################
#  1. Load scan metadata written by CI
###############################################################################

META_FILE="${RUN_OUTPUT_DIR}/scan_meta.env"
if [[ ! -f "$META_FILE" ]]; then
  echo "ERROR: $META_FILE not found — was the CI setup step skipped?"
  exit 1
fi

# Securely load scan_meta.env:
# - no global /tmp metadata file
# - no raw source of untrusted env
# - only whitelisted keys accepted
# - Windows CRLF normalized
# - values shell-quoted with shlex.quote
set -a
# shellcheck disable=SC1090
source <(
  python3 - "$META_FILE" <<'PY'
import sys
import shlex

src = sys.argv[1]

allowed = {
    "APP_NAME",
    "APP_URL",
    "DOCKER_IMAGE_NAME",
    "ENABLE_SEMGREP",
    "ENABLE_TRIVY_FS",
    "ENABLE_TRIVY_IMAGE",
    "ENABLE_ZAP",
    "REQUIRE_SEMGREP",
    "REQUIRE_TRIVY_FS",
    "REQUIRE_TRIVY_IMAGE",
    "REQUIRE_ZAP",
    "GIT_COMMIT",
    "GIT_BRANCH",
    "BUILD_ID",
    "COMMIT_HASH",
    "BRANCH_TAG",
    "REPO_URI",
    "TEST_STRATEGY",
    "DOJO_PRODUCT_NAME",
}

with open(src, "rb") as f:
    text = f.read().decode("utf-8-sig", errors="replace")

for raw_line in text.splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue

    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()

    if key not in allowed:
        continue

    print(f"{key}={shlex.quote(value)}")
PY
)
set +a

# Backward-compatible fallbacks from scan_meta.env / GitHub env
BUILD_ID="${BUILD_ID:-${GITHUB_RUN_ID:-manual}}"
COMMIT_HASH="${COMMIT_HASH:-${GIT_COMMIT:-unknown}}"
BRANCH_TAG="${BRANCH_TAG:-${GIT_BRANCH:-unknown}}"

if [[ -z "${REPO_URI:-}" ]]; then
  if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" ]]; then
    REPO_URI="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"
  else
    REPO_URI="unknown"
  fi
fi

TEST_STRATEGY="${TEST_STRATEGY:-Automated CI/CD security scan import}"

###############################################################################
#  2. Validate required env vars
###############################################################################

required_vars=(
  DOJO_URL  DOJO_TOKEN
  DOJO_PRODUCT_TYPE_NAME  DOJO_ENGAGEMENT_NAME
  DOJO_ENGAGEMENT_LEAD_USERNAME
  SCAN_TYPE_TRIVY_FS  SCAN_TYPE_TRIVY_IMAGE  SCAN_TYPE_ZAP  SCAN_TYPE_SEMGREP
  BUILD_ID  COMMIT_HASH  BRANCH_TAG  REPO_URI  TEST_STRATEGY
  RUN_OUTPUT_DIR  APP_NAME
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: Required variable missing or empty: $v"
    exit 1
  fi
done

# Product name defaults to APP_NAME but can be overridden.
DOJO_PRODUCT_NAME="${DOJO_PRODUCT_NAME:-${APP_NAME}}"

###############################################################################
#  3. Scanner enable/disable flags
###############################################################################

ENABLE_SEMGREP="${ENABLE_SEMGREP:-true}"
ENABLE_TRIVY_FS="${ENABLE_TRIVY_FS:-true}"
ENABLE_TRIVY_IMAGE="${ENABLE_TRIVY_IMAGE:-true}"
ENABLE_ZAP="${ENABLE_ZAP:-true}"

REQUIRE_SEMGREP="${REQUIRE_SEMGREP:-false}"
REQUIRE_TRIVY_FS="${REQUIRE_TRIVY_FS:-false}"
REQUIRE_TRIVY_IMAGE="${REQUIRE_TRIVY_IMAGE:-false}"
REQUIRE_ZAP="${REQUIRE_ZAP:-false}"

echo "════════════════════════════════════════════════════════════════"
echo "  DefectDojo import"
echo "  App            : ${APP_NAME}"
echo "  Product Type   : ${DOJO_PRODUCT_TYPE_NAME}"
echo "  Product        : ${DOJO_PRODUCT_NAME}"
echo "  Engagement     : ${DOJO_ENGAGEMENT_NAME}"
echo "  Scanners       : semgrep=${ENABLE_SEMGREP}  trivy_fs=${ENABLE_TRIVY_FS}"
echo "                   trivy_image=${ENABLE_TRIVY_IMAGE}  zap=${ENABLE_ZAP}"
echo "════════════════════════════════════════════════════════════════"

###############################################################################
#  HELPER FUNCTIONS
###############################################################################

urlencode() {
  python3 -c "import sys; from urllib.parse import quote; print(quote(sys.argv[1], safe=''))" "$1"
}

extract_first_id() {
  python3 -c "
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    print('ERROR: invalid JSON: ' + str(e), file=sys.stderr)
    sys.exit(1)
results = data.get('results') or []
print(results[0].get('id', '') if results else '')
"
}

extract_id() {
  python3 -c "
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    print('ERROR: invalid JSON: ' + str(e), file=sys.stderr)
    sys.exit(1)
print(data.get('id', ''))
"
}

curl_dd() {
  local label="$1"; shift
  local tmp http_code body

  tmp=$(mktemp "${SAFE_TMP_DIR}/dojo_curl_XXXXXX.json")

  http_code=$(curl -sS -w "%{http_code}" -o "$tmp" "$@") || {
    echo "ERROR [${label}]: curl network/TLS error (exit $?)" >&2
    rm -f "$tmp"
    return 1
  }

  body=$(cat "$tmp")
  rm -f "$tmp"

  if [[ "${http_code}" -ge 400 ]]; then
    echo "ERROR [${label}]: DefectDojo returned HTTP ${http_code}" >&2
    echo "  Body: $(printf '%s' "${body:0:1200}" | redact_secrets)" >&2
    return 1
  fi

  printf '%s' "$body"
}

metadata_json() {
  python3 -c "
import json, os
print(json.dumps({
    'build_id':                    os.environ['BUILD_ID'],
    'commit_hash':                 os.environ['COMMIT_HASH'],
    'branch_tag':                  os.environ['BRANCH_TAG'],
    'source_code_management_uri':  os.environ['REPO_URI'],
    'test_strategy':               os.environ['TEST_STRATEGY'],
    'deduplication_on_engagement': False,
}))
"
}

log_import_response() {
  local label="$1"
  local response="$2"
  local tmp

  tmp=$(mktemp "${SAFE_TMP_DIR}/dojo_resp_XXXXXX.json")
  printf '%s' "$response" > "$tmp"
  python3 "$(dirname "$0")/dojo_log_response.py" "$label" "$tmp"
  rm -f "$tmp"
}

###############################################################################
#  CONNECTIVITY CHECK
###############################################################################

echo "Checking DefectDojo connectivity..."
DOJO_CHECK_FILE="${SAFE_TMP_DIR}/dojo_check.txt"

http_code=$(curl -o "$DOJO_CHECK_FILE" -sS -w "%{http_code}" \
  -H "Authorization: Token ${DOJO_TOKEN}" \
  "${DOJO_URL}/api/v2/users/?limit=1")

if [[ "$http_code" != "200" ]]; then
  echo "ERROR: DefectDojo returned HTTP $http_code — check DOJO_URL / DOJO_TOKEN"
  redact_secrets < "$DOJO_CHECK_FILE"
  exit 1
fi

echo "DefectDojo reachable (HTTP $http_code)"

###############################################################################
#  PRODUCT TYPE — get or create
###############################################################################

get_or_create_product_type() {
  local pt_name="$1"
  local encoded_name
  encoded_name=$(urlencode "$pt_name")

  echo "Looking up Product Type '${pt_name}'..." >&2

  local response
  response=$(curl_dd "product-type-lookup" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/product_types/?name=${encoded_name}&limit=10") \
    || { echo "ERROR: product-type lookup failed" >&2; return 1; }

  local pt_id
  pt_id=$(printf '%s' "$response" | PT_NAME="$pt_name" python3 -c "
import json, sys, os
target = os.environ['PT_NAME']
data   = json.loads(sys.stdin.read())
for r in data.get('results', []):
    if r.get('name') == target:
        print(r['id'])
        break
")

  if [[ -n "$pt_id" ]]; then
    echo "  Found Product Type '${pt_name}' → ID ${pt_id}" >&2
    echo "$pt_id"
    return 0
  fi

  echo "  Product Type '${pt_name}' not found — creating..." >&2

  local payload
  payload=$(PT_NAME="$pt_name" python3 -c "
import json, os
print(json.dumps({'name': os.environ['PT_NAME']}))
")

  local created
  created=$(curl_dd "product-type-create" -X POST \
    "${DOJO_URL}/api/v2/product_types/" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload") \
    || { echo "ERROR: product-type creation failed" >&2; return 1; }

  pt_id=$(printf '%s' "$created" | extract_id)
  if [[ -z "$pt_id" ]]; then
    echo "ERROR: product-type creation returned no ID" >&2
    echo "  Response: $(printf '%s' "${created:0:500}" | redact_secrets)" >&2
    return 1
  fi

  echo "  Created Product Type '${pt_name}' → ID ${pt_id}" >&2
  echo "$pt_id"
}

###############################################################################
#  PRODUCT — get or create
###############################################################################

get_or_create_product() {
  local prod_name="$1"
  local prod_type_id="$2"
  local encoded_name
  encoded_name=$(urlencode "$prod_name")

  echo "Looking up Product '${prod_name}'..." >&2

  local response
  response=$(curl_dd "product-lookup" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/products/?name=${encoded_name}&limit=10") \
    || { echo "ERROR: product lookup failed" >&2; return 1; }

  local product_id
  product_id=$(printf '%s' "$response" | PROD_NAME="$prod_name" python3 -c "
import json, sys, os
target = os.environ['PROD_NAME']
data   = json.loads(sys.stdin.read())
for r in data.get('results', []):
    if r.get('name') == target:
        print(r['id'])
        break
")

  if [[ -n "$product_id" ]]; then
    echo "  Found Product '${prod_name}' → ID ${product_id}" >&2
    echo "$product_id"
    return 0
  fi

  echo "  Product '${prod_name}' not found — creating (prod_type=${prod_type_id})..." >&2

  local payload
  payload=$(PROD_NAME="$prod_name" python3 -c "
import json, os
print(json.dumps({
    'name':        os.environ['PROD_NAME'],
    'description': 'Auto-created by DevSecOps pipeline',
    'prod_type':   int('${prod_type_id}'),
}))
")

  local created
  created=$(curl_dd "product-create" -X POST \
    "${DOJO_URL}/api/v2/products/" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload") \
    || { echo "ERROR: product creation failed" >&2; return 1; }

  product_id=$(printf '%s' "$created" | extract_id)
  if [[ -z "$product_id" ]]; then
    echo "ERROR: product creation returned no ID" >&2
    echo "  Response: $(printf '%s' "${created:0:500}" | redact_secrets)" >&2
    return 1
  fi

  echo "  Created Product '${prod_name}' → ID ${product_id}" >&2
  echo "$product_id"
}

###############################################################################
#  ENGAGEMENT — get or create
###############################################################################

get_or_create_engagement() {
  local eng_name="$1"
  local product_id="$2"

  echo "Looking up Engagement '${eng_name}' in product ${product_id}..." >&2

  local engagement_id=""
  local encoded_name encoded_product tmp http_code body
  encoded_name=$(urlencode "$eng_name")
  encoded_product=$(urlencode "$product_id")

  tmp=$(mktemp "${SAFE_TMP_DIR}/dojo_eng_XXXXXX.json")
  http_code=$(curl -sS -w "%{http_code}" -o "$tmp" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/engagements/?name=${encoded_name}&product=${encoded_product}&limit=1")
  body=$(cat "$tmp")
  rm -f "$tmp"

  if [[ "$http_code" == "200" ]]; then
    engagement_id=$(printf '%s' "$body" | extract_first_id)
  else
    echo "  WARN: combined filter returned HTTP ${http_code}, falling back to product-only..." >&2

    tmp=$(mktemp "${SAFE_TMP_DIR}/dojo_eng_XXXXXX.json")
    http_code=$(curl -sS -w "%{http_code}" -o "$tmp" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      "${DOJO_URL}/api/v2/engagements/?product=${encoded_product}&limit=200")
    body=$(cat "$tmp")
    rm -f "$tmp"

    if [[ "${http_code}" -ge 400 ]]; then
      echo "ERROR: engagement fallback lookup returned HTTP ${http_code}" >&2
      echo "  Body: $(printf '%s' "${body:0:800}" | redact_secrets)" >&2
      return 1
    fi

    engagement_id=$(printf '%s' "$body" | ENG_NAME="$eng_name" python3 -c "
import json, sys, os
target = os.environ['ENG_NAME']
data   = json.loads(sys.stdin.read())
match  = next((r for r in data.get('results', []) if r.get('name') == target), None)
print(match['id'] if match else '')
")
  fi

  if [[ -n "$engagement_id" ]]; then
    echo "  Found Engagement '${eng_name}' → ID ${engagement_id}" >&2
    echo "  Patching engagement metadata..." >&2

    curl_dd "engagement-patch" -X PATCH \
      "${DOJO_URL}/api/v2/engagements/${engagement_id}/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$(metadata_json)" > /dev/null \
      || { echo "ERROR: engagement metadata patch failed" >&2; return 1; }

    echo "$engagement_id"
    return 0
  fi

  echo "  Engagement '${eng_name}' not found — creating..." >&2

  local encoded_lead lead_payload lead_id
  encoded_lead=$(urlencode "$DOJO_ENGAGEMENT_LEAD_USERNAME")

  lead_payload=$(curl_dd "user-lookup" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/users/?username=${encoded_lead}&limit=1") \
    || { echo "ERROR: user lookup failed" >&2; return 1; }

  lead_id=$(printf '%s' "$lead_payload" | extract_first_id)
  if [[ -z "$lead_id" ]]; then
    echo "ERROR: DefectDojo user not found: ${DOJO_ENGAGEMENT_LEAD_USERNAME}" >&2
    return 1
  fi

  local target_start target_end
  target_start=$(date -u +%Y-%m-%d)
  target_end=$(date -u -d "+7 days" +%Y-%m-%d 2>/dev/null \
    || date -u -v+7d +%Y-%m-%d 2>/dev/null \
    || echo "$target_start")

  local payload
  payload=$(
    ENG_NAME="$eng_name" PRODUCT_ID="$product_id" LEAD_ID="$lead_id" \
    TARGET_START="$target_start" TARGET_END="$target_end" \
    python3 -c "
import json, os
print(json.dumps({
    'name':                        os.environ['ENG_NAME'],
    'product':                     int(os.environ['PRODUCT_ID']),
    'status':                      'In Progress',
    'engagement_type':             'CI/CD',
    'target_start':                os.environ['TARGET_START'],
    'target_end':                  os.environ['TARGET_END'],
    'lead':                        int(os.environ['LEAD_ID']),
    'build_id':                    os.environ['BUILD_ID'],
    'commit_hash':                 os.environ['COMMIT_HASH'],
    'branch_tag':                  os.environ['BRANCH_TAG'],
    'source_code_management_uri':  os.environ['REPO_URI'],
    'test_strategy':               os.environ['TEST_STRATEGY'],
    'deduplication_on_engagement': False,
}))
")

  local created
  created=$(curl_dd "engagement-create" -X POST \
    "${DOJO_URL}/api/v2/engagements/" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload") \
    || { echo "ERROR: engagement creation failed" >&2; return 1; }

  engagement_id=$(printf '%s' "$created" | extract_id)
  if [[ -z "$engagement_id" ]]; then
    echo "ERROR: engagement creation returned no ID" >&2
    echo "  Response: $(printf '%s' "${created:0:500}" | redact_secrets)" >&2
    return 1
  fi

  echo "  Created Engagement '${eng_name}' → ID ${engagement_id}" >&2
  echo "$engagement_id"
}

###############################################################################
#  TEST LOOKUP
###############################################################################

find_existing_test() {
  local scan_type="$1"
  local test_title="$2"
  local encoded_type encoded_title
  encoded_type=$(urlencode "$scan_type")
  encoded_title=$(urlencode "$test_title")

  local result
  result=$(curl_dd "test-lookup [${test_title}]" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/tests/?engagement=${DOJO_ENGAGEMENT_ID}&test_type_name=${encoded_type}&title=${encoded_title}&limit=1") \
    || { echo "ERROR: test lookup failed for [${test_title}]" >&2; return 1; }

  printf '%s' "$result" | extract_first_id
}

###############################################################################
#  IMPORT / REIMPORT A SINGLE SCAN
###############################################################################

import_or_reimport() {
  local scan_type="$1"
  local file_path="$2"
  local min_sev="$3"
  local mime="$4"
  local label="$5"

  if [[ ! -f "$file_path" ]]; then
    echo "ERROR: scan file not found: $file_path" >&2
    exit 1
  fi

  local test_title="${APP_NAME} - ${label}"

  local test_id
  test_id=$(find_existing_test "$scan_type" "$test_title")

  local response
  if [[ -n "$test_id" ]]; then
    echo "Reimporting (test ${test_id}) [${test_title}]: ${scan_type} <- ${file_path}"

    response=$(curl_dd "reimport [${test_title}]" -X POST \
      "${DOJO_URL}/api/v2/reimport-scan/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -F "active=true" \
      -F "verified=false" \
      -F "close_old_findings=true" \
      -F "deduplication_on_engagement=false" \
      -F "test=${test_id}" \
      -F "scan_type=${scan_type}" \
      -F "test_title=${test_title}" \
      -F "minimum_severity=${min_sev}" \
      -F "product=${DOJO_PRODUCT_ID}" \
      -F "engagement=${DOJO_ENGAGEMENT_ID}" \
      -F "file=@${file_path};type=${mime}") \
      || { echo "ERROR: reimport-scan failed for [${test_title}]" >&2; exit 1; }
  else
    echo "Importing (first run) [${test_title}]: ${scan_type} <- ${file_path}"

    response=$(curl_dd "import [${test_title}]" -X POST \
      "${DOJO_URL}/api/v2/import-scan/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -F "active=true" \
      -F "verified=false" \
      -F "close_old_findings=false" \
      -F "deduplication_on_engagement=false" \
      -F "scan_type=${scan_type}" \
      -F "test_title=${test_title}" \
      -F "minimum_severity=${min_sev}" \
      -F "product=${DOJO_PRODUCT_ID}" \
      -F "engagement=${DOJO_ENGAGEMENT_ID}" \
      -F "file=@${file_path};type=${mime}") \
      || { echo "ERROR: import-scan failed for [${test_title}]" >&2; exit 1; }
  fi

  log_import_response "${test_title}" "$response"
}

###############################################################################
#  GATE — check a scan file before importing
###############################################################################

check_scan_file() {
  local scanner="$1"
  local file="$2"
  local enabled="$3"
  local required="$4"

  if [[ "$enabled" != "true" ]]; then
    echo "SKIP [${scanner}]: disabled"
    return 1
  fi

  if [[ ! -s "$file" ]]; then
    if [[ "$required" == "true" ]]; then
      echo "ERROR [${scanner}]: output file missing or empty: ${file}"
      echo "       REQUIRE=true — aborting."
      exit 1
    else
      echo "WARN [${scanner}]: output file missing or empty — skipping"
      return 1
    fi
  fi

  echo "OK [${scanner}]: $(wc -c < "$file") bytes"
  return 0
}

###############################################################################
#  MAIN — resolve hierarchy, then import scans
###############################################################################

echo "RUN_OUTPUT_DIR=${RUN_OUTPUT_DIR}"

if [[ ! -d "$RUN_OUTPUT_DIR" ]]; then
  echo "ERROR: RUN_OUTPUT_DIR does not exist: $RUN_OUTPUT_DIR"
  exit 1
fi

DOJO_PRODUCT_TYPE_ID=$(get_or_create_product_type "$DOJO_PRODUCT_TYPE_NAME")
if [[ -z "$DOJO_PRODUCT_TYPE_ID" ]]; then
  echo "ERROR: Failed to resolve Product Type"
  exit 1
fi
echo "Product Type ID : ${DOJO_PRODUCT_TYPE_ID}"

DOJO_PRODUCT_ID=$(get_or_create_product "$DOJO_PRODUCT_NAME" "$DOJO_PRODUCT_TYPE_ID")
if [[ -z "$DOJO_PRODUCT_ID" ]]; then
  echo "ERROR: Failed to resolve Product"
  exit 1
fi
export DOJO_PRODUCT_ID
echo "Product ID      : ${DOJO_PRODUCT_ID}"

DOJO_ENGAGEMENT_ID=$(get_or_create_engagement "$DOJO_ENGAGEMENT_NAME" "$DOJO_PRODUCT_ID")
if [[ -z "$DOJO_ENGAGEMENT_ID" ]]; then
  echo "ERROR: Failed to resolve Engagement"
  exit 1
fi
export DOJO_ENGAGEMENT_ID
echo "Engagement ID   : ${DOJO_ENGAGEMENT_ID}"

echo ""
ls -la "${RUN_OUTPUT_DIR}"
echo ""

if check_scan_file "semgrep" "${RUN_OUTPUT_DIR}/semgrep.json" "$ENABLE_SEMGREP" "$REQUIRE_SEMGREP"; then
  import_or_reimport "${SCAN_TYPE_SEMGREP}" "${RUN_OUTPUT_DIR}/semgrep.json" "Low" "application/json" "Semgrep SAST"
fi

if check_scan_file "trivy_fs" "${RUN_OUTPUT_DIR}/trivy_fs.json" "$ENABLE_TRIVY_FS" "$REQUIRE_TRIVY_FS"; then
  import_or_reimport "${SCAN_TYPE_TRIVY_FS}" "${RUN_OUTPUT_DIR}/trivy_fs.json" "Low" "application/json" "Trivy Filesystem"
fi

if check_scan_file "trivy_image" "${RUN_OUTPUT_DIR}/trivy_image.json" "$ENABLE_TRIVY_IMAGE" "$REQUIRE_TRIVY_IMAGE"; then
  import_or_reimport "${SCAN_TYPE_TRIVY_IMAGE}" "${RUN_OUTPUT_DIR}/trivy_image.json" "Low" "application/json" "Trivy Image"
fi

if check_scan_file "zap" "${RUN_OUTPUT_DIR}/zap.xml" "$ENABLE_ZAP" "$REQUIRE_ZAP"; then
  import_or_reimport "${SCAN_TYPE_ZAP}" "${RUN_OUTPUT_DIR}/zap.xml" "Low" "text/xml" "ZAP Baseline"
fi

echo ""
echo "All enabled scans processed for: ${APP_NAME}"
