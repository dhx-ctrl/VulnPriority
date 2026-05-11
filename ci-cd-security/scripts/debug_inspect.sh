#!/usr/bin/env bash
# debug_inspect.sh — Inspect raw scan outputs for CI log visibility.
#
# Sourced by run_pipeline.sh.
# Expects: RUN_OUTPUT_DIR

set -euo pipefail

inspect_semgrep() {
  python3 -c "
import json, sys
with open('${RUN_OUTPUT_DIR}/semgrep.json') as f:
    d = json.load(f)
results = d.get('results', [])
errors  = d.get('errors', [])
print(f'  findings : {len(results)}')
print(f'  errors   : {len(errors)}')
for i, r in enumerate(results[:5]):
    print(f'  [{i+1}] {r.get(\"check_id\",\"?\")} | {r.get(\"path\",\"?\")}:{r.get(\"start\",{}).get(\"line\",\"?\")} | severity={r.get(\"extra\",{}).get(\"severity\",\"?\")}')
if len(results) > 5:
    print(f'  ... and {len(results)-5} more')
"
}

inspect_trivy() {
  local file="$1"
  python3 -c "
import json, sys
with open('${RUN_OUTPUT_DIR}/${file}') as f:
    d = json.load(f)
results = d.get('Results', [])
total = sum(len(r.get('Vulnerabilities') or []) + len(r.get('Misconfigurations') or []) for r in results)
print(f'  Result blocks : {len(results)} | Total vulns+misconfigs: {total}')
count = 0
for r in results:
    for v in (r.get('Vulnerabilities') or [])[:3]:
        print(f'  [vuln] {v.get(\"VulnerabilityID\",\"?\")} | {v.get(\"PkgName\",\"?\")} | {v.get(\"Severity\",\"?\")}')
        count += 1
        if count >= 5: break
    if count >= 5: break
" "$file"
}

inspect_zap() {
  python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('${RUN_OUTPUT_DIR}/zap.xml')
root = tree.getroot()
alerts    = root.findall('.//alertitem')
instances = root.findall('.//instance')
print(f'  alert types : {len(alerts)} | instances: {len(instances)}')
for a in alerts[:5]:
    print(f'  [{a.findtext(\"alert\",\"?\")}] risk={a.findtext(\"riskdesc\",\"?\")} count={a.findtext(\"count\",\"?\")}')
"
}

for scanner in semgrep trivy_fs trivy_image zap; do
  echo "══════════════════════════════════════════════════"
  echo "DEBUG: $scanner"
  echo "══════════════════════════════════════════════════"
  case "$scanner" in
    semgrep)
      [[ -s "${RUN_OUTPUT_DIR}/semgrep.json" ]]     && inspect_semgrep          || echo "  SKIPPED / missing"
      ;;
    trivy_fs)
      [[ -s "${RUN_OUTPUT_DIR}/trivy_fs.json" ]]    && inspect_trivy trivy_fs.json || echo "  SKIPPED / missing"
      ;;
    trivy_image)
      [[ -s "${RUN_OUTPUT_DIR}/trivy_image.json" ]] && inspect_trivy trivy_image.json || echo "  SKIPPED / missing"
      ;;
    zap)
      [[ -s "${RUN_OUTPUT_DIR}/zap.xml" ]]          && inspect_zap              || echo "  SKIPPED / missing"
      ;;
  esac
done
