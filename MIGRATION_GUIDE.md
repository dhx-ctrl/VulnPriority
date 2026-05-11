# VulnPriority CI/CD Refactoring — Migration Guide

## 1. Final Folder Tree

```
VulnPriority/
  ci-cd-security/
    scripts/
      run_pipeline.sh          # Main controller — orchestrates everything
      common.sh                # Shared helper functions (logging, URL parsing)
      setup_scan_dir.sh        # Prepare /tmp/devsecops-scans/$GITHUB_RUN_ID
      wait_for_app.sh          # Wait for target app to respond on zapnet
      run_semgrep.sh           # Semgrep SAST scan
      run_trivy_fs.sh          # Trivy filesystem SCA scan
      run_trivy_image.sh       # Trivy image SCA scan
      run_zap.sh               # ZAP baseline DAST scan (pre-flight + zap_wrk)
      import_defectdojo.sh     # Sets DD env vars, calls import_scans.sh
      import_scans.sh          # DefectDojo import logic (UNCHANGED from original)
      dojo_log_response.py     # DD response parser (UNCHANGED from original)
      debug_inspect.sh         # Inspect raw scan outputs for CI logs
      cleanup.sh               # Remove temp files and Docker networks

    products/
      juice-shop/
        product.env            # App-specific configuration
        start_app.sh           # Docker startup for Juice Shop
      dvwa/
        product.env
        start_app.sh
        post_start.sh          # DVWA-only: POST /setup.php database init
      dvna/
        product.env
        start_app.sh
      nodegoat/
        product.env
        start_app.sh           # MongoDB sidecar + NodeGoat startup
        stop_app.sh            # Stop both app container and MongoDB

    example-workflows/
      juice-shop-devsecops.yml
      dvwa-devsecops.yml
      dvna-devsecops.yml
      nodegoat-devsecops.yml
```

## 7. DVNA Test-First Migration (Safe Migration)

Test with DVNA first because it's the simplest app (pre-built image, single
container, no post-start hooks, no sidecars).

### Step 1: Create VulnPriority repo

```bash
mkdir VulnPriority && cd VulnPriority
# extract the tarball contents here
git init
git add .
git commit -m "DevSecOps central pipeline"
git remote add origin <your-vulnpriority-url>
git push -u origin main
```

### Step 2: Prepare DVNA repo (keep old files as backup)

```bash
cd /path/to/dvna-repo

# Back up old workflow — do NOT delete yet
cp .github/workflows/devsecops.yml .github/workflows/devsecops.yml.bak
cp .github/workflows/import-defectdojo.yml .github/workflows/import-defectdojo.yml.bak

# Disable old import-defectdojo.yml so it doesn't double-run
# (rename so GH Actions ignores it)
mv .github/workflows/import-defectdojo.yml .github/workflows/import-defectdojo.yml.disabled

# Install new wrapper workflow
cp /path/to/VulnPriority/ci-cd-security/example-workflows/dvna-devsecops.yml \
   .github/workflows/devsecops.yml
```

### Step 3: Verify secret exists

In GitHub → DVNA repo → Settings → Secrets and variables → Actions:
- Confirm `DOJO_TOKEN` secret exists (same one you already use).

### Step 4: If VulnPriority is private

Add a PAT with read access to VulnPriority as a secret named `VULNPRIORITY_TOKEN`
in the DVNA repo, then edit the wrapper workflow's VulnPriority checkout step:

```yaml
      - name: Checkout VulnPriority (central CI/CD repo)
        uses: actions/checkout@v4
        with:
          repository: ${{ github.repository_owner }}/VulnPriority
          token: ${{ secrets.VULNPRIORITY_TOKEN }}
          path: vulnpriority
```

### Step 5: Push and trigger

```bash
cd /path/to/dvna-repo
git add -A
git commit -m "test: migrate to VulnPriority central pipeline (DVNA)"
git push
```

Or use workflow_dispatch from the GitHub Actions UI.

### Step 6: Validate each stage in the Actions log

Open the workflow run in GitHub Actions. Check each stage in order:

**6a. Scan output directory created:**
```
Look for: RUN_OUTPUT_DIR=/tmp/devsecops-scans/<run-id>
Look for: APP_NAME=dvna | APP_URL=http://dvna:9090
Look for: Scanners → semgrep=true trivy_fs=true trivy_image=true zap=true
```

**6b. scan_meta.env written:**
```
Look for: scan_meta.env written:
          APP_NAME=dvna
          ENABLE_SEMGREP=true
          ...
```

**6c. Semgrep completed:**
```
Look for: semgrep.json written (XXXXX bytes)
```

**6d. Trivy filesystem completed:**
```
Look for: trivy_fs.json written (XXXXX bytes)
```

**6e. Trivy image completed:**
```
Look for: trivy_image.json written (XXXXX bytes)
```

**6f. ZAP — app started, waited, scanned:**
```
Look for: dvna ready after X×2s with HTTP 200
Look for: Pre-flight OK — http://dvna:9090 returned HTTP 200
Look for: zap.xml written (XXXXX bytes)
```

**6g. DefectDojo import:**
```
Look for: DefectDojo reachable (HTTP 200)
Look for: Product Type 'CI-CD Apps' → ID X
Look for: Product 'dvna' → ID X
Look for: Engagement 'DevSecOps-CICD' → ID X

For each scanner:
Look for: OK [dvna - Semgrep SAST] test_id=X | total=X | active=X | dupes=X
Look for: OK [dvna - Trivy Filesystem] test_id=X | total=X | active=X | dupes=X
Look for: OK [dvna - Trivy Image] test_id=X | total=X | active=X | dupes=X
Look for: OK [dvna - ZAP Baseline] test_id=X | total=X | active=X | dupes=X

Look for: All enabled scans processed for: dvna
```

**6h. Artifact uploaded:**
```
Look for: Upload scan reports step showing files uploaded
```

### Step 7: Verify in DefectDojo

1. Open DefectDojo at http://localhost:8080
2. Go to Products → look for "dvna"
3. Click into it → Engagements → "DevSecOps-CICD"
4. Verify 4 tests exist:
   - "dvna - Semgrep SAST" (scan type: Semgrep JSON Report)
   - "dvna - Trivy Filesystem" (scan type: Trivy Scan)
   - "dvna - Trivy Image" (scan type: Trivy Scan)
   - "dvna - ZAP Baseline" (scan type: ZAP Scan)
5. Check finding counts match what the CI log reported

### Step 8: Run again to verify reimport

Push another commit or trigger workflow_dispatch again. This time:

```
Look for: Reimporting (test <id>) [dvna - Semgrep SAST]
```

Instead of "Importing (first run)". This confirms reimport logic works.

### Step 9: Test scanner disable

Trigger via workflow_dispatch with ENABLE_ZAP=false. Verify:
- ZAP section shows "SKIP: ZAP (disabled)"
- No ZAP container started
- DefectDojo import skips ZAP
- Other 3 scanners still run

### Step 10: Confirm old import-defectdojo.yml is not needed

The old import-defectdojo.yml triggered on `workflow_run` completion of the CI
workflow. Since you renamed it to `.disabled`, it can't fire. The new pipeline
handles import inline. If Steps 6-8 passed, delete it:

```bash
rm .github/workflows/import-defectdojo.yml.disabled
rm .github/workflows/devsecops.yml.bak
rm .github/workflows/import-defectdojo.yml.bak
```

### Step 11: Migrate the other 3 repos

Once DVNA is confirmed working, repeat Steps 2-10 for:
- DVWA (has post_start.sh — verify database init in logs)
- Juice Shop (simplest after DVNA)
- NodeGoat (has MongoDB sidecar — verify mongo startup in logs)

## 8. Full Migration Checklist

### What to put in VulnPriority

The entire `ci-cd-security/` directory from this deliverable.

### What to replace in each forked app repo

1. **Delete** (after verifying the new pipeline works):
   - `.github/workflows/import-defectdojo.yml`
   - `.github/scripts/import_scans.sh` (or wherever it lived)
   - `.github/scripts/dojo_log_response.py` (or wherever it lived)

2. **Replace** `.github/workflows/devsecops.yml` with the matching wrapper:
   - Juice Shop → `juice-shop-devsecops.yml`
   - DVWA → `dvwa-devsecops.yml`
   - DVNA → `dvna-devsecops.yml`
   - NodeGoat → `nodegoat-devsecops.yml`

### Secrets required (per app repo)

| Secret | Required | Purpose |
|--------|----------|---------|
| `DOJO_TOKEN` | Yes | DefectDojo API token |
| `VULNPRIORITY_TOKEN` | Only if VulnPriority is private | PAT with read access to VulnPriority |

### Environment variables (all have defaults, override via env if needed)

| Variable | Default | Override? |
|----------|---------|-----------|
| `DOJO_URL` | `http://localhost:8080` | Set in workflow env if different |
| `DOJO_PRODUCT_TYPE_NAME` | `CI-CD Apps` | Set in workflow env if different |
| `DOJO_ENGAGEMENT_NAME` | `DevSecOps-CICD` | Set in workflow env if different |
| `DOJO_ENGAGEMENT_LEAD_USERNAME` | `admin` | Set in workflow env if different |
| `ENABLE_SEMGREP` | `true` | Via workflow_dispatch |
| `ENABLE_TRIVY_FS` | `true` | Via workflow_dispatch |
| `ENABLE_TRIVY_IMAGE` | `true` | Via workflow_dispatch |
| `ENABLE_ZAP` | `true` | Via workflow_dispatch |

## 9. Assumptions

1. **CI + CD merged into one run.** The original used two separate workflows
   (devsecops.yml for scanning, import-defectdojo.yml for importing). The
   refactored pipeline runs both in sequence within run_pipeline.sh. The
   workflow_run trigger is eliminated. scan_meta.env is still written and
   read by import_scans.sh to keep that script unchanged.

2. **import_scans.sh and dojo_log_response.py are copied verbatim.** Zero
   changes to DefectDojo import logic, API payloads, test-title namespacing,
   hierarchy resolution, or error handling.

3. **Scan output path is /tmp/devsecops-scans/$GITHUB_RUN_ID.** This matches
   the original workflows exactly. Not changed to $RUNNER_TEMP because
   self-hosted runners set RUNNER_TEMP to a different path.

4. **ZAP work directory pattern uses zap_wrk/ for all apps.** The original
   juice-shop and dvwa workflows used zap_wrk/ with chmod 777 and a pre-flight
   reachability check. The original dvna and nodegoat mounted RUN_OUTPUT_DIR
   directly. The refactored run_zap.sh uses the zap_wrk/ pattern for all apps
   because it prevents the PermissionError. The final zap.xml is always copied
   to RUN_OUTPUT_DIR/zap.xml where import_scans.sh expects it.

5. **Wait-for-app uses container state check + HTTP check.** The most robust
   pattern, already used by dvna and nodegoat originals. Juice-shop and dvwa
   used HTTP-only. The added container state check is strictly more robust.

6. **NodeGoat image is built from source, not pulled.** Controlled by
   DOCKER_IMAGE_SOURCE=build in product.env. Build only happens when
   ENABLE_TRIVY_IMAGE or ENABLE_ZAP is true.

7. **DVWA post-start hook.** Database init (POST /setup.php) extracted into
   products/dvwa/post_start.sh. run_pipeline.sh auto-runs it if the file exists.

8. **NodeGoat MongoDB sidecar.** Start and stop logic in start_app.sh and
   stop_app.sh respectively. Other apps use the default stop (docker rm -f).

9. **Branch triggers preserved per-app.** Juice Shop / DVWA: master.
   DVNA / NodeGoat: master + main.

10. **Semgrep extra configs.** DVNA and NodeGoat include --config=p/nodejs.
    Parameterized via SEMGREP_EXTRA_CONFIGS in product.env.

11. **upload-artifact stays in wrapper workflow.** It requires the GitHub
    Action, which can only run as a workflow step. Cleanup runs AFTER it.

12. **The separate import-defectdojo.yml is no longer needed.** Its logic is
    now inline via import_defectdojo.sh + import_scans.sh.

## 10. Bugs Found and Fixed During Review

| # | Bug | Impact | Fix |
|---|-----|--------|-----|
| 1 | product.env used `ENABLE_SEMGREP="true"` (plain assignment) which clobbered workflow_dispatch overrides like `ENABLE_SEMGREP=false` | Scanner disable via UI would silently not work | Changed to `ENABLE_SEMGREP="${ENABLE_SEMGREP:-true}"` |
| 2 | cleanup.sh was called at the end of run_pipeline.sh, deleting scan files before the wrapper workflow's upload-artifact step could upload them | Artifact uploads would always be empty | Removed cleanup from run_pipeline.sh; added as separate workflow step after upload-artifact |
| 3 | Sourced scripts used `exit 0` / `exit 1` which terminates the parent shell (run_pipeline.sh) instead of just returning | wait_for_app.sh would kill the pipeline on success (`exit 0`), skipping ZAP, import, everything after | Changed all `exit` to `return` in sourced scripts (wait_for_app.sh, run_zap.sh, import_defectdojo.sh, nodegoat/start_app.sh) |
| 4 | DOJO_TOKEN was inherited via env but never explicitly exported for the `bash import_scans.sh` subprocess | Would work on most runners but could fail in edge cases with env isolation | Added explicit `export DOJO_TOKEN` in import_defectdojo.sh |
| 5 | setup_scan_dir.sh used `$RUNNER_TEMP` instead of `/tmp` | On self-hosted runners, RUNNER_TEMP is often `/home/runner/work/_temp`, not `/tmp`. Artifact upload path wouldn't match. | Hardcoded `/tmp` to match original workflows |
