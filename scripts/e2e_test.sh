#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${SBH_E2E_LOG_DIR:-${TMPDIR:-/tmp}/sbh-e2e-$(date +%Y%m%d-%H%M%S)}"
LOG_FILE="${LOG_DIR}/e2e.log"
CASE_DIR="${LOG_DIR}/cases"
SUMMARY_JSON="${LOG_DIR}/summary.json"
VERBOSE=0

if [[ "${1:-}" == "--verbose" ]]; then
  VERBOSE=1
fi

mkdir -p "${CASE_DIR}"

# ── cleanup trap ─────────────────────────────────────────────────────────────
# Ensure temporary test artifacts are cleaned up on exit (success or failure).
# The log directory is preserved for debugging.
cleanup() {
  local exit_code=$?
  if [[ ${exit_code} -ne 0 ]]; then
    echo "E2E suite exited with code ${exit_code}. Logs preserved at: ${LOG_DIR}" >&2
  fi
  # Remove any stray background processes we may have started.
  jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
  exit "${exit_code}"
}
trap cleanup EXIT

# ── helpers ──────────────────────────────────────────────────────────────────

log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${msg}" | tee -a "${LOG_FILE}"
}

# Run a test case: expects zero exit + expected substring in combined output.
run_case() {
  local name="$1"
  local expected="$2"
  shift 2
  local -a cmd=("$@")
  local case_log="${CASE_DIR}/${name}.log"
  local start_ns
  start_ns=$(date +%s%N 2>/dev/null || date +%s)

  log "CASE START: ${name}"
  {
    echo "name=${name}"
    echo "expected=${expected}"
    echo "command=${cmd[*]}"
    echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  } > "${case_log}"

  set +e
  local output
  output="$(SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
  local status=$?
  set -e

  local end_ns
  end_ns=$(date +%s%N 2>/dev/null || date +%s)
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  {
    echo "status=${status}"
    echo "elapsed_ms=${elapsed_ms}"
    echo "----- output -----"
    echo "${output}"
  } >> "${case_log}"

  if [[ ${VERBOSE} -eq 1 ]]; then
    printf '%s\n' "${output}" | tee -a "${LOG_FILE}" >/dev/null
  fi

  if [[ ${status} -ne 0 ]]; then
    log "CASE FAIL: ${name} (non-zero status=${status}) [${elapsed_ms}ms]"
    return 1
  fi

  if ! grep -Fq "${expected}" <<< "${output}"; then
    log "CASE FAIL: ${name} (missing expected text: ${expected}) [${elapsed_ms}ms]"
    return 1
  fi

  log "CASE PASS: ${name} [${elapsed_ms}ms]"
  return 0
}

# Run a test case that expects a non-zero exit code.
run_case_expect_fail() {
  local name="$1"
  local expected_status="$2"
  local expected_text="$3"
  shift 3
  local -a cmd=("$@")
  local case_log="${CASE_DIR}/${name}.log"
  local start_ns
  start_ns=$(date +%s%N 2>/dev/null || date +%s)

  log "CASE START: ${name}"
  {
    echo "name=${name}"
    echo "expected_status=${expected_status}"
    echo "expected_text=${expected_text}"
    echo "command=${cmd[*]}"
    echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  } > "${case_log}"

  set +e
  local output
  output="$(SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
  local status=$?
  set -e

  local end_ns
  end_ns=$(date +%s%N 2>/dev/null || date +%s)
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  {
    echo "status=${status}"
    echo "elapsed_ms=${elapsed_ms}"
    echo "----- output -----"
    echo "${output}"
  } >> "${case_log}"

  if [[ ${VERBOSE} -eq 1 ]]; then
    printf '%s\n' "${output}" | tee -a "${LOG_FILE}" >/dev/null
  fi

  if [[ ${status} -ne ${expected_status} ]]; then
    log "CASE FAIL: ${name} (expected status=${expected_status} got status=${status}) [${elapsed_ms}ms]"
    return 1
  fi

  if [[ -n "${expected_text}" ]] && ! grep -Fq "${expected_text}" <<< "${output}"; then
    log "CASE FAIL: ${name} (missing expected text: ${expected_text}) [${elapsed_ms}ms]"
    return 1
  fi

  log "CASE PASS: ${name} [${elapsed_ms}ms]"
  return 0
}

# Run a test case validating JSON output (expects zero exit + valid JSON with key).
run_case_json() {
  local name="$1"
  local json_key="$2"
  shift 2
  local -a cmd=("$@")
  local case_log="${CASE_DIR}/${name}.log"
  local start_ns
  start_ns=$(date +%s%N 2>/dev/null || date +%s)

  log "CASE START: ${name}"
  {
    echo "name=${name}"
    echo "json_key=${json_key}"
    echo "command=${cmd[*]}"
    echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  } > "${case_log}"

  set +e
  local output
  output="$(SBH_OUTPUT_FORMAT=json RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
  local status=$?
  set -e

  local end_ns
  end_ns=$(date +%s%N 2>/dev/null || date +%s)
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  {
    echo "status=${status}"
    echo "elapsed_ms=${elapsed_ms}"
    echo "----- output -----"
    echo "${output}"
  } >> "${case_log}"

  if [[ ${VERBOSE} -eq 1 ]]; then
    printf '%s\n' "${output}" | tee -a "${LOG_FILE}" >/dev/null
  fi

  if [[ ${status} -ne 0 ]]; then
    log "CASE FAIL: ${name} (non-zero status=${status}) [${elapsed_ms}ms]"
    return 1
  fi

  # Validate it's valid JSON containing the key.
  if ! echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '${json_key}' in d" 2>/dev/null; then
    # Fallback: just check the key string appears in output.
    if ! grep -Fq "\"${json_key}\"" <<< "${output}"; then
      log "CASE FAIL: ${name} (JSON missing key: ${json_key}) [${elapsed_ms}ms]"
      return 1
    fi
  fi

  log "CASE PASS: ${name} [${elapsed_ms}ms]"
  return 0
}

tally_case() {
  if "$@"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    failed_names+=("${2}")
  fi
}

assert_file_contains() {
  local name="$1"
  local file="$2"
  local expected="$3"

  log "ASSERT START: ${name}"

  if [[ ! -f "${file}" ]]; then
    log "ASSERT FAIL: ${name} (missing file: ${file})"
    return 1
  fi

  if ! grep -Fq "${expected}" "${file}"; then
    log "ASSERT FAIL: ${name} (missing expected text: ${expected})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

assert_file_not_exists() {
  local name="$1"
  local file="$2"

  log "ASSERT START: ${name}"

  if [[ -f "${file}" ]]; then
    log "ASSERT FAIL: ${name} (file should not exist: ${file})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

assert_file_exists() {
  local name="$1"
  local file="$2"

  log "ASSERT START: ${name}"

  if [[ ! -f "${file}" ]]; then
    log "ASSERT FAIL: ${name} (file should exist: ${file})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

create_installer_fixture() {
  local fixture_dir="$1"
  mkdir -p "${fixture_dir}/payload" "${fixture_dir}/bin"

  cat > "${fixture_dir}/payload/sbh" <<'EOF'
#!/usr/bin/env bash
echo "sbh mock 0.0.0"
EOF
  chmod +x "${fixture_dir}/payload/sbh"

  tar -cJf "${fixture_dir}/artifact.tar.xz" -C "${fixture_dir}/payload" sbh

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${fixture_dir}/artifact.tar.xz" | awk '{print $1 "  artifact.tar.xz"}' > "${fixture_dir}/artifact.sha256"
  else
    shasum -a 256 "${fixture_dir}/artifact.tar.xz" | awk '{print $1 "  artifact.tar.xz"}' > "${fixture_dir}/artifact.sha256"
  fi
}

# Create a tree of fake build artifacts for scan/clean testing.
create_artifact_tree() {
  local root="$1"
  mkdir -p "${root}/project_a/target/debug"
  mkdir -p "${root}/project_a/target/release"
  mkdir -p "${root}/project_a/src"
  mkdir -p "${root}/project_b/node_modules/.cache"
  mkdir -p "${root}/project_c/build/intermediates"

  # Rust target artifacts (old timestamps).
  dd if=/dev/zero of="${root}/project_a/target/debug/binary" bs=1024 count=512 2>/dev/null
  dd if=/dev/zero of="${root}/project_a/target/release/binary" bs=1024 count=256 2>/dev/null
  touch -t 202501010000 "${root}/project_a/target/debug/binary"
  touch -t 202501010000 "${root}/project_a/target/release/binary"
  touch -t 202501010000 "${root}/project_a/target/debug"
  touch -t 202501010000 "${root}/project_a/target/release"
  touch -t 202501010000 "${root}/project_a/target"

  # Source files (should not be candidates).
  echo 'fn main() {}' > "${root}/project_a/src/main.rs"
  echo '[package]' > "${root}/project_a/Cargo.toml"

  # node_modules (old timestamp).
  dd if=/dev/zero of="${root}/project_b/node_modules/.cache/data" bs=1024 count=128 2>/dev/null
  touch -t 202501010000 "${root}/project_b/node_modules/.cache/data"
  touch -t 202501010000 "${root}/project_b/node_modules/.cache"
  touch -t 202501010000 "${root}/project_b/node_modules"

  # Generic build dir.
  dd if=/dev/zero of="${root}/project_c/build/intermediates/output.o" bs=1024 count=64 2>/dev/null
  touch -t 202501010000 "${root}/project_c/build/intermediates/output.o"
  touch -t 202501010000 "${root}/project_c/build/intermediates"
  touch -t 202501010000 "${root}/project_c/build"
}

write_summary_json() {
  local pass_count="$1"
  local fail_count="$2"
  local total="$3"
  local elapsed_sec="$4"
  shift 4
  local -a failures=("$@")

  local failures_json="["
  local first=true
  for f in "${failures[@]}"; do
    if [[ "${first}" == "true" ]]; then
      first=false
    else
      failures_json+=","
    fi
    failures_json+="\"${f}\""
  done
  failures_json+="]"

  cat > "${SUMMARY_JSON}" <<EOF
{
  "pass": ${pass_count},
  "fail": ${fail_count},
  "total": ${total},
  "elapsed_seconds": ${elapsed_sec},
  "failures": ${failures_json},
  "log_dir": "${LOG_DIR}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# ── main ─────────────────────────────────────────────────────────────────────

main() {
  cd "${ROOT_DIR}"
  : > "${LOG_FILE}"
  local suite_start
  suite_start=$(date +%s)

  log "sbh e2e start"
  log "root=${ROOT_DIR}"
  log "logs=${LOG_DIR}"

  log "building debug binary"
  cargo build --quiet
  local target_dir="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"
  local bin="${target_dir}/debug/sbh"
  local installer="${ROOT_DIR}/scripts/install.sh"
  local installer_fixture="${LOG_DIR}/installer-fixture"
  local installer_events="${installer_fixture}/events.jsonl"
  local artifact_root="${LOG_DIR}/artifacts"
  local config_dir="${LOG_DIR}/config-test"
  local protect_dir="${LOG_DIR}/protect-test"

  local pass=0
  local fail=0
  local -a failed_names=()

  # ── Section 1: Core CLI smoke tests ──────────────────────────────────────

  log "=== Section 1: Core CLI smoke tests ==="

  tally_case run_case help "Usage: sbh [OPTIONS] <COMMAND>" "${bin}" --help
  tally_case run_case version "0.1.0" "${bin}" --version
  tally_case run_case version_verbose "package:" "${bin}" version --verbose
  tally_case run_case completions_bash "sbh" "${bin}" completions bash
  tally_case run_case completions_zsh "_sbh" "${bin}" completions zsh

  # Subcommand help flags.
  tally_case run_case scan_help "Run a manual scan" "${bin}" scan --help
  tally_case run_case clean_help "Run a manual cleanup" "${bin}" clean --help
  tally_case run_case ballast_help "Manage ballast" "${bin}" ballast --help
  tally_case run_case config_help "View and update" "${bin}" config --help
  tally_case run_case status_help "Show current health" "${bin}" status --help
  tally_case run_case check_help "Pre-build disk" "${bin}" check --help
  tally_case run_case protect_help "Protect a path" "${bin}" protect --help
  tally_case run_case emergency_help "Emergency" "${bin}" emergency --help
  tally_case run_case blame_help "Attribute disk" "${bin}" blame --help
  tally_case run_case tune_help "tuning" "${bin}" tune --help
  tally_case run_case stats_help "Show aggregated" "${bin}" stats --help
  tally_case run_case install_help "Install sbh" "${bin}" install --help
  tally_case run_case uninstall_help "Remove sbh" "${bin}" uninstall --help
  tally_case run_case daemon_help "Run the monitoring" "${bin}" daemon --help

  # ── Section 2: Exit code validation ──────────────────────────────────────

  log "=== Section 2: Exit code validation ==="

  # No args: should print help and exit non-zero (arg_required_else_help).
  tally_case run_case_expect_fail exit_no_args 2 "Usage:" "${bin}"

  # Invalid subcommand: exit 2.
  tally_case run_case_expect_fail exit_invalid_subcommand 2 "" "${bin}" nonexistent

  # install without flags: user error exit 1.
  tally_case run_case_expect_fail exit_install_no_flags 1 "specify --systemd" "${bin}" install

  # uninstall without flags: user error exit 1.
  tally_case run_case_expect_fail exit_uninstall_no_flags 1 "specify --systemd" "${bin}" uninstall

  # ── Section 3: Configuration system ──────────────────────────────────────

  log "=== Section 3: Configuration system ==="

  mkdir -p "${config_dir}"

  # config path (no config file exists → uses default path + note).
  tally_case run_case config_path_default "defaults will be used" "${bin}" config path

  # config show (loads defaults when no file exists).
  tally_case run_case config_show_defaults "file_count" "${bin}" config show

  # config validate (defaults are valid).
  tally_case run_case config_validate_ok "Configuration is valid" "${bin}" config validate

  # config diff (no custom config → no differences).
  tally_case run_case config_diff_defaults "No differences" "${bin}" config diff

  # Write a custom TOML config and validate it.
  cat > "${config_dir}/sbh.toml" <<'TOML'
[ballast]
file_count = 5
file_size_bytes = 536870912

[pressure]
green_min_free_pct = 25.0

[scoring]
min_score = 0.8
TOML

  tally_case run_case config_validate_custom "Configuration is valid" \
    "${bin}" --config "${config_dir}/sbh.toml" config validate

  tally_case run_case config_show_custom "file_count = 5" \
    "${bin}" --config "${config_dir}/sbh.toml" config show

  # JSON output mode for config.
  tally_case run_case_json config_show_json "config" \
    "${bin}" --json config show

  tally_case run_case_json config_validate_json "valid" \
    "${bin}" --json config validate

  # Invalid config file.
  echo "this is not valid toml [[[" > "${config_dir}/bad.toml"
  tally_case run_case_expect_fail config_validate_invalid 1 "INVALID" \
    "${bin}" --config "${config_dir}/bad.toml" config validate

  # ── Section 4: Status command ────────────────────────────────────────────

  log "=== Section 4: Status command ==="

  tally_case run_case status_human "Storage Ballast Helper" "${bin}" status
  tally_case run_case_json status_json "command" "${bin}" --json status

  # ── Section 5: Version command ───────────────────────────────────────────

  log "=== Section 5: Version command ==="

  tally_case run_case version_plain "sbh 0.1.0" "${bin}" version
  tally_case run_case version_verbose_detail "target:" "${bin}" version --verbose
  tally_case run_case_json version_json "version" "${bin}" --json version

  # ── Section 6: Scan command ──────────────────────────────────────────────

  log "=== Section 6: Scan command ==="

  create_artifact_tree "${artifact_root}"

  # Scan the artifact tree.
  tally_case run_case scan_artifact_tree "Build Artifact Scan Results" \
    "${bin}" scan "${artifact_root}" --min-score 0.0

  # Scan with JSON output.
  tally_case run_case_json scan_json "candidates" \
    "${bin}" --json scan "${artifact_root}" --min-score 0.0

  # Scan empty dir — should report zero candidates.
  mkdir -p "${LOG_DIR}/empty_scan_target"
  tally_case run_case scan_empty_dir "Scanned:" \
    "${bin}" scan "${LOG_DIR}/empty_scan_target" --min-score 0.0

  # ── Section 7: Clean command (dry-run) ───────────────────────────────────

  log "=== Section 7: Clean command (dry-run) ==="

  # dry-run: should report candidates but not delete them.
  tally_case run_case clean_dry_run "Dry run complete" \
    "${bin}" clean "${artifact_root}" --dry-run --yes --min-score 0.0

  # Verify artifacts still exist after dry-run.
  tally_case assert_file_exists clean_dry_run_preserves_files \
    "${artifact_root}/project_a/target/debug/binary"

  # Clean empty dir dry-run.
  tally_case run_case clean_empty_dry_run "no cleanup candidates" \
    "${bin}" clean "${LOG_DIR}/empty_scan_target" --dry-run --yes --min-score 0.0

  # ── Section 8: Ballast lifecycle ─────────────────────────────────────────

  log "=== Section 8: Ballast lifecycle ==="

  local ballast_dir="${LOG_DIR}/ballast-pool"
  mkdir -p "${ballast_dir}"

  # Write config pointing ballast at our test dir.
  cat > "${config_dir}/ballast.toml" <<TOML
[ballast]
file_count = 3
file_size_bytes = 1048576
directory = "${ballast_dir}"

[paths]
config_file = "${config_dir}/ballast.toml"
data_dir = "${LOG_DIR}/sbh-data"
sqlite_db = "${LOG_DIR}/sbh-data/sbh.db"
jsonl_log = "${LOG_DIR}/sbh-data/events.jsonl"
state_file = "${LOG_DIR}/sbh-data/state.json"
TOML

  # Ballast provision.
  tally_case run_case ballast_provision "provision complete" \
    "${bin}" --config "${config_dir}/ballast.toml" ballast provision

  # Ballast status.
  tally_case run_case ballast_status "Ballast Pool Status" \
    "${bin}" --config "${config_dir}/ballast.toml" ballast status

  # Ballast verify.
  tally_case run_case ballast_verify "verification" \
    "${bin}" --config "${config_dir}/ballast.toml" ballast verify

  # Ballast release.
  tally_case run_case ballast_release "release complete" \
    "${bin}" --config "${config_dir}/ballast.toml" ballast release 1

  # Ballast replenish.
  tally_case run_case ballast_replenish "replenish complete" \
    "${bin}" --config "${config_dir}/ballast.toml" ballast replenish

  # Ballast JSON output.
  tally_case run_case_json ballast_status_json "command" \
    "${bin}" --json --config "${config_dir}/ballast.toml" ballast status

  # ── Section 9: Project protection markers ────────────────────────────────

  log "=== Section 9: Project protection markers ==="

  mkdir -p "${protect_dir}/important_project"

  # Protect a directory.
  tally_case run_case protect_create "Protected:" \
    "${bin}" protect "${protect_dir}/important_project"

  # Verify marker file was created.
  tally_case assert_file_exists protect_marker_created \
    "${protect_dir}/important_project/.sbh-protect"

  # List protections (should show the marker).
  tally_case run_case protect_list "marker" \
    "${bin}" protect --list

  # Unprotect.
  tally_case run_case unprotect_remove "Unprotected:" \
    "${bin}" unprotect "${protect_dir}/important_project"

  # Verify marker was removed.
  tally_case assert_file_not_exists unprotect_marker_removed \
    "${protect_dir}/important_project/.sbh-protect"

  # Unprotect non-existent marker (should still succeed).
  tally_case run_case unprotect_idempotent "No protection marker found" \
    "${bin}" unprotect "${protect_dir}/important_project"

  # Protection JSON output.
  tally_case run_case_json protect_list_json "command" \
    "${bin}" --json protect --list

  # ── Section 10: Check command ────────────────────────────────────────────

  log "=== Section 10: Check command ==="

  # Check current directory (should be OK on healthy system).
  tally_case run_case_json check_ok_json "status" \
    "${bin}" --json check /tmp

  # Check with --need (reasonable amount should pass).
  tally_case run_case_json check_need_ok "status" \
    "${bin}" --json check /tmp --need 1024

  # ── Section 11: Blame command ────────────────────────────────────────────

  log "=== Section 11: Blame command ==="

  tally_case run_case blame_human "Disk Usage by Agent" \
    "${bin}" blame --top 5

  tally_case run_case_json blame_json "command" \
    "${bin}" --json blame --top 5

  # ── Section 12: Tune command ─────────────────────────────────────────────

  log "=== Section 12: Tune command ==="

  # Tune without database (should handle gracefully).
  tally_case run_case tune_no_db "No activity database" \
    "${bin}" tune

  # ── Section 13: Stats command ────────────────────────────────────────────

  log "=== Section 13: Stats command ==="

  # Stats without database (should handle gracefully).
  tally_case run_case stats_no_db "No activity database" \
    "${bin}" stats

  tally_case run_case_json stats_no_db_json "command" \
    "${bin}" --json stats

  # ── Section 14: Emergency mode ───────────────────────────────────────────

  log "=== Section 14: Emergency mode ==="

  # Emergency scan on empty dir (should report no candidates and exit non-zero).
  tally_case run_case_expect_fail emergency_empty 1 "no cleanup candidates" \
    "${bin}" emergency "${LOG_DIR}/empty_scan_target" --yes

  # Emergency scan on artifact tree — should find candidates.
  # Note: we use a copy so we don't destroy the originals.
  local emergency_tree="${LOG_DIR}/emergency-artifacts"
  cp -r "${artifact_root}" "${emergency_tree}"

  tally_case run_case emergency_with_artifacts "EMERGENCY MODE" \
    "${bin}" emergency "${emergency_tree}" --yes --target-free 0.1

  # ── Section 15: Scoring determinism ──────────────────────────────────────

  log "=== Section 15: Scoring determinism ==="

  # Create a fresh artifact tree for determinism test.
  local det_tree="${LOG_DIR}/determinism-artifacts"
  create_artifact_tree "${det_tree}"

  # Run scan twice with JSON output and compare.
  local scan1="${CASE_DIR}/determinism_scan1.json"
  local scan2="${CASE_DIR}/determinism_scan2.json"

  set +e
  SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${det_tree}" --min-score 0.0 > "${scan1}" 2>/dev/null
  SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${det_tree}" --min-score 0.0 > "${scan2}" 2>/dev/null
  set -e

  log "CASE START: scoring_determinism"
  if diff -q "${scan1}" "${scan2}" > /dev/null 2>&1; then
    log "CASE PASS: scoring_determinism"
    pass=$((pass + 1))
  else
    log "CASE FAIL: scoring_determinism (scan outputs differ)"
    fail=$((fail + 1))
    failed_names+=("scoring_determinism")
  fi

  # ── Section 16: Scan with protection ─────────────────────────────────────

  log "=== Section 16: Scan with protection markers ==="

  local prot_tree="${LOG_DIR}/protected-scan"
  create_artifact_tree "${prot_tree}"

  # Protect one project.
  "${bin}" protect "${prot_tree}/project_a" > /dev/null 2>&1 || true
  tally_case assert_file_exists protection_marker_for_scan \
    "${prot_tree}/project_a/.sbh-protect"

  # Scan with --show-protected.
  tally_case run_case scan_shows_protected "PROTECTED" \
    "${bin}" scan "${prot_tree}" --min-score 0.0 --show-protected

  # Clean up marker for later tests.
  rm -f "${prot_tree}/project_a/.sbh-protect"

  # ── Section 17: Daemon stub ──────────────────────────────────────────────

  log "=== Section 17: Daemon and dashboard stubs ==="

  tally_case run_case daemon_stub "not yet implemented" "${bin}" daemon
  tally_case run_case dashboard_stub "not yet implemented" "${bin}" dashboard

  # ── Section 18: --no-color flag ──────────────────────────────────────────

  log "=== Section 18: Output formatting ==="

  tally_case run_case no_color_status "Storage Ballast Helper" \
    "${bin}" --no-color status

  tally_case run_case quiet_mode_version "sbh 0.1.0" \
    "${bin}" --quiet version

  # ── Section 19: Installer tests ──────────────────────────────────────────

  log "=== Section 19: Installer tests ==="

  if [[ -f "${installer}" ]]; then
    create_installer_fixture "${installer_fixture}"
    tally_case run_case installer_help "Usage:" "${installer}" --help
    tally_case run_case installer_dry_run "dry-run complete (no changes applied)" \
      "${installer}" --dry-run --dest "${installer_fixture}/bin" --no-color
    tally_case run_case installer_first_install "installed sbh to" env \
      SBH_INSTALLER_ASSET_URL="file://${installer_fixture}/artifact.tar.xz" \
      SBH_INSTALLER_CHECKSUM_URL="file://${installer_fixture}/artifact.sha256" \
      "${installer}" --dest "${installer_fixture}/bin" --version v0.0.0 --verify --no-color \
      --event-log "${installer_events}" --trace-id "trace-install-1"
    tally_case run_case installer_idempotent_rerun "already up to date" env \
      SBH_INSTALLER_ASSET_URL="file://${installer_fixture}/artifact.tar.xz" \
      SBH_INSTALLER_CHECKSUM_URL="file://${installer_fixture}/artifact.sha256" \
      "${installer}" --dest "${installer_fixture}/bin" --version v0.0.0 --verify --no-color \
      --event-log "${installer_events}" --trace-id "trace-install-2"
    tally_case assert_file_contains installer_events_trace1 "${installer_events}" '"trace_id":"trace-install-1"'
    tally_case assert_file_contains installer_events_trace2 "${installer_events}" '"trace_id":"trace-install-2"'
    tally_case assert_file_contains installer_events_download_phase "${installer_events}" '"phase":"download_artifact"'
    tally_case assert_file_contains installer_events_success "${installer_events}" '"status":"success"'
  else
    log "SKIP: installer tests (scripts/install.sh not found)"
  fi

  # ── Summary ──────────────────────────────────────────────────────────────

  local suite_end
  suite_end=$(date +%s)
  local elapsed=$((suite_end - suite_start))
  local total=$((pass + fail))

  log "summary pass=${pass} fail=${fail} total=${total} elapsed=${elapsed}s"
  log "case logs at ${CASE_DIR}"

  # Write machine-readable summary.
  write_summary_json "${pass}" "${fail}" "${total}" "${elapsed}" "${failed_names[@]}"
  log "JSON summary at ${SUMMARY_JSON}"

  # Human summary.
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  sbh e2e results: ${pass}/${total} passed (${elapsed}s)"
  if [[ ${fail} -gt 0 ]]; then
    echo "  FAILED (${fail}):"
    for name in "${failed_names[@]}"; do
      echo "    - ${name}"
    done
  fi
  echo "  Logs: ${LOG_DIR}"
  echo "  Summary: ${SUMMARY_JSON}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [[ ${fail} -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
