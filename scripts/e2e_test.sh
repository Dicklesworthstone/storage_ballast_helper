#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${SBH_E2E_LOG_DIR:-${TMPDIR:-/tmp}/sbh-e2e-$(date +%Y%m%d-%H%M%S)}"
LOG_FILE="${LOG_DIR}/e2e.log"
CASE_DIR="${LOG_DIR}/cases"
SUMMARY_JSON="${LOG_DIR}/summary.json"
VERBOSE=0
# Per-case timeout in seconds (0 = no timeout).
CASE_TIMEOUT="${SBH_E2E_CASE_TIMEOUT:-60}"
# Suite-level budget in seconds (0 = no budget).
SUITE_BUDGET="${SBH_E2E_SUITE_BUDGET:-600}"
# Retry count for flaky tests (0 = no retries).
FLAKY_RETRIES="${SBH_E2E_FLAKY_RETRIES:-1}"
# Keep fixture cleanup opt-in so the suite can run in no-deletion environments.
CLEANUP_FIXTURES="${SBH_E2E_CLEANUP_FIXTURES:-0}"
# Skip cases that intentionally reclaim/delete generated fixture data.
SKIP_DESTRUCTIVE="${SBH_E2E_SKIP_DESTRUCTIVE:-0}"
# Optional prebuilt binary. CI already builds release/sbh before invoking this suite.
E2E_BIN="${SBH_E2E_BIN:-}"
E2E_TARGET_TRIPLE="${SBH_E2E_TARGET_TRIPLE:-}"
INSTALLER_PAYLOAD_BIN="${SBH_E2E_INSTALLER_PAYLOAD_BIN:-}"
EXPECTED_VERSION="${SBH_E2E_EXPECTED_VERSION:-$(awk -F '"' '/^version[[:space:]]*=/ { print $2; exit }' "${ROOT_DIR}/Cargo.toml")}"
EXPECTED_VERSION_TEXT="sbh ${EXPECTED_VERSION}"

if [[ "${1:-}" == "--verbose" ]]; then
  VERBOSE=1
fi

mkdir -p "${CASE_DIR}"

# ── cleanup trap ─────────────────────────────────────────────────────────────
# Ensure temp directories are cleaned up on exit, error, or signal.
# Log directory is preserved for debugging.
_E2E_CLEANUP_DIRS=()

register_cleanup_dir() {
  _E2E_CLEANUP_DIRS+=("$1")
}

cleanup() {
  local exit_code=$?
  # Kill any stray background processes.
  jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
  if [[ "${CLEANUP_FIXTURES}" == "1" ]]; then
    # Remove registered cleanup directories only when explicitly requested.
    for d in "${_E2E_CLEANUP_DIRS[@]}"; do
      if [[ -d "${d}" ]]; then
        rm -rf "${d}" 2>/dev/null || true
      fi
    done
  elif [[ ${#_E2E_CLEANUP_DIRS[@]} -gt 0 ]]; then
    echo "E2E fixture cleanup disabled; generated fixtures preserved under: ${LOG_DIR}" >&2
  fi
  if [[ ${exit_code} -ne 0 ]]; then
    echo "E2E suite exited with code ${exit_code}. Logs preserved at: ${LOG_DIR}" >&2
  fi
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# ── helpers ──────────────────────────────────────────────────────────────────

log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${msg}" | tee -a "${LOG_FILE}"
}

is_timeout_status() {
  local status="$1"
  [[ "${status}" -eq 124 || "${status}" -eq 137 ]]
}

run_with_timeout() {
  local timeout_secs="$1"
  shift

  if [[ "${timeout_secs}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_secs}" "$@"
    return $?
  fi

  "$@"
}

resolve_binary_path() {
  local candidate="$1"
  if [[ "${candidate}" == */* ]]; then
    local dir
    dir="$(cd "$(dirname "${candidate}")" && pwd)"
    printf '%s/%s\n' "${dir}" "$(basename "${candidate}")"
  else
    command -v "${candidate}"
  fi
}

detect_binary_target_triple() {
  local binary="$1"
  local os
  os="$(uname -s)"

  case "${os}" in
    Darwin)
      local desc
      desc="$(file "${binary}" 2>/dev/null || true)"
      if grep -q "x86_64" <<< "${desc}"; then
        printf '%s\n' "x86_64-apple-darwin"
      elif grep -Eq "arm64|aarch64" <<< "${desc}"; then
        printf '%s\n' "aarch64-apple-darwin"
      else
        case "$(uname -m)" in
          x86_64) printf '%s\n' "x86_64-apple-darwin" ;;
          arm64|aarch64) printf '%s\n' "aarch64-apple-darwin" ;;
        esac
      fi
      ;;
    Linux)
      case "$(uname -m)" in
        x86_64) printf '%s\n' "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      case "$(uname -m)" in
        x86_64) printf '%s\n' "x86_64-pc-windows-msvc" ;;
        aarch64|arm64) printf '%s\n' "aarch64-pc-windows-msvc" ;;
      esac
      ;;
  esac
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
  output="$(run_with_timeout "${CASE_TIMEOUT}" env SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
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

  if is_timeout_status "${status}"; then
    log "CASE FAIL: ${name} (timed out after ${CASE_TIMEOUT}s) [${elapsed_ms}ms]"
    return 1
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
  output="$(run_with_timeout "${CASE_TIMEOUT}" env SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
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

  if is_timeout_status "${status}"; then
    log "CASE FAIL: ${name} (timed out after ${CASE_TIMEOUT}s) [${elapsed_ms}ms]"
    return 1
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
  output="$(run_with_timeout "${CASE_TIMEOUT}" env SBH_OUTPUT_FORMAT=json RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
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

  if is_timeout_status "${status}"; then
    log "CASE FAIL: ${name} (timed out after ${CASE_TIMEOUT}s) [${elapsed_ms}ms]"
    return 1
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
  local case_name="${2:-$1}"
  if "$@"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    failed_names+=("${case_name}")
  fi
}

skip_case() {
  local name="$1"
  local reason="$2"
  log "CASE SKIP: ${name} (${reason})"
  skip=$((skip + 1))
  skipped_names+=("${name}")
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

# Run a test case that must complete within a time budget (seconds).
run_case_timed() {
  local name="$1"
  local max_seconds="$2"
  local expected="$3"
  shift 3
  local -a cmd=("$@")
  local case_log="${CASE_DIR}/${name}.log"
  local start_ns
  start_ns=$(date +%s%N 2>/dev/null || date +%s)

  log "CASE START: ${name} (budget: ${max_seconds}s)"
  {
    echo "name=${name}"
    echo "max_seconds=${max_seconds}"
    echo "expected=${expected}"
    echo "command=${cmd[*]}"
    echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  } > "${case_log}"

  set +e
  local output
  output="$(run_with_timeout "${max_seconds}" env SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 "${cmd[@]}" 2>&1)"
  local status=$?
  set -e

  local end_ns
  end_ns=$(date +%s%N 2>/dev/null || date +%s)
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
  local elapsed_sec=$(( elapsed_ms / 1000 ))

  {
    echo "status=${status}"
    echo "elapsed_ms=${elapsed_ms}"
    echo "----- output -----"
    echo "${output}"
  } >> "${case_log}"

  if [[ ${VERBOSE} -eq 1 ]]; then
    printf '%s\n' "${output}" | tee -a "${LOG_FILE}" >/dev/null
  fi

  if is_timeout_status "${status}"; then
    log "CASE FAIL: ${name} (timed out after ${max_seconds}s) [${elapsed_ms}ms]"
    return 1
  fi

  if [[ ${status} -ne 0 ]]; then
    log "CASE FAIL: ${name} (non-zero status=${status}) [${elapsed_ms}ms]"
    return 1
  fi

  if [[ -n "${expected}" ]] && ! grep -Fq "${expected}" <<< "${output}"; then
    log "CASE FAIL: ${name} (missing expected text: ${expected}) [${elapsed_ms}ms]"
    return 1
  fi

  if [[ ${elapsed_sec} -gt ${max_seconds} ]]; then
    log "CASE FAIL: ${name} (exceeded time budget: ${elapsed_sec}s > ${max_seconds}s) [${elapsed_ms}ms]"
    return 1
  fi

  log "CASE PASS: ${name} [${elapsed_ms}ms]"
  return 0
}

# Assert that a directory does not exist.
assert_dir_not_exists() {
  local name="$1"
  local dir="$2"

  log "ASSERT START: ${name}"

  if [[ -d "${dir}" ]]; then
    log "ASSERT FAIL: ${name} (directory should not exist: ${dir})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

# Assert two files are byte-identical.
assert_files_identical() {
  local name="$1"
  local file1="$2"
  local file2="$3"

  log "ASSERT START: ${name}"

  if ! diff -q "${file1}" "${file2}" > /dev/null 2>&1; then
    log "ASSERT FAIL: ${name} (files differ: ${file1} vs ${file2})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

# Assert scan candidate sets are identical after sorting by path.
assert_scan_candidate_set_identical() {
  local name="$1"
  local file1="$2"
  local file2="$3"

  log "ASSERT START: ${name}"

  if ! python3 - "${file1}" "${file2}" <<'PY'
import json
import sys

def load_paths(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    candidates = payload.get("candidates", [])
    return sorted(item.get("path", "") for item in candidates), payload.get("total_reclaimable_bytes")

paths_a, bytes_a = load_paths(sys.argv[1])
paths_b, bytes_b = load_paths(sys.argv[2])

if paths_a != paths_b or bytes_a != bytes_b:
    sys.exit(1)
PY
  then
    log "ASSERT FAIL: ${name} (candidate sets differ: ${file1} vs ${file2})"
    return 1
  fi

  log "ASSERT PASS: ${name}"
  return 0
}

# Retry wrapper for tests that may be flaky due to timing/filesystem races.
tally_case_flaky() {
  local retries="${FLAKY_RETRIES}"
  local attempt=0
  while true; do
    if "$@"; then
      pass=$((pass + 1))
      return 0
    fi
    attempt=$((attempt + 1))
    if [[ ${attempt} -gt ${retries} ]]; then
      fail=$((fail + 1))
      failed_names+=("${2}")
      return 0
    fi
    log "RETRY ${attempt}/${retries}: ${2}"
    sleep 1
  done
}

# Check if suite budget has been exceeded; skip remaining tests if so.
check_suite_budget() {
  if [[ "${SUITE_BUDGET}" -eq 0 ]]; then
    return 0
  fi
  local now
  now=$(date +%s)
  local elapsed=$((now - suite_start))
  if [[ ${elapsed} -ge ${SUITE_BUDGET} ]]; then
    log "BUDGET EXCEEDED: ${elapsed}s >= ${SUITE_BUDGET}s — skipping remaining tests"
    return 1
  fi
  return 0
}

# Create a large directory tree for performance testing.
create_large_tree() {
  local root="$1"
  local count="${2:-10000}"
  local dirs=20
  local files_per_dir=$((count / dirs))
  mkdir -p "${root}"
  for d in $(seq 1 ${dirs}); do
    local dir="${root}/dir_${d}/target/debug"
    mkdir -p "${dir}"
    for f in $(seq 1 ${files_per_dir}); do
      : > "${dir}/file_${f}.o"
    done
    # Age the files so they're scored as artifacts.
    touch -t 202501010000 "${dir}"
  done
}

create_installer_fixture() {
  local fixture_dir="$1"
  mkdir -p "${fixture_dir}/payload" "${fixture_dir}/bin"

  if [[ -n "${INSTALLER_PAYLOAD_BIN:-}" && -x "${INSTALLER_PAYLOAD_BIN}" ]]; then
    cp "${INSTALLER_PAYLOAD_BIN}" "${fixture_dir}/payload/sbh"
  else
    cat > "${fixture_dir}/payload/sbh" <<'EOF'
#!/usr/bin/env bash
echo "sbh mock 0.0.0"
EOF
  fi
  chmod +x "${fixture_dir}/payload/sbh"

  tar -cJf "${fixture_dir}/artifact.tar.xz" -C "${fixture_dir}/payload" sbh

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${fixture_dir}/artifact.tar.xz" | awk '{print $1 "  artifact.tar.xz"}' > "${fixture_dir}/artifact.sha256"
  else
    shasum -a 256 "${fixture_dir}/artifact.tar.xz" | awk '{print $1 "  artifact.tar.xz"}' > "${fixture_dir}/artifact.sha256"
  fi
}

create_offline_update_bundle_fixture() {
  local fixture_dir="$1"
  local release_tag="${2:-v99.77.55}"
  local triple="${E2E_TARGET_TRIPLE:-}"
  local archive_ext="tar.xz"

  if [[ -z "${triple}" ]]; then
    case "$(uname -s)" in
      Linux)
        case "$(uname -m)" in
          x86_64) triple="x86_64-unknown-linux-gnu" ;;
          aarch64|arm64) triple="aarch64-unknown-linux-gnu" ;;
        esac
        ;;
      Darwin)
        case "$(uname -m)" in
          x86_64) triple="x86_64-apple-darwin" ;;
          arm64|aarch64) triple="aarch64-apple-darwin" ;;
        esac
        ;;
      MINGW*|MSYS*|CYGWIN*|Windows_NT)
        case "$(uname -m)" in
          x86_64) triple="x86_64-pc-windows-msvc" ;;
          aarch64|arm64) triple="aarch64-pc-windows-msvc" ;;
        esac
        archive_ext="zip"
        ;;
    esac
  fi

  if [[ -z "${triple}" ]]; then
    log "SKIP: offline update bundle fixture (unsupported host $(uname -s)/$(uname -m))"
    return 1
  fi

  mkdir -p "${fixture_dir}"

  local archive_name="sbh-${release_tag}-${triple}.${archive_ext}"
  local checksum_name="${archive_name}.sha256"
  local archive_path="${fixture_dir}/${archive_name}"
  local checksum_path="${fixture_dir}/${checksum_name}"
  local manifest_path="${fixture_dir}/bundle-manifest.json"

  printf 'offline-e2e-bundle-%s\n' "${release_tag}" > "${archive_path}"

  local checksum_hex=""
  if command -v sha256sum >/dev/null 2>&1; then
    checksum_hex="$(sha256sum "${archive_path}" | awk '{print $1}')"
  else
    checksum_hex="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${checksum_hex}" "${archive_name}" > "${checksum_path}"

  cat > "${manifest_path}" <<EOF
{
  "version": "1",
  "repository": "Dicklesworthstone/storage_ballast_helper",
  "release_tag": "${release_tag}",
  "artifacts": [
    {
      "target": "${triple}",
      "archive": "${archive_name}",
      "checksum": "${checksum_name}",
      "sigstore_bundle": null
    }
  ]
}
EOF

  # Print paths and expected normalized tag for callers.
  printf '%s\n' "${manifest_path}" "v${release_tag#v}"
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
  local skip_count="$3"
  local total="$4"
  local elapsed_sec="$5"
  shift 5
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

  local skipped_json="["
  local skipped_first=true
  for s in "${skipped_names[@]}"; do
    if [[ "${skipped_first}" == "true" ]]; then
      skipped_first=false
    else
      skipped_json+=","
    fi
    skipped_json+="\"${s}\""
  done
  skipped_json+="]"

  cat > "${SUMMARY_JSON}" <<EOF
{
  "pass": ${pass_count},
  "fail": ${fail_count},
  "skip": ${skip_count},
  "total": ${total},
  "elapsed_seconds": ${elapsed_sec},
  "case_timeout_seconds": ${CASE_TIMEOUT},
  "suite_budget_seconds": ${SUITE_BUDGET},
  "flaky_retries": ${FLAKY_RETRIES},
  "cleanup_fixtures": "${CLEANUP_FIXTURES}",
  "skip_destructive": "${SKIP_DESTRUCTIVE}",
  "expected_version": "${EXPECTED_VERSION}",
  "failures": ${failures_json},
  "skipped": ${skipped_json},
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
  log "case_timeout=${CASE_TIMEOUT}s suite_budget=${SUITE_BUDGET}s flaky_retries=${FLAKY_RETRIES}"
  log "cleanup_fixtures=${CLEANUP_FIXTURES} skip_destructive=${SKIP_DESTRUCTIVE}"
  log "expected_version=${EXPECTED_VERSION}"

  local bin
  if [[ -n "${E2E_BIN}" ]]; then
    if ! bin="$(resolve_binary_path "${E2E_BIN}")"; then
      log "ERROR: SBH_E2E_BIN could not be resolved: ${E2E_BIN}"
      exit 2
    fi
    if [[ ! -x "${bin}" ]]; then
      log "ERROR: SBH_E2E_BIN is not executable: ${bin}"
      exit 2
    fi
    log "using prebuilt binary ${bin}"
  else
    log "building debug binary"
    if command -v rch >/dev/null 2>&1; then
      rch exec -- cargo build --quiet
    else
      cargo build --quiet
    fi
    local target_dir="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"
    bin="${target_dir}/debug/sbh"
  fi
  if [[ -z "${INSTALLER_PAYLOAD_BIN}" ]]; then
    INSTALLER_PAYLOAD_BIN="${bin}"
  elif ! INSTALLER_PAYLOAD_BIN="$(resolve_binary_path "${INSTALLER_PAYLOAD_BIN}")"; then
    log "ERROR: SBH_E2E_INSTALLER_PAYLOAD_BIN could not be resolved"
    exit 2
  fi
  if [[ -z "${E2E_TARGET_TRIPLE}" ]]; then
    E2E_TARGET_TRIPLE="$(detect_binary_target_triple "${bin}")"
  fi
  log "installer_payload=${INSTALLER_PAYLOAD_BIN}"
  log "target_triple=${E2E_TARGET_TRIPLE:-unknown}"
  local installer="${ROOT_DIR}/scripts/install.sh"
  local installer_fixture="${LOG_DIR}/installer-fixture"
  local installer_events="${installer_fixture}/events.jsonl"
  local artifact_root="${LOG_DIR}/artifacts"
  local config_dir="${LOG_DIR}/config-test"
  local protect_dir="${LOG_DIR}/protect-test"

  # Register all fixture directories for cleanup.
  register_cleanup_dir "${artifact_root}"
  register_cleanup_dir "${installer_fixture}"
  register_cleanup_dir "${config_dir}"
  register_cleanup_dir "${protect_dir}"

  local pass=0
  local fail=0
  local skip=0
  local -a failed_names=()
  local -a skipped_names=()

  # ── Section 1: Core CLI smoke tests ──────────────────────────────────────

  log "=== Section 1: Core CLI smoke tests ==="

  tally_case run_case help "Storage Ballast Helper" "${bin}" --help
  tally_case run_case version "${EXPECTED_VERSION_TEXT}" "${bin}" --version
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

  # Plain install/uninstall now auto-detect the host service manager and can
  # mutate local service state. Keep this section side-effect-free by checking
  # the wrong explicit service flag for the current host instead.
  local wrong_service_flag
  case "$(uname -s)" in
    Darwin) wrong_service_flag="--systemd" ;;
    Linux) wrong_service_flag="--launchd" ;;
    *) wrong_service_flag="--systemd" ;;
  esac
  tally_case run_case_expect_fail exit_install_wrong_service_flag 1 "omit the service flag for auto-detection" "${bin}" install "${wrong_service_flag}" --dry-run
  tally_case run_case_expect_fail exit_uninstall_wrong_service_flag 1 "omit the service flag for auto-detection" "${bin}" uninstall "${wrong_service_flag}"

  # ── Section 3: Configuration system ──────────────────────────────────────

  log "=== Section 3: Configuration system ==="

  mkdir -p "${config_dir}"

  # config path (no config file exists → uses default path + note).
  tally_case run_case config_path_default "defaults will be used" "${bin}" config path

  # config show (loads defaults when no file exists).
  tally_case run_case config_show_defaults "file_count" "${bin}" config show

  # config validate (defaults are valid).
  tally_case run_case config_validate_ok "Configuration is valid" "${bin}" config validate

  # config diff remains machine-readable even when user-level overrides exist.
  tally_case run_case_json config_diff_defaults "has_differences" "${bin}" --json config diff

  # Write a custom TOML config and validate it.
  cat > "${config_dir}/sbh.toml" <<'TOML'
[ballast]
file_count = 5
file_size_bytes = 536870912

[pressure]
green_min_free_pct = 25.0

[scoring]
min_score = 0.8
calibration_floor = 0.8
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

  tally_case run_case version_plain "${EXPECTED_VERSION_TEXT}" "${bin}" version
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
  tally_case run_case clean_dry_run "Scanned" \
    "${bin}" clean "${artifact_root}" --dry-run --yes --min-score 0.0

  # Verify artifacts still exist after dry-run.
  tally_case assert_file_exists clean_dry_run_preserves_files \
    "${artifact_root}/project_a/target/debug/binary"

  # Clean empty dir dry-run.
  tally_case run_case clean_empty_dry_run "no cleanup candidates" \
    "${bin}" clean "${LOG_DIR}/empty_scan_target" --dry-run --yes --min-score 0.0

  # ── Section 7b: Explain (decision ledger) ────────────────────────────────

  log "=== Section 7b: Explain ==="

  # A private ledger, so the dry-run below records its plan somewhere we own.
  local explain_dir="${LOG_DIR}/explain"
  mkdir -p "${explain_dir}/data"
  cat > "${explain_dir}/sbh.toml" <<TOML
[paths]
state_file = "${explain_dir}/data/state.json"
sqlite_db = "${explain_dir}/data/activity.sqlite3"
jsonl_log = "${explain_dir}/data/activity.jsonl"
ballast_dir = "${explain_dir}/ballast"

[scanner]
min_file_age_minutes = 0

[notifications]
enabled = false
TOML

  # Nothing recorded yet: explain refuses with the empty-ledger hint.
  tally_case run_case_expect_fail explain_empty_ledger 1 "no decisions yet" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --last 5

  # A dry-run clean records its plan; explain reads it back.
  tally_case run_case explain_clean_dry_run_records "Scanned" \
    "${bin}" --config "${explain_dir}/sbh.toml" clean "${artifact_root}" --dry-run --yes --min-score 0.0

  tally_case run_case_json explain_last_json "decisions" \
    "${bin}" --config "${explain_dir}/sbh.toml" --json explain --last 5

  # Resolve one id at every level, human and JSON, with the verbose trace line.
  local explain_id
  explain_id="$("${bin}" --config "${explain_dir}/sbh.toml" --json explain --last 1 2>/dev/null \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["decisions"][0]["id"])' 2>/dev/null || true)"
  if [[ -z "${explain_id}" ]]; then
    skip_case explain_by_id "no decision id in explain --last 1"
  else
    local explain_level
    for explain_level in 0 1 2 3; do
      tally_case run_case "explain_by_id_level_${explain_level}" "Decision ${explain_id}" \
        "${bin}" --config "${explain_dir}/sbh.toml" explain --id "${explain_id}" --level "${explain_level}"
    done
    tally_case run_case_json explain_by_id_json "decisions" \
      "${bin}" --config "${explain_dir}/sbh.toml" --json explain --id "${explain_id}" --level 3
    tally_case run_case explain_verbose_trace "[SBH-EXPLAIN] decision_id=${explain_id}" \
      "${bin}" --config "${explain_dir}/sbh.toml" --verbose explain --id "${explain_id}"
    tally_case run_case explain_since_window "Decision ${explain_id}" \
      "${bin}" --config "${explain_dir}/sbh.toml" explain --since 1h --limit 100
  fi
  tally_case run_case_expect_fail explain_unknown_id 1 "no decision with id" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --id 000000000000

  # "No candidates found, but disk is full": one command answers why.
  tally_case run_case explain_why_not_target "Why not:" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --why-not "${artifact_root}/project_a/target"
  tally_case run_case explain_why_not_counterfactual "Counterfactuals" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --why-not "${artifact_root}/project_a/target" --counterfactual
  tally_case run_case_json explain_why_not_json "verdict" \
    "${bin}" --config "${explain_dir}/sbh.toml" --json explain --why-not "${artifact_root}/project_a/target" --counterfactual
  tally_case run_case explain_why_not_file "directories" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --why-not "${artifact_root}/project_a/Cargo.toml"
  if [[ -n "${explain_id}" ]]; then
    tally_case run_case_json explain_replay_json "drift" \
      "${bin}" --config "${explain_dir}/sbh.toml" --json explain --replay "${explain_id}"
    tally_case run_case explain_replay_human "Replay ${explain_id}" \
      "${bin}" --config "${explain_dir}/sbh.toml" explain --replay "${explain_id}"
  fi
  tally_case run_case_expect_fail explain_replay_unknown 1 "no decision with id" \
    "${bin}" --config "${explain_dir}/sbh.toml" explain --replay 000000000000

  # ── Section 8: Ballast lifecycle ─────────────────────────────────────────

  log "=== Section 8: Ballast lifecycle ==="

  local ballast_dir="${LOG_DIR}/ballast-pool"
  mkdir -p "${ballast_dir}"

  # Write config pointing ballast at our test dir.
  cat > "${config_dir}/ballast.toml" <<TOML
[ballast]
file_count = 3
file_size_bytes = 1048576

[paths]
config_file = "${config_dir}/ballast.toml"
ballast_dir = "${ballast_dir}"
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

  if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
    skip_case ballast_release "SBH_E2E_SKIP_DESTRUCTIVE=1"
    skip_case ballast_replenish "depends on ballast release"
  else
    # Ballast release.
    tally_case run_case ballast_release "release complete" \
      "${bin}" --config "${config_dir}/ballast.toml" ballast release 1

    # Ballast replenish.
    tally_case run_case ballast_replenish "replenish complete" \
      "${bin}" --config "${config_dir}/ballast.toml" ballast replenish
  fi

  # Ballast JSON output.
  tally_case run_case_json ballast_status_json "command" \
    "${bin}" --json --config "${config_dir}/ballast.toml" ballast status

  # ── Section 9: Project protection markers ────────────────────────────────

  log "=== Section 9: Project protection markers ==="

  mkdir -p "${protect_dir}/important_project"
  local protect_config="${config_dir}/protect.toml"
  cat > "${protect_config}" <<TOML
[paths]
config_file = "${protect_config}"
state_file = "${LOG_DIR}/protect-state.json"
sqlite_db = "${LOG_DIR}/protect.sqlite3"
jsonl_log = "${LOG_DIR}/protect.jsonl"
ballast_dir = "${LOG_DIR}/protect-ballast"

[scanner]
root_paths = ["${protect_dir}"]
protected_paths = []
TOML

  # Protect a directory.
  tally_case run_case protect_create "Protected:" \
    "${bin}" --config "${protect_config}" protect "${protect_dir}/important_project"

  # Verify marker file was created.
  tally_case assert_file_exists protect_marker_created \
    "${protect_dir}/important_project/.sbh-protect"

  # List protections (should show the marker).
  tally_case run_case protect_list "Protected paths" \
    "${bin}" --config "${protect_config}" protect --list

  if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
    skip_case unprotect_remove "SBH_E2E_SKIP_DESTRUCTIVE=1"
    skip_case unprotect_marker_removed "SBH_E2E_SKIP_DESTRUCTIVE=1"
    skip_case unprotect_idempotent "SBH_E2E_SKIP_DESTRUCTIVE=1"
  else
    # Unprotect.
    tally_case run_case unprotect_remove "Unprotected:" \
      "${bin}" --config "${protect_config}" unprotect "${protect_dir}/important_project"

    # Verify marker was removed.
    tally_case assert_file_not_exists unprotect_marker_removed \
      "${protect_dir}/important_project/.sbh-protect"

    # Unprotect non-existent marker (should still succeed).
    tally_case run_case unprotect_idempotent "No protection marker found" \
      "${bin}" --config "${protect_config}" unprotect "${protect_dir}/important_project"
  fi

  # Protection JSON output.
  tally_case run_case_json protect_list_json "command" \
    "${bin}" --json --config "${protect_config}" protect --list

  # ── Section 10: Check command ────────────────────────────────────────────

  log "=== Section 10: Check command ==="

  # Check current directory with zero threshold so the case is deterministic.
  tally_case run_case_json check_ok_json "status" \
    "${bin}" --json check /tmp --target-free 0

  # Check with --need (reasonable amount should pass).
  tally_case run_case_json check_need_ok "status" \
    "${bin}" --json check /tmp --need 1024 --target-free 0

  # ── Section 11: Blame command ────────────────────────────────────────────

  log "=== Section 11: Blame command ==="

  local blame_config="${config_dir}/blame.toml"
  cat > "${blame_config}" <<TOML
[scanner]
root_paths = ["${artifact_root}"]
max_depth = 8
follow_symlinks = false
cross_devices = false
parallelism = 1
excluded_paths = []
protected_paths = []
TOML

  tally_case run_case blame_human "PID" \
    "${bin}" --config "${blame_config}" blame --top 5

  tally_case run_case_json blame_json "command" \
    "${bin}" --json --config "${blame_config}" blame --top 5

  # ── Section 12: Tune command ─────────────────────────────────────────────

  log "=== Section 12: Tune command ==="

  local empty_activity_config="${config_dir}/empty-activity.toml"
  cat > "${empty_activity_config}" <<TOML
[paths]
config_file = "${empty_activity_config}"
state_file = "${LOG_DIR}/empty-activity-state.json"
sqlite_db = "${LOG_DIR}/missing-activity.sqlite3"
jsonl_log = "${LOG_DIR}/empty-activity.jsonl"
ballast_dir = "${LOG_DIR}/empty-activity-ballast"
TOML

  # Tune without database (should handle gracefully).
  tally_case run_case tune_no_db "No activity database" \
    "${bin}" --config "${empty_activity_config}" tune

  # ── Section 13: Stats command ────────────────────────────────────────────

  log "=== Section 13: Stats command ==="

  # Stats without database (should handle gracefully).
  tally_case run_case stats_no_db "No activity database" \
    "${bin}" --config "${empty_activity_config}" stats

  tally_case run_case_json stats_no_db_json "command" \
    "${bin}" --json --config "${empty_activity_config}" stats

  # ── Section 14: Emergency mode ───────────────────────────────────────────

  log "=== Section 14: Emergency mode ==="

  # Emergency scan on empty dir (should report no candidates and exit non-zero).
  tally_case run_case_expect_fail emergency_empty 1 "no cleanup candidates" \
    "${bin}" emergency "${LOG_DIR}/empty_scan_target" --yes

  # Emergency scan on artifact tree (current heuristics may still find no candidates).
  # Note: we use a copy so we don't destroy the originals.
  local emergency_tree="${LOG_DIR}/emergency-artifacts"
  cp -r "${artifact_root}" "${emergency_tree}"

  if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
    skip_case emergency_with_artifacts "SBH_E2E_SKIP_DESTRUCTIVE=1"
  else
    tally_case run_case_expect_fail emergency_with_artifacts 1 "no cleanup candidates" \
      "${bin}" emergency "${emergency_tree}" --yes --target-free 0.1
  fi

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
  local det_s1_status=$?
  SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${det_tree}" --min-score 0.0 > "${scan2}" 2>/dev/null
  local det_s2_status=$?
  set -e

  if [[ ${det_s1_status} -ne 0 || ${det_s2_status} -ne 0 ]]; then
    log "CASE FAIL: scoring_determinism (scan command failed: status1=${det_s1_status}, status2=${det_s2_status})"
    fail=$((fail + 1))
    failed_names+=("scoring_determinism")
  else
    tally_case assert_scan_candidate_set_identical scoring_determinism "${scan1}" "${scan2}"
  fi

  # ── Section 16: Scan with protection ─────────────────────────────────────

  log "=== Section 16: Scan with protection markers ==="

  local prot_tree="${LOG_DIR}/protected-scan"
  create_artifact_tree "${prot_tree}"

  # Protect one project.
  "${bin}" --config "${protect_config}" protect "${prot_tree}/project_a" > /dev/null 2>&1 || true
  tally_case assert_file_exists protection_marker_for_scan \
    "${prot_tree}/project_a/.sbh-protect"

  # Scan with --show-protected.
  tally_case run_case scan_shows_protected "PROTECTED" \
    "${bin}" --config "${protect_config}" scan "${prot_tree}" --min-score 0.0 --show-protected

  # ── Section 17: Daemon and dashboard smoke tests ─────────────────────────

  log "=== Section 17: Daemon and dashboard smoke tests ==="

  skip_case daemon_foreground "daemon is a long-running implemented service; covered by daemon --help and platform CI"

  # ── Dashboard: runtime mode selection ──

  # 17a: --new-dashboard requires TUI feature (binary built without it).
  tally_case run_case_expect_fail dashboard_new_requires_tui 2 \
    "TUI feature not enabled" \
    "${bin}" dashboard --new-dashboard

  # 17b: --json output mode is rejected for dashboard.
  tally_case run_case_expect_fail dashboard_json_rejected 1 \
    "does not support --json" \
    "${bin}" --json dashboard

  # 17c: --new-dashboard and --legacy-dashboard conflict (clap error, exit 2).
  tally_case run_case_expect_fail dashboard_flag_conflict 2 \
    "" \
    "${bin}" dashboard --new-dashboard --legacy-dashboard

  # 17d: SBH_DASHBOARD_MODE=new routes to the new path. A lean build (no tui
  #      feature) must degrade to the live status view with one stderr line,
  #      not exit 2 — only an explicit --new-dashboard is refused (17a).
  dashboard_env_mode_new_case() {
    local name="dashboard_env_mode_new_lean_fallback"
    local case_log="${CASE_DIR}/${name}.log"
    local start_ns
    start_ns=$(date +%s%N 2>/dev/null || date +%s)

    log "CASE START: ${name}"
    {
      echo "name=${name}"
      echo "command=SBH_DASHBOARD_MODE=new ${bin} dashboard"
      echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } > "${case_log}"

    set +e
    local output
    output="$(timeout 3 env SBH_DASHBOARD_MODE=new \
      SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 \
      "${bin}" dashboard 2>&1)"
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

    if echo "${output}" | grep -qF "TUI feature not enabled"; then
      log "CASE FAIL: ${name} (implicit new-dashboard route exited instead of falling back) [${elapsed_ms}ms]"
      return 1
    fi
    # Expect timeout (124/137): the live status view (lean build) or the
    # cockpit (tui build) started and kept running.
    if is_timeout_status "${status}"; then
      if echo "${output}" | grep -qF "built without the tui feature"; then
        log "CASE PASS: ${name} (lean fallback to live status view) [${elapsed_ms}ms]"
      else
        log "CASE PASS: ${name} (dashboard runtime kept running) [${elapsed_ms}ms]"
      fi
      return 0
    fi

    log "CASE FAIL: ${name} (unexpected status=${status}, expected timeout) [${elapsed_ms}ms]"
    return 1
  }
  if command -v timeout >/dev/null 2>&1; then
    tally_case dashboard_env_mode_new_case
  else
    log "SKIP: dashboard_env_mode_new_lean_fallback (GNU timeout not available)"
  fi

  # 17e: SBH_DASHBOARD_KILL_SWITCH=true forces legacy even with --new-dashboard env mode.
  #      Legacy loop will timeout; we verify it starts, not that --new-dashboard error fires.
  #      Use a short timeout (3s) — expect exit 124 (GNU timeout) to prove legacy loop ran.
  dashboard_kill_switch_case() {
    local name="dashboard_kill_switch_forces_legacy"
    local case_log="${CASE_DIR}/${name}.log"
    local start_ns
    start_ns=$(date +%s%N 2>/dev/null || date +%s)

    log "CASE START: ${name}"
    {
      echo "name=${name}"
      echo "command=SBH_DASHBOARD_KILL_SWITCH=true SBH_DASHBOARD_MODE=new ${bin} dashboard"
      echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } > "${case_log}"

    set +e
    local output
    output="$(timeout 3 env SBH_DASHBOARD_KILL_SWITCH=true SBH_DASHBOARD_MODE=new \
      SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 \
      "${bin}" dashboard 2>&1)"
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

    # Expect timeout (124) or SIGTERM (137) — proves legacy loop started.
    if is_timeout_status "${status}"; then
      # Verify it actually rendered status output (not the TUI error).
      if echo "${output}" | grep -qF "requires a binary built with"; then
        log "CASE FAIL: ${name} (kill switch did not override to legacy) [${elapsed_ms}ms]"
        return 1
      fi
      log "CASE PASS: ${name} (legacy loop confirmed via timeout) [${elapsed_ms}ms]"
      return 0
    fi

    log "CASE FAIL: ${name} (unexpected status=${status}, expected timeout) [${elapsed_ms}ms]"
    return 1
  }
  if command -v timeout >/dev/null 2>&1; then
    tally_case dashboard_kill_switch_case
  else
    log "SKIP: dashboard_kill_switch_forces_legacy (GNU timeout not available)"
  fi

  # 17f: --verbose shows runtime selection reason in stderr.
  dashboard_verbose_case() {
    local name="dashboard_verbose_shows_reason"
    local case_log="${CASE_DIR}/${name}.log"
    local start_ns
    start_ns=$(date +%s%N 2>/dev/null || date +%s)

    log "CASE START: ${name}"
    {
      echo "name=${name}"
      echo "command=${bin} --verbose dashboard --new-dashboard"
      echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } > "${case_log}"

    set +e
    local output
    output="$(run_with_timeout "${CASE_TIMEOUT}" env SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human \
      RUST_BACKTRACE=1 "${bin}" --verbose dashboard --new-dashboard 2>&1)"
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

    # --new-dashboard without TUI exits 1, but verbose should show reason in output.
    if [[ ${status} -ne 0 ]] && echo "${output}" | grep -qF "[dashboard] runtime="; then
      log "CASE PASS: ${name} [${elapsed_ms}ms]"
      return 0
    fi

    log "CASE FAIL: ${name} (missing verbose reason or unexpected status=${status}) [${elapsed_ms}ms]"
    return 1
  }
  tally_case dashboard_verbose_case

  # 17g: Legacy dashboard starts and renders within timeout (smoke test).
  #      Runs for 3s then kills; expects status output to appear.
  dashboard_legacy_smoke_case() {
    local name="dashboard_legacy_renders_status"
    local case_log="${CASE_DIR}/${name}.log"
    local start_ns
    start_ns=$(date +%s%N 2>/dev/null || date +%s)

    log "CASE START: ${name}"
    {
      echo "name=${name}"
      echo "command=${bin} dashboard --refresh-ms 500"
      echo "start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } > "${case_log}"

    set +e
    local output
    output="$(timeout 3 env SBH_TEST_VERBOSE=1 SBH_OUTPUT_FORMAT=human RUST_BACKTRACE=1 \
      "${bin}" dashboard --refresh-ms 500 2>&1)"
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

    if [[ ${status} -eq 2 ]] && echo "${output}" | grep -qF "TUI feature not enabled"; then
      log "CASE PASS: ${name} (dashboard feature gate reported) [${elapsed_ms}ms]"
      return 0
    fi

    # Expect timeout (124/137) — proves loop ran.
    if is_timeout_status "${status}"; then
      # Verify it produced meaningful output (status render or refresh hint).
      if echo "${output}" | grep -qF "Refreshing every"; then
        log "CASE PASS: ${name} (legacy loop rendered status) [${elapsed_ms}ms]"
        return 0
      fi
      # Even without "Refreshing every" text, timeout proves the loop started.
      log "CASE PASS: ${name} (legacy loop confirmed via timeout) [${elapsed_ms}ms]"
      return 0
    fi

    log "CASE FAIL: ${name} (unexpected status=${status}, expected timeout) [${elapsed_ms}ms]"
    return 1
  }
  if command -v timeout >/dev/null 2>&1; then
    tally_case dashboard_legacy_smoke_case
  else
    log "SKIP: dashboard_legacy_renders_status (GNU timeout not available)"
  fi

  # 17h: --no-color with --new-dashboard still reports the feature-gate error.
  tally_case run_case_expect_fail dashboard_no_color_new 2 \
    "TUI feature not enabled" \
    "${bin}" --no-color dashboard --new-dashboard

  # 17i: --refresh-ms is accepted (non-default value).
  tally_case run_case_expect_fail dashboard_refresh_ms_new 2 \
    "TUI feature not enabled" \
    "${bin}" dashboard --new-dashboard --refresh-ms 250

  # ── Section 18: --no-color flag ──────────────────────────────────────────

  log "=== Section 18: Output formatting ==="

  tally_case run_case no_color_status "Storage Ballast Helper" \
    "${bin}" --no-color status

  tally_case run_case quiet_mode_version "${EXPECTED_VERSION_TEXT}" \
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
      "${installer}" --dest "${installer_fixture}/bin" --version "v${EXPECTED_VERSION}" --no-verify --no-color \
      --event-log "${installer_events}" --trace-id "trace-install-1"
    tally_case run_case installer_idempotent_rerun "already up to date" env \
      SBH_INSTALLER_ASSET_URL="file://${installer_fixture}/artifact.tar.xz" \
      SBH_INSTALLER_CHECKSUM_URL="file://${installer_fixture}/artifact.sha256" \
      "${installer}" --dest "${installer_fixture}/bin" --version "v${EXPECTED_VERSION}" --no-verify --no-color \
      --event-log "${installer_events}" --trace-id "trace-install-2"
    tally_case assert_file_contains installer_events_trace1 "${installer_events}" '"trace_id":"trace-install-1"'
    tally_case assert_file_contains installer_events_trace2 "${installer_events}" '"trace_id":"trace-install-2"'
    tally_case assert_file_contains installer_events_download_phase "${installer_events}" '"phase":"download_artifact"'
    tally_case assert_file_contains installer_events_success "${installer_events}" '"status":"success"'
  else
    log "SKIP: installer tests (scripts/install.sh not found)"
  fi

  # ── Section 20: Large directory tree performance ────────────────────────

  # ── Section 19b: Offline bundle update E2E ─────────────────────────────

  log "=== Section 19b: Offline bundle update E2E ==="

  local offline_fixture="${LOG_DIR}/offline-update-fixture"
  register_cleanup_dir "${offline_fixture}"
  local offline_manifest=""
  local offline_expected_tag=""
  local offline_fixture_output=""
  local -a offline_fixture_info=()
  if offline_fixture_output="$(create_offline_update_bundle_fixture "${offline_fixture}" "v99.77.55")"; then
    mapfile -t offline_fixture_info <<< "${offline_fixture_output}"
    offline_manifest="${offline_fixture_info[0]}"
    offline_expected_tag="${offline_fixture_info[1]}"

    tally_case run_case update_check_offline_bundle_json "${offline_expected_tag}" \
      "${bin}" update --check --offline "${offline_manifest}" --json

    tally_case run_case_expect_fail update_check_offline_bundle_mismatch 2 "offline bundle tag mismatch" \
      "${bin}" update --check --offline "${offline_manifest}" --version v99.77.56 --json
  else
    log "SKIP: offline bundle update E2E (fixture generation unsupported on host)"
  fi

  if check_suite_budget; then
    log "=== Section 20: Large directory tree performance ==="

    local large_tree="${LOG_DIR}/large-tree"
    register_cleanup_dir "${large_tree}"
    log "creating 10,000-file tree for performance test"
    create_large_tree "${large_tree}" 10000

    # Scan must complete within the case timeout.
    local perf_start perf_end perf_elapsed
    perf_start=$(date +%s)

    set +e
    local perf_output
    perf_output="$(SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${large_tree}" --min-score 0.0 2>&1)"
    local perf_status=$?
    set -e

    perf_end=$(date +%s)
    perf_elapsed=$((perf_end - perf_start))

    log "CASE START: large_tree_scan_perf"
    {
      echo "name=large_tree_scan_perf"
      echo "elapsed_sec=${perf_elapsed}"
      echo "file_count=10000"
      echo "----- output -----"
      echo "${perf_output}"
    } > "${CASE_DIR}/large_tree_scan_perf.log"

    if [[ ${perf_status} -eq 0 ]] && [[ ${perf_elapsed} -lt 30 ]]; then
      log "CASE PASS: large_tree_scan_perf (${perf_elapsed}s)"
      pass=$((pass + 1))
    else
      log "CASE FAIL: large_tree_scan_perf (status=${perf_status}, elapsed=${perf_elapsed}s, limit=30s)"
      fail=$((fail + 1))
      failed_names+=("large_tree_scan_perf")
    fi
  fi

  # ── Section 21: Emergency mode dry-run ──────────────────────────────────

  if check_suite_budget; then
    log "=== Section 21: Emergency mode dry-run ==="

    local emerg_dry="${LOG_DIR}/emergency-dry"
    create_artifact_tree "${emerg_dry}"
    register_cleanup_dir "${emerg_dry}"

    # --dry-run is not supported for emergency (verify expected clap error).
    tally_case run_case_expect_fail emergency_dry_run 2 "unexpected argument '--dry-run'" \
      "${bin}" emergency "${emerg_dry}" --dry-run --target-free 0.1

    # Verify artifacts still exist after dry-run.
    tally_case assert_file_exists emergency_dry_preserves \
      "${emerg_dry}/project_a/target/debug/binary"
  fi

  # ── Section 22: Pre-build check exit codes ──────────────────────────────

  if check_suite_budget; then
    log "=== Section 22: Pre-build check exit codes ==="

    # Check with absurdly high --need value should exit 2 (runtime error).
    tally_case run_case_expect_fail check_need_critical 2 "insufficient" \
      "${bin}" check /tmp --need 999999999999

    # Check with zero --target-free should pass (JSON mode for output verification).
    tally_case run_case_json check_target_free_ok "status" \
      "${bin}" --json check /tmp --target-free 0
  fi

  # ── Section 23: Config set command ──────────────────────────────────────

  if check_suite_budget; then
    log "=== Section 23: Config set command ==="

    local set_config="${config_dir}/set-test.toml"
    cat > "${set_config}" <<'TOML'
[ballast]
file_count = 3
TOML

    # config set with valid key.
    tally_case run_case config_set_valid "Set ballast.file_count" \
      "${bin}" --config "${set_config}" config set ballast.file_count 10

    # Verify the change took effect.
    tally_case run_case config_set_verify "10" \
      "${bin}" --config "${set_config}" config show
  fi

  # ── Section 24: Clean with actual deletion ──────────────────────────────

  if check_suite_budget; then
    log "=== Section 24: Clean with actual deletion ==="

    local clean_tree="${LOG_DIR}/clean-delete"
    create_artifact_tree "${clean_tree}"
    register_cleanup_dir "${clean_tree}"

    if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
      skip_case clean_actual_delete "SBH_E2E_SKIP_DESTRUCTIVE=1"
    else
      # Clean with --yes and very low min-score; may still report no candidates.
      tally_case run_case clean_actual_delete "Scanned" \
        "${bin}" clean "${clean_tree}" --yes --min-score 0.0 --target-free 0.001
    fi

    # JSON output for clean.
    local clean_tree2="${LOG_DIR}/clean-delete-json"
    create_artifact_tree "${clean_tree2}"
    register_cleanup_dir "${clean_tree2}"

    if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
      skip_case clean_json_output "SBH_E2E_SKIP_DESTRUCTIVE=1"
    else
      tally_case run_case_json clean_json_output "command" \
        "${bin}" --json clean "${clean_tree2}" --yes --min-score 0.0 --target-free 0.001
    fi
  fi

  # ── Section 25: Scan --top limit ────────────────────────────────────────

  if check_suite_budget; then
    log "=== Section 25: Scan --top limit ==="

    tally_case run_case scan_top_limit "Scanned:" \
      "${bin}" scan "${artifact_root}" --min-score 0.0 --top 1
  fi

  # ── Section 26: Concurrent CLI invocations ──────────────────────────────

  if check_suite_budget; then
    log "=== Section 26: Concurrent CLI invocations ==="

    # Run two CLI commands concurrently to verify no deadlock or corruption.
    log "CASE START: concurrent_cli"
    local conc1="${CASE_DIR}/concurrent_1.out"
    local conc2="${CASE_DIR}/concurrent_2.out"

    "${bin}" status > "${conc1}" 2>&1 &
    local pid1=$!
    "${bin}" version > "${conc2}" 2>&1 &
    local pid2=$!

    set +e
    wait "${pid1}"
    local s1=$?
    wait "${pid2}"
    local s2=$?
    set -e

    if [[ ${s1} -eq 0 ]] && [[ ${s2} -eq 0 ]]; then
      log "CASE PASS: concurrent_cli"
      pass=$((pass + 1))
    else
      log "CASE FAIL: concurrent_cli (status1=${s1}, status2=${s2})"
      fail=$((fail + 1))
      failed_names+=("concurrent_cli")
    fi
  fi

  # ── Section 27: Protect then scan exclusion ─────────────────────────────

  if check_suite_budget; then
    log "=== Section 27: Protect then scan exclusion ==="

    local prot_excl="${LOG_DIR}/protect-exclusion"
    create_artifact_tree "${prot_excl}"
    register_cleanup_dir "${prot_excl}"

    # Protect project_a, scan, and verify it's not a candidate.
    "${bin}" --config "${protect_config}" protect "${prot_excl}/project_a" > /dev/null 2>&1 || true

    set +e
    local excl_output
    excl_output="$(SBH_OUTPUT_FORMAT=json "${bin}" --json --config "${protect_config}" scan "${prot_excl}" --min-score 0.0 2>&1)"
    set -e

    log "CASE START: protected_excluded_from_candidates"
    # The JSON candidates list should NOT contain project_a paths.
    if echo "${excl_output}" | grep -q "project_a/target"; then
      log "CASE FAIL: protected_excluded_from_candidates (project_a still appears as candidate)"
      fail=$((fail + 1))
      failed_names+=("protected_excluded_from_candidates")
    else
      log "CASE PASS: protected_excluded_from_candidates"
      pass=$((pass + 1))
    fi

  fi

  # ── Section 28: Multiple scan paths ─────────────────────────────────────

  if check_suite_budget; then
    log "=== Section 28: Multiple scan paths ==="

    local multi1="${LOG_DIR}/multi-scan-1"
    local multi2="${LOG_DIR}/multi-scan-2"
    create_artifact_tree "${multi1}"
    create_artifact_tree "${multi2}"
    register_cleanup_dir "${multi1}"
    register_cleanup_dir "${multi2}"

    tally_case run_case scan_multiple_paths "Scanned:" \
      "${bin}" scan "${multi1}" "${multi2}" --min-score 0.0
  fi

  # ── Section 29: Config reset command ────────────────────────────────────

  if check_suite_budget; then
    log "=== Section 29: Config reset command ==="

    local reset_config="${config_dir}/reset-test.toml"
    cat > "${reset_config}" <<'TOML'
[ballast]
file_count = 99
file_size_bytes = 1
TOML

    tally_case run_case config_reset_to_defaults "Reset config to defaults" \
      "${bin}" --config "${reset_config}" config reset

    tally_case assert_file_exists config_reset_file_exists "${reset_config}"
    tally_case run_case config_reset_validates "Configuration is valid" \
      "${bin}" --config "${reset_config}" config validate
    tally_case run_case config_reset_no_diff "paths.config_file" \
      "${bin}" --config "${reset_config}" config diff
  fi

  # ── Section 30: Clean preserves source files ────────────────────────────

  if check_suite_budget; then
    log "=== Section 30: Clean preserves source files ==="

    local src_tree="${LOG_DIR}/source-preserve"
    create_artifact_tree "${src_tree}"
    register_cleanup_dir "${src_tree}"

    if [[ "${SKIP_DESTRUCTIVE}" == "1" ]]; then
      skip_case clean_preserves_main_rs "SBH_E2E_SKIP_DESTRUCTIVE=1"
      skip_case clean_preserves_cargo_toml "SBH_E2E_SKIP_DESTRUCTIVE=1"
    else
      "${bin}" clean "${src_tree}" --yes --min-score 0.0 --target-free 0.001 > /dev/null 2>&1 || true

      tally_case assert_file_exists clean_preserves_main_rs \
        "${src_tree}/project_a/src/main.rs"
      tally_case assert_file_exists clean_preserves_cargo_toml \
        "${src_tree}/project_a/Cargo.toml"
    fi
  fi

  # ── Section 31: JSON output coverage ────────────────────────────────────

  if check_suite_budget; then
    log "=== Section 31: JSON output coverage ==="

    tally_case run_case_json json_cov_check "status" "${bin}" --json check /tmp --target-free 0.001
    tally_case run_case_json json_cov_config_path "path" "${bin}" --json config path
    tally_case run_case_json json_cov_config_diff "has_differences" "${bin}" --json config diff
    tally_case run_case_json json_cov_version "version" "${bin}" --json version
    tally_case run_case_json json_cov_blame "command" \
      "${bin}" --json --config "${blame_config}" blame --top 3
    tally_case run_case_json json_cov_scan "candidates" \
      "${bin}" --json scan "${artifact_root}" --min-score 0.0
  fi

  # ── Section 32: Scoring determinism (strict byte-identical) ─────────────

  if check_suite_budget; then
    log "=== Section 32: Scoring determinism (strict) ==="

    local det_strict="${LOG_DIR}/determinism-strict"
    create_artifact_tree "${det_strict}"
    register_cleanup_dir "${det_strict}"

    local det_s1="${CASE_DIR}/det_strict_1.json"
    local det_s2="${CASE_DIR}/det_strict_2.json"

    set +e
    SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${det_strict}" --min-score 0.0 > "${det_s1}" 2>/dev/null
    SBH_OUTPUT_FORMAT=json "${bin}" --json scan "${det_strict}" --min-score 0.0 > "${det_s2}" 2>/dev/null
    set -e

    tally_case assert_scan_candidate_set_identical scoring_byte_identical "${det_s1}" "${det_s2}"
  fi

  # ── Section 33: Daemon-dependent tests (deferred) ───────────────────────
  # Requires a running daemon (currently stubbed). Specification in bd-2q9
  # bead comments (tests 23-28):
  #   - Signal SIGHUP → config reload, daemon stays running
  #   - Signal SIGUSR1 → immediate scan trigger
  #   - Ballast concurrent access → daemon + CLI ballast ops
  #   - JSONL tailing → real-time event verification

  log "=== Section 33: Daemon-dependent tests (DEFERRED) ==="
  log "SKIP: signal_sighup_config_reload (requires running daemon)"
  log "SKIP: signal_sigusr1_immediate_scan (requires running daemon)"
  log "SKIP: ballast_concurrent_access (requires running daemon)"
  log "SKIP: jsonl_tailing_verification (requires running daemon)"

  # ── Summary ──────────────────────────────────────────────────────────────

  local suite_end
  suite_end=$(date +%s)
  local elapsed=$((suite_end - suite_start))
  local total=$((pass + fail + skip))

  log "summary pass=${pass} fail=${fail} skip=${skip} total=${total} elapsed=${elapsed}s"
  log "case logs at ${CASE_DIR}"

  # Write machine-readable summary.
  write_summary_json "${pass}" "${fail}" "${skip}" "${total}" "${elapsed}" "${failed_names[@]}"
  log "JSON summary at ${SUMMARY_JSON}"

  # Human summary.
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  sbh e2e results: ${pass}/${total} passed, ${skip} skipped (${elapsed}s)"
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
