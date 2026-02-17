#!/usr/bin/env bash
# quality-gate.sh — Authoritative quality-gate runbook for sbh
#
# Runs all verification stages in dependency order, emitting structured
# pass/fail results with timing, artifacts, and failure triage guidance.
#
# Usage:
#   ./scripts/quality-gate.sh [OPTIONS]
#
# Options:
#   --local          Run cargo commands locally (skip rch exec)
#   --ci             CI mode: no rch, capture all artifacts, exit 1 on first HARD failure
#   --stage STAGE    Run only the named stage (e.g., "lint", "unit", "tui")
#   --skip STAGE     Skip the named stage (repeatable)
#   --verbose        Show full command output (default: summary only)
#   --no-color       Disable colored output
#   --help           Show this help
#
# Environment:
#   SBH_QG_LOG_DIR   Override artifact directory (default: /tmp/sbh-qg-TIMESTAMP)
#   SBH_QG_TIMEOUT   Per-stage timeout in seconds (default: 600)
#
# Exit codes:
#   0   All gates passed
#   1   One or more HARD gates failed
#   2   One or more SOFT gates failed (all HARD gates passed)
#   3   Infrastructure error (rch unavailable, build failure, etc.)
#
# Reference:
#   docs/tui-acceptance-gates-and-budgets.md (gate definitions)
#   .github/workflows/ci.yml (CI pipeline alignment)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${SBH_QG_LOG_DIR:-${TMPDIR:-/tmp}/sbh-qg-${TIMESTAMP}}"
STAGE_TIMEOUT="${SBH_QG_TIMEOUT:-600}"

# Defaults
USE_RCH=1
CI_MODE=0
VERBOSE=0
NO_COLOR=0
ONLY_STAGE=""
SKIP_STAGES=()

# ── argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)  USE_RCH=0; shift ;;
    --ci)     CI_MODE=1; USE_RCH=0; shift ;;
    --stage)  ONLY_STAGE="$2"; shift 2 ;;
    --skip)   SKIP_STAGES+=("$2"); shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    --help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

# ── color helpers ────────────────────────────────────────────────────────────

if [[ "${NO_COLOR}" -eq 1 ]] || [[ ! -t 1 ]]; then
  RED="" GRN="" YLW="" BLU="" RST="" BLD=""
else
  RED=$'\033[31m' GRN=$'\033[32m' YLW=$'\033[33m'
  BLU=$'\033[34m' RST=$'\033[0m' BLD=$'\033[1m'
fi

# ── setup ────────────────────────────────────────────────────────────────────

mkdir -p "${LOG_DIR}/stages"

TRACE_ID="qg-${TIMESTAMP}-$$"
SUMMARY_JSON="${LOG_DIR}/summary.json"
GATE_RESULTS=()   # "stage:level:status:elapsed_s"

# Check rch availability
if [[ "${USE_RCH}" -eq 1 ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "${RED}ERROR: rch not found. Use --local to skip remote compilation.${RST}" >&2
    exit 3
  fi
fi

# ── helpers ──────────────────────────────────────────────────────────────────

log() {
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1"
}

should_skip() {
  local stage="$1"
  if [[ -n "${ONLY_STAGE}" && "${ONLY_STAGE}" != "${stage}" ]]; then
    return 0
  fi
  for s in "${SKIP_STAGES[@]+"${SKIP_STAGES[@]}"}"; do
    if [[ "${s}" == "${stage}" ]]; then
      return 0
    fi
  done
  return 1
}

run_cargo() {
  # Run a cargo command, routing through rch exec when enabled.
  local logfile="$1"
  shift
  local cmd="$*"

  if [[ "${USE_RCH}" -eq 1 ]]; then
    rch exec "${cmd}" > "${logfile}" 2>&1
  else
    eval "${cmd}" > "${logfile}" 2>&1
  fi
}

# Run a gate stage. Arguments:
#   $1 = stage name (for logging/artifacts)
#   $2 = gate level (HARD|SOFT)
#   $3 = quality dimension
#   $4 = triage hint on failure
#   $5... = command to run
run_stage() {
  local stage="$1"
  local level="$2"
  local dimension="$3"
  local triage="$4"
  shift 4

  if should_skip "${stage}"; then
    if [[ "${VERBOSE}" -eq 1 ]]; then
      log "SKIP  ${stage}"
    fi
    return 0
  fi

  local logfile="${LOG_DIR}/stages/${stage}.log"
  local start_s
  start_s="$(date +%s)"

  if [[ "${VERBOSE}" -eq 1 ]]; then
    log "${BLU}START${RST} ${BLD}${stage}${RST} [${level}] — ${dimension}"
  else
    printf "  %-35s " "${stage} (${level})"
  fi

  local rc=0
  "$@" "${logfile}" || rc=$?

  local end_s
  end_s="$(date +%s)"
  local elapsed=$(( end_s - start_s ))

  if [[ ${rc} -eq 0 ]]; then
    GATE_RESULTS+=("${stage}:${level}:pass:${elapsed}")
    if [[ "${VERBOSE}" -eq 1 ]]; then
      log "${GRN}PASS${RST}  ${stage} (${elapsed}s)"
    else
      printf "${GRN}PASS${RST}  %ds\n" "${elapsed}"
    fi
  else
    GATE_RESULTS+=("${stage}:${level}:fail:${elapsed}")
    if [[ "${VERBOSE}" -eq 1 ]]; then
      log "${RED}FAIL${RST}  ${stage} (${elapsed}s, exit ${rc})"
      log "  Triage: ${triage}"
      log "  Log: ${logfile}"
    else
      printf "${RED}FAIL${RST}  %ds  exit=%d\n" "${elapsed}" "${rc}"
      echo "    Triage: ${triage}"
      echo "    Log:    ${logfile}"
    fi

    # In CI mode, abort on first HARD failure.
    if [[ "${CI_MODE}" -eq 1 && "${level}" == "HARD" ]]; then
      log "${RED}HARD gate failed in CI mode — aborting.${RST}"
      write_summary
      exit 1
    fi
  fi
}

write_summary() {
  local total=0 passed=0 hard_fail=0 soft_fail=0
  local stages_json="["
  local first=1

  for entry in "${GATE_RESULTS[@]+"${GATE_RESULTS[@]}"}"; do
    IFS=: read -r s_name s_level s_status s_elapsed <<< "${entry}"
    total=$((total + 1))

    if [[ "${s_status}" == "pass" ]]; then
      passed=$((passed + 1))
    elif [[ "${s_level}" == "HARD" ]]; then
      hard_fail=$((hard_fail + 1))
    else
      soft_fail=$((soft_fail + 1))
    fi

    if [[ ${first} -eq 1 ]]; then first=0; else stages_json+=","; fi
    stages_json+=$(printf '{"stage":"%s","level":"%s","status":"%s","elapsed_s":%s}' \
      "${s_name}" "${s_level}" "${s_status}" "${s_elapsed}")
  done
  stages_json+="]"

  local overall="pass"
  if [[ ${hard_fail} -gt 0 ]]; then
    overall="hard_fail"
  elif [[ ${soft_fail} -gt 0 ]]; then
    overall="soft_fail"
  fi

  cat > "${SUMMARY_JSON}" <<ENDJSON
{
  "trace_id": "${TRACE_ID}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "log_dir": "${LOG_DIR}",
  "overall": "${overall}",
  "total": ${total},
  "passed": ${passed},
  "hard_failures": ${hard_fail},
  "soft_failures": ${soft_fail},
  "stages": ${stages_json}
}
ENDJSON
}

# ── stage runner wrappers ────────────────────────────────────────────────────
# Each wrapper takes a logfile as $1 and runs the command, routing output there.

stage_fmt() {
  # Formatting is fast — always run locally.
  local logfile="$1"
  (cd "${ROOT_DIR}" && cargo fmt --check) > "${logfile}" 2>&1
}

stage_clippy() {
  run_cargo "$1" "cargo clippy --all-targets -- -D warnings"
}

stage_unit() {
  run_cargo "$1" "cargo test --lib -- --test-threads=4"
}

stage_bin() {
  run_cargo "$1" "cargo test --bin sbh -- --test-threads=4"
}

stage_integration() {
  run_cargo "$1" "cargo test --test integration_tests -- --test-threads=4"
}

stage_decision_plane() {
  local logfile="$1"
  run_cargo "${logfile}" "cargo test --test proof_harness -- --test-threads=4"
  run_cargo "${logfile}.dp" "cargo test --test decision_plane_e2e -- --test-threads=4"
  cat "${logfile}.dp" >> "${logfile}"
}

stage_fallback() {
  run_cargo "$1" "cargo test --test fallback_verification -- --test-threads=4"
}

stage_dashboard_integration() {
  run_cargo "$1" "cargo test --test dashboard_integration_tests -- --test-threads=4"
}

stage_tui_unit() {
  run_cargo "$1" "cargo test --lib tui:: -- --test-threads=4"
}

stage_tui_replay() {
  run_cargo "$1" "cargo test --lib tui::test_replay -- --test-threads=4"
}

stage_tui_scenarios() {
  run_cargo "$1" "cargo test --lib tui::test_scenario_drills -- --test-threads=4"
}

stage_tui_properties() {
  run_cargo "$1" "cargo test --lib tui::test_properties -- --test-threads=4"
}

stage_tui_fault_injection() {
  run_cargo "$1" "cargo test --lib tui::test_fault_injection -- --test-threads=4"
}

stage_tui_snapshots() {
  run_cargo "$1" "cargo test --lib tui::test_snapshot_golden -- --test-threads=4"
}

stage_tui_stress() {
  run_cargo "$1" "cargo test --lib tui::test_stress -- --test-threads=4"
}

stage_tui_parity() {
  run_cargo "$1" "cargo test --lib tui::parity_harness -- --test-threads=4"
}

stage_tui_benchmarks() {
  run_cargo "$1" "cargo test --lib tui::test_operator_benchmark -- --test-threads=4"
}

stage_installer() {
  run_cargo "$1" "cargo test --test installer_e2e -- --test-threads=4"
}

stage_stress() {
  run_cargo "$1" "cargo test --test stress_tests -- --test-threads=2"
}

stage_stress_harness() {
  run_cargo "$1" "cargo test --test stress_harness -- --test-threads=2"
}

stage_e2e() {
  local logfile="$1"
  (cd "${ROOT_DIR}" && SBH_E2E_LOG_DIR="${LOG_DIR}/e2e" ./scripts/e2e_test.sh) > "${logfile}" 2>&1
}

# ── main ─────────────────────────────────────────────────────────────────────

echo ""
echo "${BLD}sbh Quality Gate Runbook${RST}"
echo "trace_id: ${TRACE_ID}"
echo "log_dir:  ${LOG_DIR}"
echo "mode:     $(if [[ ${USE_RCH} -eq 1 ]]; then echo "rch (remote)"; elif [[ ${CI_MODE} -eq 1 ]]; then echo "CI (local)"; else echo "local"; fi)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Code Quality (format + lint)
# Quality dimension: Code style, correctness warnings
# Triage: Run 'cargo fmt' to fix formatting; fix clippy warnings in source
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 1: Code Quality${RST}"

run_stage "fmt" "HARD" "code-style" \
  "Run 'cargo fmt' to auto-fix formatting" \
  stage_fmt

run_stage "clippy" "HARD" "correctness-warnings" \
  "Fix clippy warnings — check stage log for specific lints" \
  stage_clippy

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Unit Tests (library + binary)
# Quality dimension: Core logic correctness
# Triage: Check failing test name → module → recent changes to that module
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 2: Unit Tests${RST}"

run_stage "unit-lib" "HARD" "core-logic" \
  "Check failing test → module → recent changes. Run with --nocapture for details" \
  stage_unit

run_stage "unit-bin" "HARD" "cli-routing" \
  "CLI argument parsing or output formatting regression" \
  stage_bin

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Integration Tests
# Quality dimension: Cross-module behavior, pipeline correctness
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 3: Integration Tests${RST}"

run_stage "integration" "HARD" "pipeline-correctness" \
  "Cross-module wiring failure — check state passing between scanner/ballast/daemon" \
  stage_integration

run_stage "decision-plane" "HARD" "policy-correctness" \
  "Decision safety invariant violated — check proof_harness for specific property" \
  stage_decision_plane

run_stage "fallback" "HARD" "fallback-safety" \
  "Fallback/rollback path broken — check mode transition logic" \
  stage_fallback

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 4: Dashboard / TUI Tests
# Quality dimension: Operator experience, dashboard correctness
# Maps to: Contract C-01..C-18, workflow acceptance gates
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 4: Dashboard / TUI Tests${RST}"

run_stage "tui-unit" "HARD" "dashboard-correctness" \
  "TUI model/update/render regression — check which screen or overlay broke" \
  stage_tui_unit

run_stage "tui-replay" "HARD" "deterministic-replay" \
  "Replay divergence — elm update loop produced different state for same inputs" \
  stage_tui_replay

run_stage "tui-scenarios" "HARD" "operator-workflows" \
  "Scenario drill failure — check which phase/screen transition broke" \
  stage_tui_scenarios

run_stage "tui-properties" "HARD" "invariant-safety" \
  "Property test failure — random input violated model invariant (check seed)" \
  stage_tui_properties

run_stage "tui-fault-injection" "HARD" "degraded-recovery" \
  "Fault injection failure — dashboard didn't degrade/recover safely" \
  stage_tui_fault_injection

run_stage "tui-snapshots" "SOFT" "visual-contract" \
  "Snapshot mismatch — intentional render change? Update golden files if so" \
  stage_tui_snapshots

run_stage "tui-parity" "HARD" "legacy-parity" \
  "Legacy parity regression — new dashboard lost behavior the old one had" \
  stage_tui_parity

run_stage "tui-benchmarks" "SOFT" "operator-efficiency" \
  "Benchmark threshold exceeded — operator workflow takes too many keystrokes" \
  stage_tui_benchmarks

run_stage "dashboard-integration" "HARD" "dashboard-e2e" \
  "Dashboard integration test failure — check feature gating and runtime mode" \
  stage_dashboard_integration

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 5: Stress & Performance
# Quality dimension: Reliability under load, resource stability
# Maps to: Performance budgets in acceptance gates doc
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 5: Stress & Performance${RST}"

run_stage "stress" "HARD" "daemon-stability" \
  "Stress test failure — check for deadlocks, channel starvation, or OOM" \
  stage_stress

run_stage "stress-harness" "SOFT" "concurrency-safety" \
  "Stress harness failure — may indicate timing sensitivity (check thread count)" \
  stage_stress_harness

run_stage "tui-stress" "SOFT" "dashboard-endurance" \
  "TUI stress failure — long-run dashboard stability or memory growth issue" \
  stage_tui_stress

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 6: E2E & Installer
# Quality dimension: End-to-end user experience, install safety
# Requires: release binary built (e2e uses it)
# ─────────────────────────────────────────────────────────────────────────────
echo "${BLD}Stage 6: E2E & Installer${RST}"

run_stage "installer" "HARD" "install-safety" \
  "Installer test failure — check install/uninstall/rollback logic" \
  stage_installer

run_stage "e2e" "HARD" "user-experience" \
  "E2E failure — check ${LOG_DIR}/e2e/ for per-case logs and summary.json" \
  stage_e2e

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

write_summary

echo "${BLD}═══ Summary ═══${RST}"

total=0; passed=0; hard_fail=0; soft_fail=0
for entry in "${GATE_RESULTS[@]+"${GATE_RESULTS[@]}"}"; do
  IFS=: read -r s_name s_level s_status s_elapsed <<< "${entry}"
  total=$((total + 1))
  if [[ "${s_status}" == "pass" ]]; then
    passed=$((passed + 1))
  elif [[ "${s_level}" == "HARD" ]]; then
    hard_fail=$((hard_fail + 1))
  else
    soft_fail=$((soft_fail + 1))
  fi
done

echo "Total: ${total}  Passed: ${GRN}${passed}${RST}  Hard fail: ${RED}${hard_fail}${RST}  Soft fail: ${YLW}${soft_fail}${RST}"
echo "Artifacts: ${LOG_DIR}"
echo "Summary:   ${SUMMARY_JSON}"

if [[ ${hard_fail} -gt 0 ]]; then
  echo ""
  echo "${RED}${BLD}BLOCKED — ${hard_fail} HARD gate(s) failed. Fix before merge/release.${RST}"
  echo ""
  echo "Failed HARD gates:"
  for entry in "${GATE_RESULTS[@]}"; do
    IFS=: read -r s_name s_level s_status s_elapsed <<< "${entry}"
    if [[ "${s_status}" == "fail" && "${s_level}" == "HARD" ]]; then
      echo "  - ${s_name}  (log: ${LOG_DIR}/stages/${s_name}.log)"
    fi
  done
  exit 1
elif [[ ${soft_fail} -gt 0 ]]; then
  echo ""
  echo "${YLW}${BLD}WARNING — ${soft_fail} SOFT gate(s) failed. Waiver required for release.${RST}"
  echo ""
  echo "Failed SOFT gates:"
  for entry in "${GATE_RESULTS[@]}"; do
    IFS=: read -r s_name s_level s_status s_elapsed <<< "${entry}"
    if [[ "${s_status}" == "fail" && "${s_level}" == "SOFT" ]]; then
      echo "  - ${s_name}  (log: ${LOG_DIR}/stages/${s_name}.log)"
    fi
  done
  exit 2
else
  echo ""
  echo "${GRN}${BLD}ALL GATES PASSED${RST}"
  exit 0
fi
