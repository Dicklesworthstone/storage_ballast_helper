#!/usr/bin/env bash
# quality-gate.sh — Authoritative quality-gate runbook for sbh
#
# Runs all verification stages in dependency order, emitting structured
# pass/fail results with timing, executed-test counts, artifacts, and
# failure triage guidance. A test stage that executes zero tests FAILS
# (status "vacuous"): a green run means tests ran, not that a filter
# selected nothing.
#
# Usage:
#   ./scripts/quality-gate.sh [OPTIONS]
#
# Options:
#   --local          Run cargo commands locally (skip rch exec)
#   --ci             CI mode: no rch, capture all artifacts, exit 1 on first HARD failure
#   --stage STAGE    Run only the named stage (e.g., "lint", "unit", "tui")
#   --skip STAGE     Skip the named stage (repeatable)
#   --print-stages   Print the stage table (what would run) and exit
#   --markdown       With --print-stages: emit a Markdown table (docs embed it)
#   --write-stages   Rewrite the stage table embedded in the docs (between
#                    <!-- sbh-qg:stages:begin --> and <!-- sbh-qg:stages:end -->)
#   --check-stages   Exit 1 when an embedded stage table differs from this script
#   --self-test      Check the executed-test accounting and the vacuous
#                    failure path against fixtures, without cargo; exit 0/3
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
#   1   One or more HARD gates failed (a vacuous test stage counts as failed)
#   2   One or more SOFT gates failed (all HARD gates passed)
#   3   Infrastructure error (rch unavailable, self-test failure, etc.)
#
# Stage kinds:
#   test   a cargo test run; must execute at least one test (else "vacuous")
#   e2e    scripts/e2e_test.sh; its "summary pass=N fail=M" line is the count
#   check  fmt/clippy: no tests by nature (allow-empty)
#
# Features: `tui` is a default feature (bd-rc-master-ajg1.4.7); the TUI
# and fallback stages still pass `--features tui` explicitly so the gate
# stays honest if the default set changes again.
#
# Reference:
#   docs/tui-acceptance-gates-and-budgets.md (gate definitions)
#   docs/quality-gate-runbook.md (embeds `--print-stages --markdown`)
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
PRINT_STAGES=0
MARKDOWN=0
SELF_TEST=0
STAGE_DOCS_MODE=""

# ── argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)  USE_RCH=0; shift ;;
    --ci)     CI_MODE=1; USE_RCH=0; shift ;;
    --stage)  ONLY_STAGE="$2"; shift 2 ;;
    --skip)   SKIP_STAGES+=("$2"); shift 2 ;;
    --print-stages) PRINT_STAGES=1; shift ;;
    --markdown) MARKDOWN=1; shift ;;
    --write-stages) STAGE_DOCS_MODE="write"; shift ;;
    --check-stages) STAGE_DOCS_MODE="check"; shift ;;
    --self-test) SELF_TEST=1; USE_RCH=0; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    --help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

# ── stage table ──────────────────────────────────────────────────────────────
# One record per stage, in execution order:
#   name|level|kind|group|dimension|command|triage
# `command` is a cargo invocation run through rch (or locally with --local /
# --ci), except the two local stages `fmt` and `e2e`. This table is the single
# source for the run, `--print-stages`, and the docs that embed the table.

STAGES=(
  "fmt|HARD|check|Code Quality|code-style|cargo fmt --check|Run 'cargo fmt' to auto-fix formatting"
  "clippy|HARD|check|Code Quality|correctness-warnings|cargo clippy --all-targets -- -D warnings|Fix clippy warnings — check stage log for specific lints"
  "docs-drift|SOFT|check|Code Quality|generated-docs|cargo run --quiet --bin sbh -- docs --check README.md AGENTS.md|A generated README/AGENTS region no longer matches the code: run 'sbh docs --render README.md AGENTS.md' and commit the result"
  "test-census|SOFT|check|Code Quality|generated-test-counts|./scripts/test-census.sh --check|The test counts in docs/testing-and-logging.md no longer match the targets: run './scripts/test-census.sh --write' and commit the result"
  "stage-docs|SOFT|check|Code Quality|generated-stage-table|./scripts/quality-gate.sh --check-stages|The stage table embedded in the docs no longer matches this script: run './scripts/quality-gate.sh --write-stages' and commit the result"
  "unit-lib|HARD|test|Unit Tests|core-logic|cargo test --lib -- --test-threads=4|Check failing test → module → recent changes. Run with --nocapture for details"
  "unit-bin|HARD|test|Unit Tests|cli-routing|cargo test --bin sbh -- --test-threads=4|CLI argument parsing or output formatting regression"
  "cli-exit-codes|HARD|test|Unit Tests|exit-code-contract|cargo test --test cli_exit_codes -- --test-threads=4|C-EXIT contract broken — a command's exit code or stream discipline changed"
  "integration|HARD|test|Integration Tests|pipeline-correctness|cargo test --test integration_tests -- --test-threads=4|Cross-module wiring failure — check state passing between scanner/ballast/daemon"
  "decision-plane|HARD|test|Integration Tests|policy-correctness|cargo test --test proof_harness -- --test-threads=4|Decision safety invariant violated — check proof_harness for specific property"
  "decision-e2e|HARD|test|Integration Tests|policy-lifecycle|cargo test --test decision_plane_e2e -- --test-threads=4|Policy lifecycle (observe→canary→enforce) regression — check decision_plane_e2e"
  "explain-ledger|HARD|test|Integration Tests|explainability|cargo test --test explain_ledger -- --test-threads=4|sbh explain no longer matches the decision ledger — check decision_log writes and the explain query"
  "fallback|HARD|test|Integration Tests|fallback-safety|cargo test --test fallback_verification --features tui -- --test-threads=4|Fallback/rollback path broken — check mode transition logic"
  "tui-unit|HARD|test|Dashboard / TUI Tests|dashboard-correctness|cargo test --lib --features tui tui:: -- --test-threads=4|TUI model/update/render regression — check which screen or overlay broke"
  "tui-replay|HARD|test|Dashboard / TUI Tests|deterministic-replay|cargo test --lib --features tui tui::test_replay -- --test-threads=4|Replay divergence — elm update loop produced different state for same inputs"
  "tui-scenarios|HARD|test|Dashboard / TUI Tests|operator-workflows|cargo test --lib --features tui tui::test_scenario_drills -- --test-threads=4|Scenario drill failure — check which phase/screen transition broke"
  "tui-properties|HARD|test|Dashboard / TUI Tests|invariant-safety|cargo test --lib --features tui tui::test_properties -- --test-threads=4|Property test failure — random input violated model invariant (check seed)"
  "tui-fault-injection|HARD|test|Dashboard / TUI Tests|degraded-recovery|cargo test --lib --features tui tui::test_fault_injection -- --test-threads=4|Fault injection failure — dashboard didn't degrade/recover safely"
  "tui-snapshots|SOFT|test|Dashboard / TUI Tests|visual-contract|cargo test --lib --features tui tui::test_snapshot_golden -- --test-threads=4|Snapshot mismatch — intentional render change? Update golden files if so"
  "tui-parity|HARD|test|Dashboard / TUI Tests|legacy-parity|cargo test --lib --features tui tui::parity_harness -- --test-threads=4|Legacy parity regression — new dashboard lost behavior the old one had"
  "tui-benchmarks|SOFT|test|Dashboard / TUI Tests|operator-efficiency|cargo test --lib --features tui tui::test_operator_benchmark -- --test-threads=4|Benchmark threshold exceeded — operator workflow takes too many keystrokes"
  "dashboard-integration|HARD|test|Dashboard / TUI Tests|dashboard-e2e|cargo test --test dashboard_integration_tests --features tui -- --test-threads=4|Dashboard integration test failure — check feature gating and runtime mode"
  "dashboard-pty|HARD|test|Dashboard / TUI Tests|dashboard-pty-session|cargo test --test dashboard_pty --features tui -- --test-threads=1|The cockpit on a pty against a sandbox daemon failed — check the stage log for the cockpit's own message (needs util-linux setsid)"
  "stress|HARD|test|Stress & Performance|daemon-stability|cargo test --test stress_tests -- --test-threads=2|Stress test failure — check for deadlocks, channel starvation, or OOM"
  "fuzz|SOFT|test|Stress & Performance|parser-robustness|cargo test --test fuzz_smoke|A harness in src/fuzzing.rs panicked: reproduce with 'cargo test --test fuzz_smoke', add the input as a seed under fuzz/corpus/<target>/ and fix the parser"
  "stress-harness|SOFT|test|Stress & Performance|concurrency-safety|cargo test --test stress_harness -- --test-threads=2|Stress harness failure — may indicate timing sensitivity (check thread count)"
  "tui-stress|SOFT|test|Stress & Performance|dashboard-endurance|cargo test --lib --features tui tui::test_stress -- --test-threads=4|TUI stress failure — long-run dashboard stability or memory growth issue"
  "daemon-e2e|SOFT|test|E2E & Installer|daemon-lifecycle|cargo test --test daemon_e2e -- --test-threads=2|Real daemon runs (start/stop, injected pressure, reclaim, events); the idle-CPU case is load-sensitive on a busy host — rerun quiet before treating as a regression"
  "installer|HARD|test|E2E & Installer|install-safety|cargo test --test installer_e2e -- --test-threads=4|Installer test failure — check install/uninstall/rollback logic"
  "e2e|HARD|e2e|E2E & Installer|user-experience|./scripts/e2e_test.sh|E2E failure — check the e2e/ artifact dir for per-case logs and summary.json"
)

stage_field() {
  # $1 = record, $2 = 1-based field index
  local record="$1" index="$2"
  awk -F'|' -v i="${index}" '{ print $i }' <<< "${record}"
}

print_stages() {
  local n=0
  if [[ "${MARKDOWN}" -eq 1 ]]; then
    echo "| # | Stage | Gate | Kind | Group | Dimension | Command |"
    echo "| --- | --- | --- | --- | --- | --- | --- |"
  else
    printf '%-3s %-22s %-4s %-5s %-24s %-24s %s\n' "#" "STAGE" "GATE" "KIND" "GROUP" "DIMENSION" "COMMAND"
  fi
  for record in "${STAGES[@]}"; do
    n=$((n + 1))
    local name level kind group dimension command
    name="$(stage_field "${record}" 1)"
    level="$(stage_field "${record}" 2)"
    kind="$(stage_field "${record}" 3)"
    group="$(stage_field "${record}" 4)"
    dimension="$(stage_field "${record}" 5)"
    command="$(stage_field "${record}" 6)"
    if [[ "${MARKDOWN}" -eq 1 ]]; then
      printf '| %d | `%s` | %s | %s | %s | %s | `%s` |\n' "${n}" "${name}" "${level}" "${kind}" "${group}" "${dimension}" "${command}"
    else
      printf '%-3d %-22s %-4s %-5s %-24s %-24s %s\n' "${n}" "${name}" "${level}" "${kind}" "${group}" "${dimension}" "${command}"
    fi
  done
  local hard=0 soft=0
  for record in "${STAGES[@]}"; do
    if [[ "$(stage_field "${record}" 2)" == "HARD" ]]; then hard=$((hard + 1)); else soft=$((soft + 1)); fi
  done
  echo ""
  if [[ "${MARKDOWN}" -eq 1 ]]; then
    echo "${n} stages: ${hard} HARD, ${soft} SOFT."
  else
    echo "${n} stages: ${hard} HARD, ${soft} SOFT"
  fi
}

if [[ "${PRINT_STAGES}" -eq 1 ]]; then
  print_stages
  exit 0
fi

# The docs that embed the Markdown stage table (between the markers).
STAGE_DOCS=(
  "${ROOT_DIR}/docs/quality-gate-runbook.md"
  "${ROOT_DIR}/docs/testing-and-logging.md"
)
STAGE_DOCS_BEGIN="<!-- sbh-qg:stages:begin -->"
STAGE_DOCS_END="<!-- sbh-qg:stages:end -->"

extract_stage_region() {
  awk -v b="${STAGE_DOCS_BEGIN}" -v e="${STAGE_DOCS_END}" '$0==b{f=1;next} $0==e{f=0} f' "$1"
}

if [[ -n "${STAGE_DOCS_MODE}" ]]; then
  table="$(MARKDOWN=1; print_stages)"
  drifted=0
  for doc in "${STAGE_DOCS[@]}"; do
    if ! grep -qF "${STAGE_DOCS_BEGIN}" "${doc}"; then
      echo "stage-docs: ${doc} has no ${STAGE_DOCS_BEGIN} marker" >&2
      exit 3
    fi
    embedded="$(extract_stage_region "${doc}")"
    if [[ "${embedded}" == "${table}" ]]; then
      echo "stage-docs: ${doc} matches the script"
      continue
    fi
    if [[ "${STAGE_DOCS_MODE}" == "check" ]]; then
      echo "stage-docs: ${doc} has drifted from the script; run ./scripts/quality-gate.sh --write-stages" >&2
      diff <(printf '%s\n' "${embedded}") <(printf '%s\n' "${table}") >&2 || true
      drifted=1
      continue
    fi
    tmp="${doc}.stages.tmp"
    awk -v b="${STAGE_DOCS_BEGIN}" -v e="${STAGE_DOCS_END}" -v table="${table}" '
      $0==b { print; print table; skip=1; next }
      $0==e { skip=0 }
      !skip { print }
    ' "${doc}" > "${tmp}"
    mv -f "${tmp}" "${doc}"
    echo "stage-docs: ${doc} rewritten"
  done
  exit "${drifted}"
fi

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
GATE_RESULTS=()   # "stage:level:status:elapsed_s:executed"

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
    (cd "${ROOT_DIR}" && eval "${cmd}") > "${logfile}" 2>&1
  fi
}

# Executed tests recorded in a stage log. Test stages: the sum of passed and
# failed over every `test result:` line (ignored tests did not execute). E2E:
# pass+fail from the suite's `summary pass=N fail=M ...` line. Check stages
# have no tests: -1 (not applicable).
count_executed() {
  local logfile="$1" kind="$2"
  case "${kind}" in
    check) echo -1 ;;
    e2e)
      awk '
        /^(\[[^]]*\] )?summary pass=/ {
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^pass=/) { split($i, p, "="); n += p[2] }
            if ($i ~ /^fail=/) { split($i, f, "="); n += f[2] }
          }
        }
        END { print n + 0 }' "${logfile}"
      ;;
    *)
      awk '
        /^test result:/ {
          for (i = 1; i <= NF; i++) {
            if ($(i+1) == "passed;" || $(i+1) == "passed") n += $i
            if ($(i+1) == "failed;" || $(i+1) == "failed") n += $i
          }
        }
        END { print n + 0 }' "${logfile}"
      ;;
  esac
}

# The two stages that never go through rch.
stage_fmt() {
  local logfile="$1"
  (cd "${ROOT_DIR}" && cargo fmt --check) > "${logfile}" 2>&1
}

stage_e2e() {
  local logfile="$1"
  (cd "${ROOT_DIR}" && SBH_E2E_LOG_DIR="${LOG_DIR}/e2e" ./scripts/e2e_test.sh) > "${logfile}" 2>&1
}

# Run one stage record: run the command, count executed tests, classify.
#   pass      exit 0 and (kind=check or executed > 0)
#   vacuous   exit 0 but a test/e2e stage executed zero tests (a failure)
#   fail      non-zero exit
run_stage() {
  local record="$1"
  local stage level kind dimension command triage
  stage="$(stage_field "${record}" 1)"
  level="$(stage_field "${record}" 2)"
  kind="$(stage_field "${record}" 3)"
  dimension="$(stage_field "${record}" 5)"
  command="$(stage_field "${record}" 6)"
  triage="$(stage_field "${record}" 7)"

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
  case "${stage}" in
    fmt) stage_fmt "${logfile}" || rc=$? ;;
    e2e) stage_e2e "${logfile}" || rc=$? ;;
    *)   run_cargo "${logfile}" "${command}" || rc=$? ;;
  esac

  local end_s
  end_s="$(date +%s)"
  local elapsed=$(( end_s - start_s ))
  local executed
  executed="$(count_executed "${logfile}" "${kind}")"

  local status="pass"
  if [[ ${rc} -ne 0 ]]; then
    status="fail"
  elif [[ "${kind}" != "check" && "${executed}" -eq 0 ]]; then
    status="vacuous"
  fi
  GATE_RESULTS+=("${stage}:${level}:${status}:${elapsed}:${executed}")

  local count_text=""
  if [[ "${executed}" -ge 0 ]]; then
    count_text="${executed} tests"
  fi

  case "${status}" in
    pass)
      if [[ "${VERBOSE}" -eq 1 ]]; then
        log "${GRN}PASS${RST}  ${stage} (${elapsed}s${count_text:+, ${count_text}})"
      else
        printf "${GRN}PASS${RST}  %ds  %s\n" "${elapsed}" "${count_text}"
      fi
      ;;
    vacuous)
      if [[ "${VERBOSE}" -eq 1 ]]; then
        log "${RED}VACUOUS${RST}  ${stage} (${elapsed}s, 0 tests executed — the filter selected nothing)"
        log "  Log: ${logfile}"
      else
        printf "${RED}VACUOUS${RST}  %ds  0 tests executed\n" "${elapsed}"
        echo "    The command ran but selected no test; a green stage must execute tests."
        echo "    Log:    ${logfile}"
      fi
      ;;
    fail)
      if [[ "${VERBOSE}" -eq 1 ]]; then
        log "${RED}FAIL${RST}  ${stage} (${elapsed}s, exit ${rc}${count_text:+, ${count_text}})"
        log "  Triage: ${triage}"
        log "  Log: ${logfile}"
      else
        printf "${RED}FAIL${RST}  %ds  exit=%d  %s\n" "${elapsed}" "${rc}" "${count_text}"
        echo "    Triage: ${triage}"
        echo "    Log:    ${logfile}"
      fi
      ;;
  esac

  # In CI mode, abort on the first HARD failure (vacuous included).
  if [[ "${status}" != "pass" && "${CI_MODE}" -eq 1 && "${level}" == "HARD" ]]; then
    log "${RED}HARD gate failed in CI mode — aborting.${RST}"
    write_summary
    exit 1
  fi
}

write_summary() {
  local total=0 passed=0 hard_fail=0 soft_fail=0 vacuous=0 executed_total=0
  local stages_json="["
  local first=1

  for entry in "${GATE_RESULTS[@]+"${GATE_RESULTS[@]}"}"; do
    IFS=: read -r s_name s_level s_status s_elapsed s_executed <<< "${entry}"
    total=$((total + 1))

    if [[ "${s_status}" == "pass" ]]; then
      passed=$((passed + 1))
    elif [[ "${s_level}" == "HARD" ]]; then
      hard_fail=$((hard_fail + 1))
    else
      soft_fail=$((soft_fail + 1))
    fi
    if [[ "${s_status}" == "vacuous" ]]; then
      vacuous=$((vacuous + 1))
    fi
    if [[ "${s_executed}" -gt 0 ]]; then
      executed_total=$((executed_total + s_executed))
    fi

    if [[ ${first} -eq 1 ]]; then first=0; else stages_json+=","; fi
    local executed_json="${s_executed}"
    if [[ "${s_executed}" -lt 0 ]]; then executed_json="null"; fi
    stages_json+=$(printf '{"stage":"%s","level":"%s","status":"%s","elapsed_s":%s,"executed_tests":%s}' \
      "${s_name}" "${s_level}" "${s_status}" "${s_elapsed}" "${executed_json}")
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
  "vacuous": ${vacuous},
  "executed_tests": ${executed_total},
  "stages": ${stages_json}
}
ENDJSON
}

# ── self-test ────────────────────────────────────────────────────────────────
# Exercises the accounting without cargo: fixture logs for the three kinds,
# then two fake stages through run_stage — one whose command "passes" while
# selecting zero tests (must be recorded as vacuous) and one that ran tests.

self_test() {
  local fixtures="${LOG_DIR}/self-test"
  mkdir -p "${fixtures}"
  local checks=0 failures=0

  check() {
    local what="$1" expected="$2" actual="$3"
    checks=$((checks + 1))
    if [[ "${expected}" == "${actual}" ]]; then
      echo "  ok    ${what}: ${actual}"
    else
      failures=$((failures + 1))
      echo "  FAIL  ${what}: expected ${expected}, got ${actual}"
    fi
  }

  printf 'running 3 tests\ntest a ... ok\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s\n' \
    > "${fixtures}/zero.log"
  printf 'test result: ok. 12 passed; 1 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.10s\ntest result: FAILED. 7 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s\n' \
    > "${fixtures}/two-runs.log"
  printf '[2026-09-03T00:00:00Z] summary pass=134 fail=1 skip=1 total=136 elapsed=43s\n' \
    > "${fixtures}/e2e.log"
  printf 'warning: nothing\n' > "${fixtures}/check.log"

  check "test kind, zero selected" 0 "$(count_executed "${fixtures}/zero.log" test)"
  check "test kind, two runs (ignored not counted)" 22 "$(count_executed "${fixtures}/two-runs.log" test)"
  check "e2e kind, summary line" 135 "$(count_executed "${fixtures}/e2e.log" e2e)"
  check "check kind, not applicable" -1 "$(count_executed "${fixtures}/check.log" check)"

  # Fake stages: `command` is a shell snippet run locally (USE_RCH=0).
  local zero_cmd="printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s\\n'"
  local real_cmd="printf 'test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n'"
  local saved_ci="${CI_MODE}"
  CI_MODE=0
  GATE_RESULTS=()
  run_stage "self-vacuous|HARD|test|Self Test|accounting|${zero_cmd}|n/a" > /dev/null
  run_stage "self-real|SOFT|test|Self Test|accounting|${real_cmd}|n/a" > /dev/null
  run_stage "self-check|HARD|check|Self Test|accounting|true|n/a" > /dev/null
  CI_MODE="${saved_ci}"

  local vacuous_entry="${GATE_RESULTS[0]}" real_entry="${GATE_RESULTS[1]}" check_entry="${GATE_RESULTS[2]}"
  check "zero-test stage is recorded vacuous" "self-vacuous:HARD:vacuous" "${vacuous_entry%:*:*}"
  check "real stage passes with its count" "self-real:SOFT:pass" "${real_entry%:*:*}"
  check "real stage executed count" 5 "${real_entry##*:}"
  check "check stage passes without tests" "self-check:HARD:pass" "${check_entry%:*:*}"

  write_summary
  check "summary counts the vacuous stage as a hard failure" 1 "$(grep -o '"hard_failures": [0-9]*' "${SUMMARY_JSON}" | grep -o '[0-9]*$')"
  check "summary counts vacuous stages" 1 "$(grep -o '"vacuous": [0-9]*' "${SUMMARY_JSON}" | grep -o '[0-9]*$')"
  check "summary sums executed tests" 5 "$(grep -o '"executed_tests": [0-9]*' "${SUMMARY_JSON}" | head -1 | grep -o '[0-9]*$')"

  echo ""
  if [[ ${failures} -eq 0 ]]; then
    echo "self-test: ${checks} checks passed"
    return 0
  fi
  echo "self-test: ${failures} of ${checks} checks FAILED"
  return 3
}

if [[ "${SELF_TEST}" -eq 1 ]]; then
  echo "${BLD}sbh Quality Gate self-test${RST} (log_dir: ${LOG_DIR})"
  self_test
  exit $?
fi

# ── main ─────────────────────────────────────────────────────────────────────

echo ""
echo "${BLD}sbh Quality Gate Runbook${RST}"
echo "trace_id: ${TRACE_ID}"
echo "log_dir:  ${LOG_DIR}"
echo "mode:     $(if [[ ${USE_RCH} -eq 1 ]]; then echo "rch (remote)"; elif [[ ${CI_MODE} -eq 1 ]]; then echo "CI (local)"; else echo "local"; fi)"
echo "stages:   ${#STAGES[@]} (a test stage that executes zero tests fails as vacuous)"
echo ""

current_group=""
for record in "${STAGES[@]}"; do
  group="$(stage_field "${record}" 4)"
  if [[ "${group}" != "${current_group}" ]]; then
    if [[ -n "${current_group}" ]]; then echo ""; fi
    echo "${BLD}${group}${RST}"
    current_group="${group}"
  fi
  run_stage "${record}"
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

write_summary

echo "${BLD}═══ Summary ═══${RST}"

total=0; passed=0; hard_fail=0; soft_fail=0; vacuous=0; executed_total=0
for entry in "${GATE_RESULTS[@]+"${GATE_RESULTS[@]}"}"; do
  IFS=: read -r s_name s_level s_status s_elapsed s_executed <<< "${entry}"
  total=$((total + 1))
  if [[ "${s_status}" == "pass" ]]; then
    passed=$((passed + 1))
  elif [[ "${s_level}" == "HARD" ]]; then
    hard_fail=$((hard_fail + 1))
  else
    soft_fail=$((soft_fail + 1))
  fi
  if [[ "${s_status}" == "vacuous" ]]; then vacuous=$((vacuous + 1)); fi
  if [[ "${s_executed}" -gt 0 ]]; then executed_total=$((executed_total + s_executed)); fi
done

echo "Total: ${total}  Passed: ${GRN}${passed}${RST}  Hard fail: ${RED}${hard_fail}${RST}  Soft fail: ${YLW}${soft_fail}${RST}  Vacuous: ${vacuous}  Tests executed: ${executed_total}"
echo "Artifacts: ${LOG_DIR}"
echo "Summary:   ${SUMMARY_JSON}"

list_failed() {
  local wanted_level="$1"
  for entry in "${GATE_RESULTS[@]+"${GATE_RESULTS[@]}"}"; do
    IFS=: read -r s_name s_level s_status s_elapsed s_executed <<< "${entry}"
    if [[ "${s_status}" != "pass" && "${s_level}" == "${wanted_level}" ]]; then
      echo "  - ${s_name}  [${s_status}]  (log: ${LOG_DIR}/stages/${s_name}.log)"
    fi
  done
}

if [[ ${hard_fail} -gt 0 ]]; then
  echo ""
  echo "${RED}${BLD}BLOCKED — ${hard_fail} HARD gate(s) failed. Fix before merge/release.${RST}"
  echo ""
  echo "Failed HARD gates:"
  list_failed HARD
  exit 1
elif [[ ${soft_fail} -gt 0 ]]; then
  echo ""
  echo "${YLW}${BLD}WARNING — ${soft_fail} SOFT gate(s) failed. Waiver required for release.${RST}"
  echo ""
  echo "Failed SOFT gates:"
  list_failed SOFT
  exit 2
else
  echo ""
  echo "${GRN}${BLD}ALL GATES PASSED${RST}"
  exit 0
fi
