#!/usr/bin/env bash
# test-census.sh — the test counts the docs quote, generated (bd-rc-master-ajg1.1.5)
#
# Enumerates every cargo test target with `cargo test <target> -- --list` and
# counts the tests each one defines on this host (Linux, default features:
# the shipped set with the TUI, plus the lean set for the library), adds the
# e2e shell cases `scripts/e2e_test.sh` defines, and prints a Markdown table.
# docs/testing-and-logging.md embeds that table between
# `<!-- sbh-census:begin -->` and `<!-- sbh-census:end -->`.
#
# Usage:
#   ./scripts/test-census.sh            Print the table
#   ./scripts/test-census.sh --check    Exit 1 when the embedded table differs
#   ./scripts/test-census.sh --write    Rewrite the embedded table in place
#   ./scripts/test-census.sh --local    Run cargo here instead of through rch
#   ./scripts/test-census.sh --self-test  Check the counting on fixtures (no cargo)
#
# Environment:
#   SBH_CENSUS_CARGO   cargo command for --local (default: cargo)
#   SBH_CENSUS_DOC     the document carrying the region (default: docs/testing-and-logging.md)
#
# Counts are what libtest enumerates: `#[ignore]` tests are listed and so
# counted; tests compiled out on this platform or feature set are not.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="${SBH_CENSUS_DOC:-${ROOT_DIR}/docs/testing-and-logging.md}"
BEGIN_MARKER="<!-- sbh-census:begin -->"
END_MARKER="<!-- sbh-census:end -->"
LEAN_FEATURES="cli,daemon,sqlite"

MODE="print"
USE_RCH=1
if ! command -v rch >/dev/null 2>&1; then
  USE_RCH=0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --write) MODE="write"; shift ;;
    --self-test) MODE="self-test"; shift ;;
    --local) USE_RCH=0; shift ;;
    --help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

# Lines of a `cargo test -- --list` run that name a test.
count_listed_tests() {
  grep -c ': test$' || true
}

run_cargo_list() {
  # $@ = cargo test target flags; prints the --list output.
  local cmd="cargo test $* -- --list"
  if [[ "${USE_RCH}" -eq 1 ]]; then
    rch exec "${cmd}" 2>/dev/null
  else
    (cd "${ROOT_DIR}" && ${SBH_CENSUS_CARGO:-cargo} test "$@" -- --list 2>/dev/null)
  fi
}

count_target() {
  run_cargo_list "$@" | count_listed_tests
}

e2e_case_count() {
  # Every `tally_case …` call site defines one case (the harness names each).
  grep -cE '^\s*tally_case ' "${ROOT_DIR}/scripts/e2e_test.sh" || true
}

census_table() {
  local lib_default lib_lean bin total=0
  lib_default="$(count_target --lib)"
  lib_lean="$(count_target --lib --no-default-features --features "${LEAN_FEATURES}")"
  bin="$(count_target --bin sbh)"
  total=$((lib_default + bin))

  echo "| Target | Tests |"
  echo "| --- | --- |"
  echo "| \`cargo test --lib\` (default features, with the TUI) | ${lib_default} |"
  echo "| \`cargo test --lib --no-default-features --features ${LEAN_FEATURES}\` (lean) | ${lib_lean} |"
  echo "| \`cargo test --bin sbh\` | ${bin} |"
  local integration_total=0
  for file in "${ROOT_DIR}"/tests/*.rs; do
    local name
    name="$(basename "${file}" .rs)"
    local n
    n="$(count_target --test "${name}")"
    echo "| \`cargo test --test ${name}\` | ${n} |"
    integration_total=$((integration_total + n))
  done
  total=$((total + integration_total))
  local e2e
  e2e="$(e2e_case_count)"
  echo "| Integration test files (sum of the \`--test\` rows) | ${integration_total} |"
  echo "| E2E shell cases defined in \`scripts/e2e_test.sh\` | ${e2e} |"
  echo "| **Cargo tests on Linux, default features (lib + bin + integration)** | **${total}** |"
}

extract_region() {
  awk -v b="${BEGIN_MARKER}" -v e="${END_MARKER}" '$0==b{f=1;next} $0==e{f=0} f' "${DOC}"
}

self_test() {
  local fixture
  fixture="$(printf 'a::b: test\nc: test\nignored_one: test\nsome_bench: benchmark\n\n3 tests, 1 benchmark\n')"
  local n
  n="$(printf '%s\n' "${fixture}" | count_listed_tests)"
  if [[ "${n}" != "3" ]]; then
    echo "self-test FAIL: expected 3 listed tests, got ${n}" >&2
    exit 3
  fi
  local empty
  empty="$(printf '\n0 tests\n' | count_listed_tests)"
  if [[ "${empty}" != "0" ]]; then
    echo "self-test FAIL: expected 0 for an empty list, got ${empty}" >&2
    exit 3
  fi
  local e2e
  e2e="$(e2e_case_count)"
  if [[ "${e2e}" -le 0 ]]; then
    echo "self-test FAIL: no e2e cases counted" >&2
    exit 3
  fi
  if ! grep -qF "${BEGIN_MARKER}" "${DOC}" || ! grep -qF "${END_MARKER}" "${DOC}"; then
    echo "self-test FAIL: ${DOC} lacks the census markers" >&2
    exit 3
  fi
  echo "self-test: counting ok (3 listed, 0 empty), ${e2e} e2e cases, markers present in ${DOC}"
}

case "${MODE}" in
  self-test)
    self_test
    ;;
  print)
    census_table
    ;;
  check)
    fresh="$(census_table)"
    embedded="$(extract_region)"
    if [[ "${fresh}" == "${embedded}" ]]; then
      echo "test-census: ${DOC} matches this host's census"
      exit 0
    fi
    echo "test-census: ${DOC} has drifted from the census; run ./scripts/test-census.sh --write" >&2
    diff <(printf '%s\n' "${embedded}") <(printf '%s\n' "${fresh}") >&2 || true
    exit 1
    ;;
  write)
    fresh="$(census_table)"
    tmp="${DOC}.census.tmp"
    awk -v b="${BEGIN_MARKER}" -v e="${END_MARKER}" -v table="${fresh}" '
      $0==b { print; print table; skip=1; next }
      $0==e { skip=0 }
      !skip { print }
    ' "${DOC}" > "${tmp}"
    mv -f "${tmp}" "${DOC}"
    echo "test-census: ${DOC} rewritten"
    ;;
esac
