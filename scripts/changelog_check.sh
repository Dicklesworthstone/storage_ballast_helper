#!/usr/bin/env bash
# Assert that CHANGELOG.md carries a heading for a release tag and that the
# `[release]` marker on that heading matches whether the tag actually has
# GitHub Release assets.
#
# Usage:
#   scripts/changelog_check.sh --tag vX.Y.Z [--expect-release | --assets N] [--changelog PATH]
#   scripts/changelog_check.sh --all [--changelog PATH]
#
# --tag T            Check the heading for tag T. Without --expect-release or
#                    --assets the asset count is looked up with `gh` (a tag
#                    with no GitHub Release counts as 0 assets).
# --expect-release   The tag is being published right now (release workflow):
#                    the heading must exist and carry the marker.
# --assets N         Use N as the asset count instead of asking GitHub (tests).
# --all              Audit every tag GitHub lists as a release (needs `gh`).
#
# Exit 0 when every checked heading matches, 1 on any mismatch, 2 on usage or
# lookup errors. Lines are prefixed `changelog-check:`; failures also use the
# GitHub Actions `::error::` form so they surface in a workflow summary.
set -euo pipefail

REPOSITORY="Dicklesworthstone/storage_ballast_helper"
USER_AGENT="OpenAI File Downloader, XaiImageApiFetch/1.0"
MARKER='\*\*\[release\]\*\*'

changelog="CHANGELOG.md"
tag=""
mode="lookup"
assets=""
audit_all=0

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

fail() {
  echo "::error::changelog-check: $1" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --expect-release) mode="expect"; shift ;;
    --assets) mode="assets"; assets="${2:-}"; shift 2 ;;
    --all) audit_all=1; shift ;;
    --changelog) changelog="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "changelog-check: unknown argument: $1" >&2; usage ;;
  esac
done

if [[ ! -f "$changelog" ]]; then
  fail "no changelog at $changelog"
  exit 2
fi

# Asset count for a tag via the GitHub API; 0 when there is no release.
assets_for_tag() {
  local t="$1"
  local count
  if ! command -v gh >/dev/null 2>&1; then
    echo "changelog-check: gh is required to look up release assets for $t (or pass --assets N)" >&2
    return 2
  fi
  if count="$(gh api -H "User-Agent: ${USER_AGENT}" "repos/${REPOSITORY}/releases/tags/${t}" --jq '.assets | length' 2>/dev/null)"; then
    printf '%s' "$count"
  else
    printf '0'
  fi
}

# The heading line for a tag: `## vX.Y.Z ...` or `## [vX.Y.Z] -- date ...`.
heading_for_tag() {
  local t="$1"
  local escaped="${t//./\\.}"
  grep -E "^## \[?${escaped}\]?([^0-9A-Za-z.]|$)" "$changelog" || true
}

# Check one tag against an expected marker state. Prints one line, returns 1
# on mismatch.
check_tag() {
  local t="$1"
  local want_marker="$2"   # 1 or 0
  local why="$3"
  local heading
  heading="$(heading_for_tag "$t")"
  local lines
  lines="$(printf '%s' "$heading" | grep -c . || true)"
  if [[ "$lines" -eq 0 ]]; then
    fail "$t has no heading in $changelog ($why)"
    return 1
  fi
  if [[ "$lines" -gt 1 ]]; then
    fail "$t has $lines headings in $changelog; expected exactly one"
    return 1
  fi
  local has_marker=0
  if printf '%s' "$heading" | grep -Eq "$MARKER"; then
    has_marker=1
  fi
  if [[ "$has_marker" -ne "$want_marker" ]]; then
    if [[ "$want_marker" -eq 1 ]]; then
      fail "$t heading lacks the **[release]** marker ($why): $heading"
    else
      fail "$t heading carries **[release]** but the tag has no release assets ($why): $heading"
    fi
    return 1
  fi
  echo "changelog-check: $t ok (marker=$has_marker, $why)"
  return 0
}

status=0

if [[ "$audit_all" -eq 1 ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    fail "--all needs gh"
    exit 2
  fi
  # Every release GitHub knows about, with its asset count.
  while IFS=' ' read -r release_tag count; do
    [[ -n "$release_tag" ]] || continue
    want=0
    [[ "$count" -gt 0 ]] && want=1
    check_tag "$release_tag" "$want" "$count assets" || status=1
  done < <(gh api -H "User-Agent: ${USER_AGENT}" --paginate "repos/${REPOSITORY}/releases?per_page=100" \
            --jq '.[] | "\(.tag_name) \(.assets | length)"')
  # Headings that claim a release must correspond to a tag GitHub released with assets.
  released_with_assets="$(gh api -H "User-Agent: ${USER_AGENT}" --paginate "repos/${REPOSITORY}/releases?per_page=100" \
            --jq '.[] | select((.assets | length) > 0) | .tag_name')"
  while IFS= read -r marked; do
    [[ -n "$marked" ]] || continue
    if ! grep -qx "$marked" <<< "$released_with_assets"; then
      fail "$marked is marked **[release]** but GitHub has no release assets for it"
      status=1
    fi
  done < <(grep -E "^## .*${MARKER}" "$changelog" | sed -E 's/^## \[?(v[0-9][^] ]*)\]?.*/\1/')
  exit "$status"
fi

if [[ -z "$tag" ]]; then
  echo "changelog-check: --tag or --all is required" >&2
  usage
fi

case "$mode" in
  expect)
    check_tag "$tag" 1 "being published" || status=1
    ;;
  assets)
    if ! [[ "$assets" =~ ^[0-9]+$ ]]; then
      echo "changelog-check: --assets needs a non-negative integer" >&2
      exit 2
    fi
    want=0
    [[ "$assets" -gt 0 ]] && want=1
    check_tag "$tag" "$want" "$assets assets" || status=1
    ;;
  lookup)
    if ! count="$(assets_for_tag "$tag")"; then
      exit 2
    fi
    want=0
    [[ "$count" -gt 0 ]] && want=1
    check_tag "$tag" "$want" "$count assets" || status=1
    ;;
esac

exit "$status"
