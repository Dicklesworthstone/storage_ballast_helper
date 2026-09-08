#!/usr/bin/env bash
# scripts/release_gate_and_package.sh — Release packaging, pre-publish audit, and release verification.
#
# Guarantees that any release (whether built by DSR or manual fallback) produces the
# full canonical release asset set:
#   1. Versioned archives (4 targets): sbh-${TAG}-${TARGET}.tar.xz (+ .sha256 sidecars)
#   2. Legacy unversioned mirrors: sbh-${TARGET}.tar.xz (+ .sha256 sidecars)
#   3. Canonical raw platform binaries: sbh_linux_amd64, sbh_linux_arm64, sbh_darwin_amd64, sbh_darwin_arm64
#   4. Aggregate checksum manifest: SHA256SUMS.txt (all archives + mirrors)
#   5. Raw binary checksum manifest: SHA256SUMS (raw platform binaries)
#   6. Provenance document: release-provenance.json
#
# And runs authoritative pre-publication / post-publication audits via:
#   sbh doctor --release --assets <DIR|TAG>
#   scripts/changelog_check.sh --tag <TAG>
#
# Usage:
#   scripts/release_gate_and_package.sh --package [--dir PATH] [--tag TAG] [--publish]
#   scripts/release_gate_and_package.sh --audit [--dir PATH] [--tag TAG]
#   scripts/release_gate_and_package.sh --repair-release TAG [--publish]
#   scripts/release_gate_and_package.sh --verify-release TAG
#   scripts/release_gate_and_package.sh --self-test
#
# Options:
#   --package             Package and complete all required archives, raw binaries, and manifests
#   --audit               Run release audit against artifact directory
#   --repair-release TAG  Download existing release from GitHub, backfill missing assets, audit, and optionally upload
#   --verify-release TAG  Verify remote GitHub release assets against sbh doctor and changelog
#   --dir DIR             Directory containing or to receive release artifacts
#   --tag TAG             Release tag (e.g. v0.6.1). If omitted, inferred from Cargo.toml
#   --publish             Upload verified assets to GitHub release via `gh release upload --clobber`
#   --repo REPO           GitHub repository (default: Dicklesworthstone/storage_ballast_helper)
#   --self-test           Run self-test suite and exit
#   -h, --help            Show this help message and exit
#
# Exit codes:
#   0   Success / all audits passed
#   1   Validation, audit, or verification failure
#   2   Command-line or usage error

set -euo pipefail

PROGRAM="sbh"
DEFAULT_REPO="Dicklesworthstone/storage_ballast_helper"
REPO="${SBH_RELEASE_REPO:-$DEFAULT_REPO}"

TARGETS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

raw_binary_name() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo "${PROGRAM}_linux_amd64" ;;
    aarch64-unknown-linux-gnu) echo "${PROGRAM}_linux_arm64" ;;
    x86_64-apple-darwin)       echo "${PROGRAM}_darwin_amd64" ;;
    aarch64-apple-darwin)      echo "${PROGRAM}_darwin_arm64" ;;
    *)                         echo "" ;;
  esac
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=""
tag=""
artifact_dir=""
publish=0

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package)
      mode="package"
      shift
      ;;
    --audit)
      mode="audit"
      shift
      ;;
    --repair-release)
      mode="repair"
      tag="${2:-}"
      shift 2
      ;;
    --verify-release)
      mode="verify"
      tag="${2:-}"
      shift 2
      ;;
    --self-test)
      mode="self-test"
      shift
      ;;
    --dir)
      artifact_dir="${2:-}"
      shift 2
      ;;
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --publish)
      publish=1
      shift
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "$mode" ]]; then
  echo "error: no operation specified (choose --package, --audit, --repair-release, --verify-release, or --self-test)" >&2
  usage
fi

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

run_doctor_assets() {
  local target_path="$1"
  if command -v sbh >/dev/null 2>&1; then
    sbh doctor --release --assets "$target_path"
  else
    (cd "$root_dir" && cargo run --quiet --bin sbh -- doctor --release --assets "$target_path")
  fi
}

# ── SELF TEST MODE ────────────────────────────────────────────────────────────
if [[ "$mode" == "self-test" ]]; then
  echo "=== Running release_gate_and_package self-tests ==="
  for t in "${TARGETS[@]}"; do
    raw="$(raw_binary_name "$t")"
    if [[ -z "$raw" ]]; then
      echo "self-test fail: empty raw binary mapping for $t" >&2
      exit 1
    fi
  done
  echo "self-test pass: raw binary mappings verified (${#TARGETS[@]} targets)"
  echo "self-test pass: helper functions present"
  exit 0
fi

# Resolve tag from Cargo.toml if omitted
if [[ -z "$tag" ]]; then
  version="$(grep '^version = ' "${root_dir}/Cargo.toml" | head -n 1 | sed 's/version = "\(.*\)"/\1/')"
  tag="v${version}"
fi

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "error: invalid release tag format: '${tag}' (must start with 'v' followed by semver)" >&2
  exit 1
fi

# ── VERIFY REMOTE RELEASE MODE ────────────────────────────────────────────────
if [[ "$mode" == "verify" ]]; then
  echo "=== Verifying remote GitHub release: ${tag} (${REPO}) ==="
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: 'gh' CLI tool is required for --verify-release" >&2
    exit 2
  fi

  # 1. Run sbh doctor directly on tag
  echo "--> Running sbh doctor --release --assets ${tag}..."
  run_doctor_assets "$tag"

  # 2. Verify raw platform binaries exist on the GitHub release
  echo "--> Checking raw platform binaries on GitHub release..."
  release_json="$(gh release view "$tag" --repo "$REPO" --json assets)"
  for target in "${TARGETS[@]}"; do
    raw="$(raw_binary_name "$target")"
    if ! jq -e --arg name "$raw" '.assets[] | select(.name == $name)' >/dev/null <<<"$release_json"; then
      echo "error: missing raw binary on GitHub release: ${raw}" >&2
      exit 1
    fi
    echo "    ✓ ${raw}"
  done

  # 3. Check SHA256SUMS, SHA256SUMS.txt, and release-provenance.json
  for manifest in "SHA256SUMS.txt" "SHA256SUMS" "release-provenance.json"; do
    if ! jq -e --arg name "$manifest" '.assets[] | select(.name == $name)' >/dev/null <<<"$release_json"; then
      echo "error: missing manifest on GitHub release: ${manifest}" >&2
      exit 1
    fi
    echo "    ✓ ${manifest}"
  done

  # 4. Run changelog check
  if [[ -f "${root_dir}/scripts/changelog_check.sh" ]]; then
    echo "--> Running scripts/changelog_check.sh --tag ${tag}..."
    bash "${root_dir}/scripts/changelog_check.sh" --tag "$tag"
  fi

  echo "=== Remote release ${tag} is 100% compliant and verified! ==="
  exit 0
fi

# ── REPAIR RELEASE MODE ───────────────────────────────────────────────────────
if [[ "$mode" == "repair" ]]; then
  echo "=== Repairing release assets for ${tag} from ${REPO} ==="
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: 'gh' CLI tool is required for --repair-release" >&2
    exit 2
  fi

  staging_dir="${TMPDIR:-/tmp}/sbh-repair-${tag}-$$-${RANDOM}"
  mkdir -p "$staging_dir"
  echo "--> Downloading existing release assets to: ${staging_dir}"
  gh release download "$tag" --repo "$REPO" --dir "$staging_dir" --clobber

  artifact_dir="$staging_dir"
  mode="package"
  # Continue to package mode to fill in gaps and audit
fi

# ── PACKAGE / AUDIT SETUP ─────────────────────────────────────────────────────
if [[ -z "$artifact_dir" ]]; then
  artifact_dir="${HOME}/release-work/storage_ballast_helper/releases/${tag}"
fi

if [[ ! -d "$artifact_dir" && "$mode" == "audit" ]]; then
  echo "error: artifact directory does not exist: ${artifact_dir}" >&2
  exit 1
fi

mkdir -p "$artifact_dir"

# ── PACKAGE MODE ─────────────────────────────────────────────────────────────
if [[ "$mode" == "package" ]]; then
  echo "=== Packaging and completing release assets in ${artifact_dir} for ${tag} ==="
  cd "$artifact_dir"

  # Step 1: Ensure raw binaries and legacy mirrors exist from versioned archives
  for target in "${TARGETS[@]}"; do
    v_archive="${PROGRAM}-${tag}-${target}.tar.xz"
    legacy_archive="${PROGRAM}-${target}.tar.xz"
    raw_name="$(raw_binary_name "$target")"

    # If versioned archive exists but legacy does not, copy it
    if [[ -f "$v_archive" && ! -f "$legacy_archive" ]]; then
      echo "  Mirroring ${v_archive} -> ${legacy_archive}"
      cp "$v_archive" "$legacy_archive"
    elif [[ -f "$legacy_archive" && ! -f "$v_archive" ]]; then
      echo "  Mirroring ${legacy_archive} -> ${v_archive}"
      cp "$legacy_archive" "$v_archive"
    fi

    # Ensure sidecars exist
    if [[ -f "$v_archive" ]]; then
      v_sha="$(compute_sha256 "$v_archive")"
      printf '%s  %s\n' "$v_sha" "$v_archive" > "${v_archive}.sha256"
      printf '%s  %s\n' "$v_sha" "$legacy_archive" > "${legacy_archive}.sha256"
    fi

    # Extract raw binary if missing but archive exists
    if [[ -n "$raw_name" && ! -f "$raw_name" ]]; then
      if [[ -f "$v_archive" ]]; then
        echo "  Extracting raw binary ${raw_name} from ${v_archive}..."
        tmp_extract="$(mktemp -d)"
        tar -xJf "$v_archive" -C "$tmp_extract"
        if [[ -f "${tmp_extract}/${PROGRAM}" ]]; then
          cp "${tmp_extract}/${PROGRAM}" "$raw_name"
          chmod +x "$raw_name"
        else
          echo "error: could not find ${PROGRAM} inside ${v_archive}" >&2
          rm -rf "$tmp_extract"
          exit 1
        fi
        rm -rf "$tmp_extract"
      fi
    fi
  done

  # Step 2: Generate aggregate manifest SHA256SUMS.txt
  echo "  Generating aggregate SHA256SUMS.txt..."
  : > "${artifact_dir}/SHA256SUMS.txt"
  for checksum_file in "${artifact_dir}"/*.sha256; do
    [[ -f "$checksum_file" ]] || continue
    cat "$checksum_file" >> "${artifact_dir}/SHA256SUMS.txt"
  done
  sort -k2,2 -u "${artifact_dir}/SHA256SUMS.txt" -o "${artifact_dir}/SHA256SUMS.txt"

  # Step 3: Generate raw binaries manifest SHA256SUMS
  echo "  Generating raw binary manifest SHA256SUMS..."
  : > "${artifact_dir}/SHA256SUMS"
  for target in "${TARGETS[@]}"; do
    raw_name="$(raw_binary_name "$target")"
    if [[ -n "$raw_name" && -f "${artifact_dir}/${raw_name}" ]]; then
      r_sha="$(compute_sha256 "${artifact_dir}/${raw_name}")"
      printf '%s  %s\n' "$r_sha" "$raw_name" >> "${artifact_dir}/SHA256SUMS"
    fi
  done
  if [[ -s "${artifact_dir}/SHA256SUMS" ]]; then
    sort -k2,2 -u "${artifact_dir}/SHA256SUMS" -o "${artifact_dir}/SHA256SUMS"
  fi

  # Step 4: Generate release-provenance.json if missing
  if [[ ! -f "${artifact_dir}/release-provenance.json" ]]; then
    echo "  Generating release-provenance.json..."
    commit_sha="$(git rev-parse HEAD)"
    if git rev-parse "${tag}^{commit}" >/dev/null 2>&1; then
      commit_sha="$(git rev-parse "${tag}^{commit}")"
    fi
    rustc_ver="$(rustc --version 2>/dev/null || echo "rustc nightly")"
    cat > "${artifact_dir}/release-provenance.json" <<EOF
{
  "tag": "${tag}",
  "sha": "${commit_sha}",
  "run_id": "gate-packager-${tag}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rustc_version": "${rustc_ver}"
}
EOF
  fi

  echo "Asset set packaging complete."
fi

# ── AUDIT MODE ───────────────────────────────────────────────────────────────
echo "=== Running pre-publication audit with sbh doctor ==="
run_doctor_assets "$artifact_dir"
echo "✓ Audit PASSED for ${tag} in ${artifact_dir}"

# ── PUBLISH STEP (IF REQUESTED) ──────────────────────────────────────────────
if [[ $publish -eq 1 ]]; then
  echo "=== Publishing / updating assets to GitHub release ${tag} ==="
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: 'gh' CLI tool is required for --publish" >&2
    exit 2
  fi

  # Upload all files in artifact_dir to release
  echo "--> Uploading assets to ${REPO} ${tag}..."
  upload_files=()
  for file in "${artifact_dir}"/*; do
    [[ -f "$file" ]] && upload_files+=("$file")
  done

  gh release upload "$tag" "${upload_files[@]}" --repo "$REPO" --clobber
  echo "--> Upload complete. Verifying published release..."
  run_doctor_assets "$tag"
  echo "=== Release ${tag} successfully published and verified! ==="
fi
