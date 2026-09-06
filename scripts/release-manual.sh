#!/usr/bin/env bash
# scripts/release-manual.sh — Manual release fallback script for storage_ballast_helper.
#
# Builds the canonical release artifact set (versioned tarballs, legacy unversioned mirrors,
# raw binaries, SHA256 sidecars, SHA256SUMS.txt manifest, and release-provenance.json),
# verifies each binary's architecture, and runs `sbh doctor --release --assets <dir>`.
#
# Usage:
#   scripts/release-manual.sh --tag vX.Y.Z [--dir PATH] [--dry-run]
#   scripts/release-manual.sh --tag vX.Y.Z --audit-only [--dir PATH]
#
# Options:
#   --tag TAG         Release tag (e.g., v0.5.2). If omitted, inferred from Cargo.toml.
#   --dir DIR         Destination directory for release artifacts.
#                     Default: $HOME/release-work/storage_ballast_helper/releases/<TAG>
#   --dry-run         Print planned targets, asset filenames, and build commands without building.
#   --skip-build      Skip compilation; package and audit existing target/ binaries.
#   --audit-only      Skip build and packaging; run audit against existing artifacts in DIR.
#   -h, --help        Print this help message and exit.

set -euo pipefail

PROGRAM="sbh"
REPO="Dicklesworthstone/storage_ballast_helper"
CI_FEATURES="--no-default-features --features cli,daemon,sqlite,tui"

# Canonical 4 CI targets
TARGETS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

# Raw binary mapping: triple -> raw name
raw_binary_name() {
  case "$1" in
    x86_64-unknown-linux-gnu)   echo "${PROGRAM}_linux_amd64" ;;
    aarch64-unknown-linux-gnu)  echo "${PROGRAM}_linux_arm64" ;;
    x86_64-apple-darwin)        echo "${PROGRAM}_darwin_amd64" ;;
    aarch64-apple-darwin)       echo "${PROGRAM}_darwin_arm64" ;;
    *)                          echo "" ;;
  esac
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag=""
artifact_dir=""
dry_run=0
skip_build=0
audit_only=0

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --dir)
      artifact_dir="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    --audit-only)
      audit_only=1
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      ;;
  esac
done

# Resolve tag from Cargo.toml if omitted
if [[ -z "$tag" ]]; then
  version="$(grep '^version = ' "${root_dir}/Cargo.toml" | head -n 1 | sed 's/version = "\(.*\)"/\1/')"
  tag="v${version}"
fi

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "error: invalid release tag format: '${tag}' (must start with 'v' followed by semver)" >&2
  exit 1
fi

if [[ -z "$artifact_dir" ]]; then
  artifact_dir="${HOME}/release-work/storage_ballast_helper/releases/${tag}"
fi

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

# ── DRY RUN MODE ─────────────────────────────────────────────────────────────
if [[ $dry_run -eq 1 ]]; then
  echo "=== Manual Release Fallback Dry-Run ==="
  echo "Tag:          ${tag}"
  echo "Artifact dir: ${artifact_dir}"
  echo "CI features:  ${CI_FEATURES}"
  echo ""
  echo "Planned targets and assets:"
  for target in "${TARGETS[@]}"; do
    raw="$(raw_binary_name "$target")"
    echo "  Target: ${target}"
    echo "    - ${PROGRAM}-${tag}-${target}.tar.xz"
    echo "    - ${PROGRAM}-${tag}-${target}.tar.xz.sha256"
    echo "    - ${PROGRAM}-${target}.tar.xz"
    echo "    - ${PROGRAM}-${target}.tar.xz.sha256"
    if [[ -n "$raw" ]]; then
      echo "    - ${raw}"
    fi
  done
  echo "  Manifests:"
  echo "    - SHA256SUMS.txt"
  echo "    - SHA256SUMS"
  echo "    - release-provenance.json"
  echo ""
  echo "Build commands:"
  for target in "${TARGETS[@]}"; do
    if [[ "$target" == "aarch64-unknown-linux-gnu" && "$(uname -m)" != "aarch64" ]]; then
      echo "  cross build ${CI_FEATURES} --release --target ${target}"
    else
      echo "  cargo build ${CI_FEATURES} --release --target ${target}"
    fi
  done
  echo ""
  echo "Verification command:"
  echo "  sbh doctor --release --assets \"${artifact_dir}\""
  exit 0
fi

# ── AUDIT-ONLY MODE ──────────────────────────────────────────────────────────
if [[ $audit_only -eq 1 ]]; then
  echo "Running release audit against: ${artifact_dir}"
  if [[ ! -d "$artifact_dir" ]]; then
    echo "error: artifact directory does not exist: ${artifact_dir}" >&2
    exit 1
  fi
  # Run doctor with local built sbh or cargo run
  if command -v sbh >/dev/null 2>&1; then
    sbh doctor --release --assets "$artifact_dir"
  else
    (cd "$root_dir" && cargo run --quiet --bin sbh -- doctor --release --assets "$artifact_dir")
  fi
  echo "Audit PASSED for ${tag} in ${artifact_dir}"
  exit 0
fi

# ── FULL BUILD AND PACKAGE ───────────────────────────────────────────────────
echo "Preparing manual release ${tag} into: ${artifact_dir}"
mkdir -p "$artifact_dir"

# Verify commit exists
commit_sha="$(git rev-parse HEAD)"
if git rev-parse "${tag}^{commit}" >/dev/null 2>&1; then
  commit_sha="$(git rev-parse "${tag}^{commit}")"
fi

if [[ $skip_build -eq 0 ]]; then
  echo "Building release targets with nightly toolchain..."
  for target in "${TARGETS[@]}"; do
    echo "==> Building ${target}..."
    if [[ "$target" == "aarch64-unknown-linux-gnu" && "$(uname -m)" != "aarch64" ]]; then
      if command -v cross >/dev/null 2>&1; then
        cross build $CI_FEATURES --release --target "$target"
      else
        echo "warning: 'cross' not found; attempting cargo build for ${target}" >&2
        cargo build $CI_FEATURES --release --target "$target"
      fi
    else
      cargo build $CI_FEATURES --release --target "$target"
    fi
  done
fi

echo "Packaging release artifacts..."
cd "$artifact_dir"

for target in "${TARGETS[@]}"; do
  bin_src="${root_dir}/target/${target}/release/${PROGRAM}"
  if [[ ! -f "$bin_src" ]]; then
    # Fallback to standard release dir for host target
    if [[ "$target" == "$(rustc -vV | grep host | awk '{print $2}')" && -f "${root_dir}/target/release/${PROGRAM}" ]]; then
      bin_src="${root_dir}/target/release/${PROGRAM}"
    else
      echo "error: binary not found for target ${target}: ${bin_src}" >&2
      exit 1
    fi
  fi

  # Create temp staging dir to package tarball
  stage_dir="$(mktemp -d)"
  cp "$bin_src" "${stage_dir}/${PROGRAM}"
  chmod +x "${stage_dir}/${PROGRAM}"

  versioned_archive="${PROGRAM}-${tag}-${target}.tar.xz"
  legacy_archive="${PROGRAM}-${target}.tar.xz"

  echo "  Creating ${versioned_archive}..."
  tar -c -J -C "$stage_dir" -f "${artifact_dir}/${versioned_archive}" "${PROGRAM}"
  cp "${artifact_dir}/${versioned_archive}" "${artifact_dir}/${legacy_archive}"

  # Checksum sidecars
  v_sha="$(compute_sha256 "${artifact_dir}/${versioned_archive}")"
  printf '%s  %s\n' "$v_sha" "$versioned_archive" > "${artifact_dir}/${versioned_archive}.sha256"
  printf '%s  %s\n' "$v_sha" "$legacy_archive" > "${artifact_dir}/${legacy_archive}.sha256"

  # Copy raw binary
  raw_name="$(raw_binary_name "$target")"
  if [[ -n "$raw_name" ]]; then
    cp "$bin_src" "${artifact_dir}/${raw_name}"
    chmod +x "${artifact_dir}/${raw_name}"
  fi

  rm -rf "$stage_dir"
done

echo "Generating aggregate manifests..."
# SHA256SUMS.txt (all archives and mirrors)
: > "${artifact_dir}/SHA256SUMS.txt"
for checksum_file in "${artifact_dir}"/*.sha256; do
  [[ -f "$checksum_file" ]] || continue
  cat "$checksum_file" >> "${artifact_dir}/SHA256SUMS.txt"
done
sort -k2,2 -u "${artifact_dir}/SHA256SUMS.txt" -o "${artifact_dir}/SHA256SUMS.txt"

# SHA256SUMS (raw binaries)
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
else
  rm -f "${artifact_dir}/SHA256SUMS"
fi

# release-provenance.json
rustc_ver="$(rustc --version 2>/dev/null || echo "unknown")"
cat > "${artifact_dir}/release-provenance.json" <<EOF
{
  "tag": "${tag}",
  "sha": "${commit_sha}",
  "run_id": "manual-fallback",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rustc_version": "${rustc_ver}"
}
EOF

echo "Running pre-publication audit with sbh doctor --release --assets..."
if command -v sbh >/dev/null 2>&1; then
  sbh doctor --release --assets "$artifact_dir"
else
  (cd "$root_dir" && cargo run --quiet --bin sbh -- doctor --release --assets "$artifact_dir")
fi

echo ""
echo "================================================================="
echo "Artifact set for ${tag} created and validated in:"
echo "  ${artifact_dir}"
echo ""
echo "To publish with operator approval, run:"
echo "  gh release create ${tag} \\"
echo "    --repo ${REPO} \\"
echo "    --title \"${tag}\" \\"
echo "    --notes \"Release ${tag}\" \\"
echo "    ${artifact_dir}/*"
echo "================================================================="
