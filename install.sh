#!/usr/bin/env bash
set -euo pipefail

REPO="Dicklesworthstone/storage_ballast_helper"
INSTALL_DIR="${SBH_INSTALL_DIR:-/usr/local/bin}"
BINARY="sbh"
TAG=""

usage() {
  cat <<'USAGE'
Usage: install.sh [--dest <dir>] [--version <tag>]

  --dest <dir>       Install sbh into <dir> (default: $SBH_INSTALL_DIR, else /usr/local/bin)
  --version <tag>    Install this release, e.g. v0.7.5 (default: the latest release)
  -h, --help         Show this help

For service setup, per-user installs and agent skills, use scripts/install.sh.
USAGE
}

# An unknown argument must never fall through to the default destination:
# as root that would silently replace /usr/local/bin/sbh, the system daemon.
while [ $# -gt 0 ]; do
  case "$1" in
    --dest)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "--dest requires a directory" >&2; exit 2; }
      INSTALL_DIR="$2"; shift 2 ;;
    --dest=?*) INSTALL_DIR="${1#--dest=}"; shift ;;
    --version)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "--version requires a release tag" >&2; exit 2; }
      TAG="$2"; shift 2 ;;
    --version=?*) TAG="${1#--version=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "${TAG}" in [0-9]*) TAG="v${TAG}" ;; esac

# Detect platform.
#
# Asset names must match what the release workflow actually uploads:
# raw (un-archived) binaries named sbh_{os}_{arch}, alongside a single
# SHA256SUMS manifest covering all four. See the v0.5.0 release assets.
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)
    case "${ARCH}" in
      x86_64)  ASSET="${BINARY}_linux_amd64" ;;
      aarch64) ASSET="${BINARY}_linux_arm64" ;;
      *)       echo "Unsupported Linux architecture: ${ARCH}" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "${ARCH}" in
      arm64|aarch64) ASSET="${BINARY}_darwin_arm64" ;;
      x86_64)        ASSET="${BINARY}_darwin_amd64" ;;
      *)             echo "Unsupported macOS architecture: ${ARCH}" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: ${OS}" >&2; exit 1
    ;;
esac

# Get latest release tag unless one was requested
if [ -n "${TAG}" ]; then
  :
elif command -v gh &>/dev/null; then
  TAG="$(gh release list --repo "${REPO}" --limit 1 --json tagName -q '.[0].tagName')"
else
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4)"
fi
case "${TAG}" in v[0-9]*|[0-9]*) ;; *) TAG="" ;; esac

if [ -z "${TAG}" ]; then
  echo "Could not determine latest release tag" >&2
  exit 1
fi

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
URL="${BASE_URL}/${ASSET}"
SUMS_URL="${BASE_URL}/SHA256SUMS"

echo "Installing ${BINARY} ${TAG} (${ASSET})..."

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

# Download binary and the shared checksum manifest
curl -fsSL -o "${WORKDIR}/${ASSET}" "${URL}"
curl -fsSL -o "${WORKDIR}/SHA256SUMS" "${SUMS_URL}"

cd "${WORKDIR}"

# Verify checksum: SHA256SUMS covers every asset, so select our line first.
# Failing to find the entry is an error, not a reason to skip verification.
if ! grep -E "[[:space:]]\*?${ASSET}\$" SHA256SUMS > "${ASSET}.sha256"; then
  echo "No checksum entry for ${ASSET} in SHA256SUMS" >&2
  exit 1
fi

if command -v sha256sum &>/dev/null; then
  sha256sum -c "${ASSET}.sha256"
elif command -v shasum &>/dev/null; then
  shasum -a 256 -c "${ASSET}.sha256"
else
  echo "Warning: no sha256sum or shasum found, skipping checksum verification" >&2
fi

chmod +x "${ASSET}"

# Install
if [ ! -d "${INSTALL_DIR}" ]; then
  mkdir -p "${INSTALL_DIR}" 2>/dev/null || sudo mkdir -p "${INSTALL_DIR}"
fi
if [ -w "${INSTALL_DIR}" ]; then
  mv "${ASSET}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${ASSET}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo "Installed ${BINARY} ${TAG} to ${INSTALL_DIR}/${BINARY}"
"${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo "Run 'sbh version' to verify."
