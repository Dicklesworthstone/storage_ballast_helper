#!/usr/bin/env bash
set -euo pipefail

REPO="Dicklesworthstone/storage_ballast_helper"
INSTALL_DIR="${SBH_INSTALL_DIR:-/usr/local/bin}"
BINARY="sbh"

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

# Get latest release tag
if command -v gh &>/dev/null; then
  TAG="$(gh release list --repo "${REPO}" --limit 1 --json tagName -q '.[0].tagName')"
else
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
fi

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
if [ -w "${INSTALL_DIR}" ]; then
  mv "${ASSET}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${ASSET}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo "Installed ${BINARY} ${TAG} to ${INSTALL_DIR}/${BINARY}"
"${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo "Run 'sbh version' to verify."
