#!/usr/bin/env bash
set -euo pipefail

REPO="Dicklesworthstone/storage_ballast_helper"
INSTALL_DIR="${SBH_INSTALL_DIR:-/usr/local/bin}"
BINARY="sbh"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)
    case "${ARCH}" in
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      *)       echo "Unsupported Linux architecture: ${ARCH}" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "${ARCH}" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64)        TARGET="x86_64-apple-darwin" ;;
      *)             echo "Unsupported macOS architecture: ${ARCH}" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: ${OS}" >&2; exit 1
    ;;
esac

ARCHIVE="${BINARY}-${TARGET}.tar.xz"

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

URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
SHA_URL="${URL}.sha256"

echo "Installing ${BINARY} ${TAG} for ${TARGET}..."

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

# Download archive and checksum
curl -fsSL -o "${TMPDIR}/${ARCHIVE}" "${URL}"
curl -fsSL -o "${TMPDIR}/${ARCHIVE}.sha256" "${SHA_URL}"

# Verify checksum
cd "${TMPDIR}"
if command -v sha256sum &>/dev/null; then
  sha256sum -c "${ARCHIVE}.sha256"
elif command -v shasum &>/dev/null; then
  shasum -a 256 -c "${ARCHIVE}.sha256"
else
  echo "Warning: no sha256sum or shasum found, skipping checksum verification" >&2
fi

# Extract
tar xJf "${ARCHIVE}"

# Install
if [ -w "${INSTALL_DIR}" ]; then
  mv "${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo "Installed ${BINARY} ${TAG} to ${INSTALL_DIR}/${BINARY}"
"${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo "Run 'sbh version' to verify."
