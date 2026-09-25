#!/usr/bin/env bash
# scripts/dsr_release.sh — finish an sbh release that `dsr build` produced.
#
# sbh never releases through GitHub Actions. `dsr build storage_ballast_helper
# --version X.Y.Z` (from a clean worktree at the tag) leaves the four target
# archives in the dsr artifact dir; this script does everything after that:
#
#   sign       Developer ID + hardened runtime for both darwin binaries, then
#              repack their archives, legacy mirrors, sidecars and the dsr
#              manifest hashes (dsr itself does not code-sign; install.sh on
#              macOS refuses a binary without this authority).
#   notarize   Submit both signed darwin binaries to Apple's notary service and
#              require "Accepted". A bare Mach-O cannot be stapled; Gatekeeper
#              finds the ticket online by code hash, so this also works for a
#              release that is already published.
#   package    scripts/release_gate_and_package.sh --package (raw binaries,
#              SHA256SUMS, provenance) plus its pre-publication audit.
#   minisign   Sign the dsr manifest with the dsr minisign key (on
#              $SBH_MINISIGN_HOST) and fetch the .minisig.
#   publish    Create the GitHub release (notes = the version's CHANGELOG
#              section) if missing, upload every asset, verify the release.
#   tap        Render packaging/homebrew/Formula/sbh.rb for this version and
#              push it to Dicklesworthstone/homebrew-sbh.
#   all        sign notarize package minisign publish tap, in that order.
#
# Usage: scripts/dsr_release.sh STEP... VERSION     (VERSION like 0.6.4)
#
# Environment:
#   DSR_ARTIFACTS       artifact dir (default ~/.local/state/dsr/artifacts/storage_ballast_helper-vVERSION)
#   SBH_SIGN_IDENTITY   codesign identity (default: Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY))
#   SBH_NOTARY_PROFILE  notarytool keychain profile (default: sbh-notary)
#   SBH_MINISIGN_HOST   host holding the dsr minisign key (default: css)
#   SBH_TAP_REPO        Homebrew tap (default: Dicklesworthstone/homebrew-sbh)

set -euo pipefail

REPO="Dicklesworthstone/storage_ballast_helper"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDENTITY="${SBH_SIGN_IDENTITY:-Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)}"
NOTARY_PROFILE="${SBH_NOTARY_PROFILE:-sbh-notary}"
MINISIGN_HOST="${SBH_MINISIGN_HOST:-css}"
TAP_REPO="${SBH_TAP_REPO:-Dicklesworthstone/homebrew-sbh}"
ENTITLEMENTS="${ROOT}/packaging/macos/sbh.entitlements.plist"

die() { echo "dsr_release: $*" >&2; exit 1; }
say() { echo "== $*"; }

[ "$#" -ge 2 ] || die "usage: $0 STEP... VERSION (steps: sign notarize package minisign publish tap all)"
VERSION="${*: -1}"
STEPS=("${@:1:$#-1}")
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must look like 0.6.4, got '${VERSION}'"
TAG="v${VERSION}"
DIR="${DSR_ARTIFACTS:-${HOME}/.local/state/dsr/artifacts/storage_ballast_helper-${TAG}}"
MANIFEST="${DIR}/storage_ballast_helper-${TAG}-manifest.json"
[ -d "${DIR}" ] || die "no artifact dir ${DIR} (run dsr build first)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sbh-dsr-release.XXXXXX")"
trap 'rm -r "${WORK}"' EXIT

darwin_triples=(aarch64-apple-darwin x86_64-apple-darwin)
raw_name() {
    case "$1" in
        aarch64-apple-darwin) echo sbh_darwin_arm64 ;;
        x86_64-apple-darwin) echo sbh_darwin_amd64 ;;
        *) die "no raw binary name for $1" ;;
    esac
}
# Capture first: `codesign | grep -q` fails under pipefail when grep exits early.
signed_by_identity() {
    local details
    details="$(codesign -dvv "$1" 2>&1)" || return 1
    [[ "${details}" == *"Authority=${IDENTITY}"* ]]
}
sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }
write_sidecar() { (cd "${DIR}" && printf '%s  %s\n' "$(sha_of "$1")" "$1" >"$1.sha256"); }

# Refuse an expired signing certificate and warn 30 days ahead (this replaced
# the nightly GitHub cert-expiration workflow).
check_certificate_expiry() {
    local pem
    pem="$(security find-certificate -c "${IDENTITY}" -p 2>/dev/null)" ||
        die "no certificate named '${IDENTITY}' in the keychain"
    printf '%s\n' "${pem}" | openssl x509 -noout -checkend 0 >/dev/null ||
        die "'${IDENTITY}' has expired"
    if ! printf '%s\n' "${pem}" | openssl x509 -noout -checkend $((30 * 24 * 60 * 60)) >/dev/null; then
        echo "dsr_release: WARNING: '${IDENTITY}' expires within 30 days ($(printf '%s\n' "${pem}" | openssl x509 -noout -enddate))" >&2
    fi
}

step_sign() {
    command -v codesign >/dev/null || die "sign needs macOS codesign"
    check_certificate_expiry
    plutil -lint "${ENTITLEMENTS}" >/dev/null
    for triple in "${darwin_triples[@]}"; do
        local raw versioned legacy unpack
        raw="${DIR}/$(raw_name "${triple}")"
        versioned="sbh-${TAG}-${triple}.tar.xz"
        legacy="sbh-${triple}.tar.xz"
        [ -f "${raw}" ] || die "missing ${raw}"
        codesign --force --options runtime --timestamp --entitlements "${ENTITLEMENTS}" \
            -s "${IDENTITY}" "${raw}"
        codesign --verify --strict "${raw}"
        signed_by_identity "${raw}" || die "${raw} lacks ${IDENTITY}"
        unpack="${WORK}/${triple}"
        mkdir -p "${unpack}"
        tar -xJf "${DIR}/${versioned}" -C "${unpack}"
        cp "${raw}" "${unpack}/sbh"
        tar -cJf "${DIR}/${versioned}" -C "${unpack}" sbh README.md LICENSE
        cp "${DIR}/${versioned}" "${DIR}/${legacy}"
        write_sidecar "${versioned}"
        write_sidecar "${legacy}"
        say "signed ${triple}: $(sha_of "${DIR}/${versioned}")"
    done
    [ -f "${MANIFEST}" ] || die "missing ${MANIFEST}"
    python3 - "${MANIFEST}" "${DIR}" <<'PY'
import hashlib, json, os, sys
manifest_path, directory = sys.argv[1], sys.argv[2]
with open(manifest_path) as f:
    manifest = json.load(f)
for artifact in manifest.get("artifacts", []):
    path = os.path.join(directory, artifact["name"])
    if "darwin" in artifact.get("target", "") and os.path.exists(path):
        with open(path, "rb") as f:
            artifact["sha256"] = hashlib.sha256(f.read()).hexdigest()
        artifact["size_bytes"] = os.path.getsize(path)
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
PY
    say "manifest hashes updated"
}

step_notarize() {
    for triple in "${darwin_triples[@]}"; do
        local raw zip result status
        raw="${DIR}/$(raw_name "${triple}")"
        zip="${WORK}/$(raw_name "${triple}").zip"
        signed_by_identity "${raw}" || die "sign ${raw} before notarizing"
        ditto -c -k --keepParent "${raw}" "${zip}"
        result="$(xcrun notarytool submit "${zip}" --keychain-profile "${NOTARY_PROFILE}" \
            --wait --timeout 30m --output-format json)"
        status="$(printf '%s' "${result}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')"
        [ "${status}" = "Accepted" ] || die "notarization of ${triple} ended '${status}': ${result}"
        say "notarized ${triple}"
    done
}

step_package() {
    # The packager audits with `sbh doctor`; use this release's own binary.
    local bin="${WORK}/bin"
    mkdir -p "${bin}"
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) cp "${DIR}/sbh_darwin_arm64" "${bin}/sbh" ;;
        Darwin-x86_64) cp "${DIR}/sbh_darwin_amd64" "${bin}/sbh" ;;
        *) die "run package on a Mac (it needs this release's darwin binary)" ;;
    esac
    PATH="${bin}:${PATH}" "${ROOT}/scripts/release_gate_and_package.sh" --package --dir "${DIR}" --tag "${TAG}"
}

step_minisign() {
    local base
    base="$(basename "${MANIFEST}")"
    scp -q "${MANIFEST}" "${MINISIGN_HOST}:/tmp/${base}"
    # shellcheck disable=SC2029 # the path is meant to expand locally
    ssh "${MINISIGN_HOST}" "dsr signing sign /tmp/${base} && dsr signing verify /tmp/${base}" >/dev/null
    scp -q "${MINISIGN_HOST}:/tmp/${base}.minisig" "${DIR}/"
    say "manifest minisigned on ${MINISIGN_HOST}"
}

step_publish() {
    local notes="${WORK}/notes.md"
    awk -v heading="## ${TAG} " 'index($0, heading) == 1 {f=1; next} /^## v[0-9]/ {f=0} f' \
        "${ROOT}/CHANGELOG.md" >"${notes}"
    [ -s "${notes}" ] || die "CHANGELOG.md has no '## ${TAG}' section"
    if ! gh release view "${TAG}" --repo "${REPO}" >/dev/null 2>&1; then
        gh release create "${TAG}" --repo "${REPO}" --title "${TAG}" --notes-file "${notes}" --verify-tag
    fi
    (
        cd "${DIR}"
        gh release upload "${TAG}" --repo "${REPO}" --clobber \
            release-provenance.json SHA256SUMS SHA256SUMS.txt \
            sbh_darwin_amd64 sbh_darwin_arm64 sbh_linux_amd64 sbh_linux_arm64 \
            sbh-*.tar.xz sbh-*.tar.xz.sha256 \
            "$(basename "${MANIFEST}")" "$(basename "${MANIFEST}").minisig"
    )
    local bin="${WORK}/verify-bin"
    mkdir -p "${bin}"
    cp "${DIR}/sbh_darwin_arm64" "${bin}/sbh" 2>/dev/null || true
    PATH="${bin}:${PATH}" "${ROOT}/scripts/release_gate_and_package.sh" --verify-release "${TAG}"
}

# Render the formula skeleton for this version. Kept separate so the
# rendering is testable without a network (see src/cli/mod.rs tests).
render_formula() {
    local template="$1" out="$2" arm_sha="$3" intel_sha="$4"
    VERSION="${VERSION}" ARM_SHA="${arm_sha}" INTEL_SHA="${intel_sha}" perl -0pe '
        s/version "[^"]+"/version "$ENV{VERSION}"/;
        s/releases\/download\/v[0-9]+\.[0-9]+\.[0-9]+\//releases\/download\/v$ENV{VERSION}\//g;
        s/sbh-v[0-9]+\.[0-9]+\.[0-9]+-/sbh-v$ENV{VERSION}-/g;
        s/ *# REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256\n( *)sha256 "[0-9a-f]{64}"/$1sha256 "$ENV{ARM_SHA}"/g;
        s/ *# REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256\n( *)sha256 "[0-9a-f]{64}"/$1sha256 "$ENV{INTEL_SHA}"/g;
    ' "${template}" >"${out}"
    ! grep -q 'REPLACE_WITH_' "${out}" || die "formula still has placeholder checksums"
    grep -q "releases/download/${TAG}/" "${out}" || die "formula does not point at ${TAG}"
    grep -q "sha256 \"${arm_sha}\"" "${out}" || die "formula lacks the arm64 checksum"
    grep -q "sha256 \"${intel_sha}\"" "${out}" || die "formula lacks the x86_64 checksum"
    ruby -c "${out}" >/dev/null
}

step_tap() {
    local arm_sha intel_sha tap="${WORK}/tap"
    arm_sha="$(awk '{print $1}' "${DIR}/sbh-${TAG}-aarch64-apple-darwin.tar.xz.sha256")"
    intel_sha="$(awk '{print $1}' "${DIR}/sbh-${TAG}-x86_64-apple-darwin.tar.xz.sha256")"
    # The tap must point at what is actually published, not a local rebuild.
    for triple in "${darwin_triples[@]}"; do
        local want published
        want="$(awk '{print $1}' "${DIR}/sbh-${TAG}-${triple}.tar.xz.sha256")"
        published="$(gh release download "${TAG}" --repo "${REPO}" \
            --pattern "sbh-${TAG}-${triple}.tar.xz.sha256" --output - | awk '{print $1}')"
        [ "${want}" = "${published}" ] || die "published ${triple} checksum ${published} != local ${want}"
    done
    gh repo clone "${TAP_REPO}" "${tap}" -- --quiet
    mkdir -p "${tap}/Formula"
    render_formula "${ROOT}/packaging/homebrew/Formula/sbh.rb" "${tap}/Formula/sbh.rb" "${arm_sha}" "${intel_sha}"
    (
        cd "${tap}"
        git add Formula/sbh.rb
        if git diff --cached --quiet; then
            say "tap already at ${TAG}"
            exit 0
        fi
        git commit -q -m "sbh ${VERSION}"
        git push -q origin HEAD:main
        say "tap updated to ${TAG}"
    )
}

for step in "${STEPS[@]}"; do
    case "${step}" in
        all) for s in sign notarize package minisign publish tap; do "step_${s}"; done ;;
        sign | notarize | package | minisign | publish | tap) "step_${step}" ;;
        *) die "unknown step '${step}'" ;;
    esac
done
