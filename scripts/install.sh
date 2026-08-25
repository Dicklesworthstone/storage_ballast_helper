#!/usr/bin/env bash
set -euo pipefail

PROGRAM="sbh"
REPO_DEFAULT="Dicklesworthstone/storage_ballast_helper"

DEST_MODE="user"
DEST_DIR=""
VERSION="latest"
DRY_RUN=0
JSON_MODE=0
QUIET=0
NO_COLOR=0
VERIFY=1
TRACE_ID=""
EVENT_LOG_PATH=""
CURRENT_PHASE="init"
CURRENT_PHASE_START=0

REPO="${SBH_REPOSITORY:-$REPO_DEFAULT}"
WORKDIR=""

if [[ ! -t 1 ]]; then
  NO_COLOR=1
fi

color() {
  local code="$1"
  local stream="${2:-1}"
  if [[ "$NO_COLOR" -eq 1 ]]; then
    return 0
  fi
  if [[ "$stream" -eq 2 ]]; then
    printf '\033[%sm' "$code" >&2
  else
    printf '\033[%sm' "$code"
  fi
}

reset_color() {
  local stream="${1:-1}"
  if [[ "$NO_COLOR" -eq 1 ]]; then
    return 0
  fi
  if [[ "$stream" -eq 2 ]]; then
    printf '\033[0m' >&2
  else
    printf '\033[0m'
  fi
}

log_header() {
  if [[ "$QUIET" -eq 1 || "$JSON_MODE" -eq 1 ]]; then
    return 0
  fi
  color "1;34"
  printf '==> %s\n' "$1"
  reset_color
}

log_info() {
  if [[ "$QUIET" -eq 1 || "$JSON_MODE" -eq 1 ]]; then
    return 0
  fi
  printf '%s\n' "$1"
}

log_warn() {
  color "1;33" 2
  printf 'WARN: %s\n' "$1" >&2
  reset_color 2
}

log_error() {
  color "1;31" 2
  printf 'ERROR: %s\n' "$1" >&2
  reset_color 2
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

emit_json_result() {
  local status="$1"
  local message="$2"
  local mode="$3"
  local destination="$4"
  local target="$5"
  local asset_url="$6"
  local verify_mode="$7"
  local changed="$8"
  local dry_run="$9"
  printf '{'
  printf '"program":"%s",' "$PROGRAM"
  printf '"status":"%s",' "$status"
  printf '"message":"%s",' "$(json_escape "$message")"
  printf '"mode":"%s",' "$mode"
  printf '"destination":"%s",' "$(json_escape "$destination")"
  printf '"target":"%s",' "$target"
  printf '"version":"%s",' "$(json_escape "$VERSION")"
  printf '"asset_url":"%s",' "$(json_escape "$asset_url")"
  printf '"trace_id":"%s",' "$(json_escape "$TRACE_ID")"
  printf '"verify":"%s",' "$verify_mode"
  printf '"changed":%s,' "$changed"
  printf '"dry_run":%s' "$(json_bool "$dry_run")"
  printf '}\n'
}

json_bool() {
  if [[ "$1" -eq 1 ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

event_json() {
  local phase="$1"
  local status="$2"
  local message="$3"
  local duration_seconds="$4"
  printf '{'
  printf '"ts":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '"trace_id":"%s",' "$(json_escape "$TRACE_ID")"
  printf '"phase":"%s",' "$phase"
  printf '"status":"%s",' "$status"
  printf '"message":"%s",' "$(json_escape "$message")"
  printf '"mode":"%s",' "$DEST_MODE"
  printf '"version":"%s",' "$(json_escape "$VERSION")"
  printf '"target":"%s",' "${TARGET_TRIPLE:-unknown}"
  printf '"destination":"%s",' "$(json_escape "${DEST_DIR:-}")"
  printf '"verify":"%s",' "$(verify_mode_label)"
  printf '"dry_run":%s,' "$(json_bool "$DRY_RUN")"
  printf '"duration_seconds":%s' "$duration_seconds"
  printf '}'
}

emit_event() {
  local phase="$1"
  local status="$2"
  local message="$3"
  local duration_seconds="$4"
  if [[ -z "$TRACE_ID" ]]; then
    initialize_trace
  fi
  local payload
  payload="$(event_json "$phase" "$status" "$message" "$duration_seconds")"

  if [[ -n "$EVENT_LOG_PATH" ]]; then
    if ! mkdir -p "$(dirname "$EVENT_LOG_PATH")" 2>/dev/null; then
      local failed_path="$EVENT_LOG_PATH"
      EVENT_LOG_PATH=""
      die "Failed to create event log directory for ${failed_path}"
    fi
    if ! printf '%s\n' "$payload" >> "$EVENT_LOG_PATH" 2>/dev/null; then
      local failed_path="$EVENT_LOG_PATH"
      EVENT_LOG_PATH=""
      die "Failed to write event log at ${failed_path}"
    fi
  fi

  if [[ "$JSON_MODE" -eq 0 && "$QUIET" -eq 0 ]]; then
    printf '[trace:%s] %s/%s: %s\n' "$TRACE_ID" "$phase" "$status" "$message"
  fi
}

start_phase() {
  CURRENT_PHASE="$1"
  CURRENT_PHASE_START="$SECONDS"
  emit_event "$CURRENT_PHASE" "start" "$2" 0
}

finish_phase() {
  local message="$1"
  local duration_seconds=0
  if [[ "$SECONDS" -ge "$CURRENT_PHASE_START" ]]; then
    duration_seconds=$((SECONDS - CURRENT_PHASE_START))
  fi
  emit_event "$CURRENT_PHASE" "success" "$message" "$duration_seconds"
}

die() {
  local message="$1"
  local duration_seconds=0
  if [[ "$SECONDS" -ge "$CURRENT_PHASE_START" ]]; then
    duration_seconds=$((SECONDS - CURRENT_PHASE_START))
  fi
  emit_event "$CURRENT_PHASE" "failure" "$message" "$duration_seconds"
  if [[ "$JSON_MODE" -eq 1 ]]; then
    emit_json_result "error" "$message" "$DEST_MODE" "${DEST_DIR:-}" "${TARGET_TRIPLE:-unknown}" "${ASSET_URL:-}" "$(verify_mode_label)" false "$DRY_RUN"
  else
    log_error "$message"
  fi
  exit 1
}

usage() {
  cat <<'EOF'
sbh Unix installer

Usage:
  install.sh [options]

Options:
  --version <tag|semver>  Install a specific release tag (default: latest)
  --dest <dir>            Destination directory for sbh binary
  --user                  Install to user location (default: ~/.local/bin)
  --system                Install to system location (/usr/local/bin)
  --dry-run               Print planned actions without changing the system
  --verify                Enforce checksum and macOS trust verification (default)
  --no-verify             Skip artifact verification (unsafe, logged)
  --json                  Emit machine-readable JSON summary
  --trace-id <id>         Set explicit trace id for event correlation
  --event-log <path>      Append per-phase JSONL events to the given file
  --quiet                 Reduce output to errors only
  --no-color              Disable ANSI colors
  -h, --help              Show this help text

Examples:
  curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash -s -- --version v0.1.0
  curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash -s -- --system --dry-run
  ./scripts/install.sh --dest "$HOME/bin" --version v0.1.0

Notes:
  - This installer is idempotent: re-running with the same artifact will not rewrite the binary.
  - For tests/airgapped simulation you can override fetch URLs via:
      SBH_INSTALLER_ASSET_URL
      SBH_INSTALLER_CHECKSUM_URL
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Missing required command: $1"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        [[ $# -ge 2 ]] || die "--version requires a value"
        VERSION="$2"
        shift 2
        ;;
      --dest)
        [[ $# -ge 2 ]] || die "--dest requires a value"
        DEST_DIR="$2"
        shift 2
        ;;
      --user)
        DEST_MODE="user"
        shift
        ;;
      --system)
        DEST_MODE="system"
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --verify)
        VERIFY=1
        shift
        ;;
      --no-verify)
        VERIFY=0
        shift
        ;;
      --json)
        JSON_MODE=1
        shift
        ;;
      --trace-id)
        [[ $# -ge 2 ]] || die "--trace-id requires a value"
        TRACE_ID="$2"
        shift 2
        ;;
      --event-log)
        [[ $# -ge 2 ]] || die "--event-log requires a value"
        EVENT_LOG_PATH="$2"
        shift 2
        ;;
      --quiet)
        QUIET=1
        shift
        ;;
      --no-color)
        NO_COLOR=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (run --help for usage)"
        ;;
    esac
  done
}

resolve_target_triple() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    linux)
      case "$arch" in
        x86_64) TARGET_TRIPLE="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) TARGET_TRIPLE="aarch64-unknown-linux-gnu" ;;
        *) die "Unsupported Linux architecture: $arch" ;;
      esac
      ;;
    darwin)
      case "$arch" in
        x86_64) TARGET_TRIPLE="x86_64-apple-darwin" ;;
        arm64|aarch64) TARGET_TRIPLE="aarch64-apple-darwin" ;;
        *) die "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    *)
      die "Unsupported operating system: $os"
      ;;
  esac
}

resolve_destination() {
  if [[ -n "$DEST_DIR" ]]; then
    return 0
  fi
  if [[ "$DEST_MODE" == "system" ]]; then
    DEST_DIR="/usr/local/bin"
  else
    DEST_DIR="${HOME}/.local/bin"
  fi
}

normalize_tag() {
  if [[ "$VERSION" == "latest" ]]; then
    RELEASE_LOCATOR="latest"
  elif [[ "$VERSION" =~ ^v ]]; then
    RELEASE_LOCATOR="$VERSION"
  else
    RELEASE_LOCATOR="v${VERSION}"
  fi
}

map_target_to_raw_name() {
  # Maps a Rust target triple to the raw binary asset naming convention
  # used in some releases (e.g., v0.2.8): sbh-{os}-{arch}
  local triple="$1"
  case "$triple" in
    x86_64-unknown-linux-gnu)   printf '%s' "${PROGRAM}-linux-x86_64" ;;
    aarch64-unknown-linux-gnu)  printf '%s' "${PROGRAM}-linux-aarch64" ;;
    x86_64-apple-darwin)        printf '%s' "${PROGRAM}-darwin-x86_64" ;;
    aarch64-apple-darwin)       printf '%s' "${PROGRAM}-darwin-aarch64" ;;
    *)                          printf '%s' "${PROGRAM}-${triple}" ;;
  esac
}

map_target_to_raw_name_candidates() {
  # Raw-binary asset naming has changed across releases, so emit every
  # convention we know about, newest first, one per line. The caller picks
  # whichever actually exists in the release.
  #
  #   sbh_linux_amd64   -- current (v0.5.0+): underscores, Go-style arch
  #   sbh-linux-x86_64  -- legacy  (v0.2.8):  hyphens, Rust-style arch
  local triple="$1"
  case "$triple" in
    x86_64-unknown-linux-gnu)   printf '%s\n' "${PROGRAM}_linux_amd64" ;;
    aarch64-unknown-linux-gnu)  printf '%s\n' "${PROGRAM}_linux_arm64" ;;
    x86_64-apple-darwin)        printf '%s\n' "${PROGRAM}_darwin_amd64" ;;
    aarch64-apple-darwin)       printf '%s\n' "${PROGRAM}_darwin_arm64" ;;
  esac
  map_target_to_raw_name "$triple"
  printf '\n'
}

pick_checksum_manifest_name() {
  # Releases have shipped the raw-binary manifest under both names. Prefer
  # whichever the release actually lists; default to SHA256SUMS.
  local asset_list="$1"
  local candidate
  for candidate in "SHA256SUMS" "SHA256SUMS.txt"; do
    if printf '%s\n' "$asset_list" | grep -qxF "$candidate" 2>/dev/null; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  printf '%s' "SHA256SUMS"
}

probe_release_assets() {
  # Queries the GitHub API to discover what assets actually exist in the
  # target release, then sets ASSET_FORMAT to one of:
  #   "archive"  -- .tar.xz with per-file .sha256 sidecar
  #   "raw"      -- raw binary with SHA256SUMS.txt manifest
  #   "none"     -- no matching asset found
  # Also sets ASSET_NAME, CHECKSUM_NAME, and the download base URL.

  ASSET_FORMAT="none"
  ASSET_NAME=""
  CHECKSUM_NAME=""

  # Allow override via environment (tests / airgapped)
  if [[ -n "${SBH_INSTALLER_ASSET_URL:-}" ]]; then
    ASSET_URL="${SBH_INSTALLER_ASSET_URL}"
    CHECKSUM_URL="${SBH_INSTALLER_CHECKSUM_URL:-}"
    # Infer format from URL
    if [[ "$ASSET_URL" == *.tar.xz ]]; then
      ASSET_FORMAT="archive"
    else
      ASSET_FORMAT="raw"
    fi
    return 0
  fi

  # Build the GitHub API endpoint for this release
  local api_path
  if [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    api_path="repos/${REPO}/releases/latest"
  else
    api_path="repos/${REPO}/releases/tags/${RELEASE_LOCATOR}"
  fi

  # Fetch the asset list (best-effort; falls back to URL guessing on failure)
  local asset_json=""
  if command -v gh >/dev/null 2>&1; then
    asset_json="$(gh api "$api_path" --jq '.assets[].name' 2>/dev/null || true)"
  fi
  if [[ -z "$asset_json" ]] && command -v curl >/dev/null 2>&1; then
    asset_json="$(curl -fsSL "https://api.github.com/$api_path" 2>/dev/null \
                  | sed -n 's/.*"name" *: *"\([^"]*\)".*/\1/p' || true)"
  fi

  # Determine download base URL
  local base_url
  if [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    base_url="https://github.com/${REPO}/releases/latest/download"
  else
    base_url="https://github.com/${REPO}/releases/download/${RELEASE_LOCATOR}"
  fi

  # Probe strategy 1: versioned .tar.xz archive.
  local versioned_archive_name=""
  if [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    versioned_archive_name="$(
      printf '%s\n' "$asset_json" \
        | grep -E "^${PROGRAM}-v[0-9][A-Za-z0-9._-]*-${TARGET_TRIPLE}[.]tar[.]xz$" \
        | head -n 1 || true
    )"
  else
    versioned_archive_name="${PROGRAM}-${RELEASE_LOCATOR}-${TARGET_TRIPLE}.tar.xz"
  fi
  local versioned_archive_checksum="${versioned_archive_name}.sha256"

  if [[ -n "$versioned_archive_name" ]] \
      && printf '%s\n' "$asset_json" | grep -qxF "$versioned_archive_name" 2>/dev/null; then
    ASSET_FORMAT="archive"
    ASSET_NAME="$versioned_archive_name"
    CHECKSUM_NAME="$versioned_archive_checksum"
    ASSET_URL="${base_url}/${ASSET_NAME}"
    CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
    return 0
  fi

  # Probe strategy 2: legacy unversioned .tar.xz archive.
  local archive_name="${PROGRAM}-${TARGET_TRIPLE}.tar.xz"
  local archive_checksum="${archive_name}.sha256"

  if printf '%s\n' "$asset_json" | grep -qxF "$archive_name" 2>/dev/null; then
    ASSET_FORMAT="archive"
    ASSET_NAME="$archive_name"
    CHECKSUM_NAME="$archive_checksum"
    ASSET_URL="${base_url}/${ASSET_NAME}"
    CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
    return 0
  fi

  # Probe strategy 3: raw binary. Naming has changed between releases
  # (sbh_linux_amd64 today, sbh-linux-x86_64 historically), so try each
  # known convention against the asset list the API gave us.
  local raw_name raw_candidate
  raw_name="$(map_target_to_raw_name "$TARGET_TRIPLE")"

  while IFS= read -r raw_candidate; do
    [[ -n "$raw_candidate" ]] || continue
    if printf '%s\n' "$asset_json" | grep -qxF "$raw_candidate" 2>/dev/null; then
      ASSET_FORMAT="raw"
      ASSET_NAME="$raw_candidate"
      CHECKSUM_NAME="$(pick_checksum_manifest_name "$asset_json")"
      ASSET_URL="${base_url}/${ASSET_NAME}"
      CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
      return 0
    fi
  done < <(map_target_to_raw_name_candidates "$TARGET_TRIPLE")

  # If the API call failed (no gh, no curl, rate-limited) fall back to
  # guessing with HEAD requests.
  if [[ -z "$asset_json" ]]; then
    # Try the versioned archive first when the tag is known.
    if [[ -n "$versioned_archive_name" ]] \
        && curl -fsSL --head "${base_url}/${versioned_archive_name}" >/dev/null 2>&1; then
      ASSET_FORMAT="archive"
      ASSET_NAME="$versioned_archive_name"
      CHECKSUM_NAME="$versioned_archive_checksum"
      ASSET_URL="${base_url}/${ASSET_NAME}"
      CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
      return 0
    fi

    # Try the legacy archive before raw binary fallback.
    if curl -fsSL --head "${base_url}/${archive_name}" >/dev/null 2>&1; then
      ASSET_FORMAT="archive"
      ASSET_NAME="$archive_name"
      CHECKSUM_NAME="$archive_checksum"
      ASSET_URL="${base_url}/${ASSET_NAME}"
      CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
      return 0
    fi
    # Try raw binary, across every known naming convention.
    while IFS= read -r raw_candidate; do
      [[ -n "$raw_candidate" ]] || continue
      if curl -fsSL --head "${base_url}/${raw_candidate}" >/dev/null 2>&1; then
        ASSET_FORMAT="raw"
        ASSET_NAME="$raw_candidate"
        # No asset list here, so probe the manifest names directly.
        CHECKSUM_NAME="SHA256SUMS"
        if ! curl -fsSL --head "${base_url}/SHA256SUMS" >/dev/null 2>&1 \
            && curl -fsSL --head "${base_url}/SHA256SUMS.txt" >/dev/null 2>&1; then
          CHECKSUM_NAME="SHA256SUMS.txt"
        fi
        ASSET_URL="${base_url}/${ASSET_NAME}"
        CHECKSUM_URL="${base_url}/${CHECKSUM_NAME}"
        return 0
      fi
    done < <(map_target_to_raw_name_candidates "$TARGET_TRIPLE")
  fi

  # No matching asset found
  ASSET_FORMAT="none"
  ASSET_URL=""
  CHECKSUM_URL=""
}

build_urls() {
  probe_release_assets
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "Neither sha256sum nor shasum is available for checksum verification"
  fi
}

is_macos_target() {
  [[ "${TARGET_TRIPLE:-}" == *-apple-darwin ]]
}

verify_macos_binary_trust() {
  local binary_path="$1"
  local codesign_detail

  if ! is_macos_target; then
    return 0
  fi

  start_phase "verify_macos_trust" "verifying macOS Developer ID signature"
  log_header "Verifying macOS binary trust"

  if ! command -v codesign >/dev/null 2>&1; then
    die "codesign is required to verify macOS release binaries. Install Xcode Command Line Tools or retry only with --no-verify if you trust the artifact."
  fi
  if ! codesign --verify --strict --verbose=2 "$binary_path"; then
    die "macOS code signature verification failed for ${ASSET_NAME}. Refusing to install."
  fi
  if ! codesign_detail="$(codesign --display --verbose=4 "$binary_path" 2>&1)"; then
    die "macOS code signature detail inspection failed for ${ASSET_NAME}. Refusing to install."
  fi
  if ! grep -Fq "Authority=Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)" <<<"$codesign_detail"; then
    die "macOS release binary was not signed by the expected Developer ID Application identity. Refusing to install."
  fi
  if ! grep -Fq "TeamIdentifier=AU8V2Z6NKY" <<<"$codesign_detail"; then
    die "macOS release binary was not signed by the expected Apple Developer team. Refusing to install."
  fi

  finish_phase "macOS Developer ID signature verified"
}

verify_mode_label() {
  if [[ "$VERIFY" -eq 1 ]]; then
    printf 'enforced'
  else
    printf 'bypassed'
  fi
}

download_with_retry() {
  local url="$1"
  local out="$2"
  curl --fail --location --silent --show-error --retry 3 --retry-delay 1 --output "$out" "$url"
}

initialize_trace() {
  if [[ -z "$TRACE_ID" ]]; then
    TRACE_ID="install-$(date -u +"%Y%m%dT%H%M%SZ")-$$-${RANDOM}"
  fi
}

install_binary() {
  local src="$1"
  local target="$2"

  if ! mkdir -p "$DEST_DIR" 2>/dev/null; then
    if [[ "$DEST_MODE" == "system" ]] && command -v sudo >/dev/null 2>&1; then
      sudo mkdir -p "$DEST_DIR" || die "Cannot create destination directory: ${DEST_DIR}"
    else
      die "Cannot create destination directory: ${DEST_DIR}. Retry with --dest, --user, or elevated privileges."
    fi
  fi

  if [[ -f "$target" ]] && cmp -s "$src" "$target"; then
    INSTALL_CHANGED=false
    return 0
  fi

  if install -m 0755 "$src" "$target" 2>/dev/null; then
    INSTALL_CHANGED=true
    return 0
  fi

  if [[ "$DEST_MODE" == "system" ]] && command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "$src" "$target"
    INSTALL_CHANGED=true
    return 0
  fi

  die "Cannot write to ${DEST_DIR}. Retry with --dest, --user, or elevated privileges."
}

install_skill() {
  local claude_dest="$HOME/.claude/skills/sbh"
  local codex_dest="$HOME/.codex/skills/sbh"
  local installed_claude=false
  local installed_codex=false

  start_phase "install_skill" "installing sbh skill for AI coding agents"
  log_header "Installing sbh skill for AI coding agents"

  mkdir -p "$claude_dest" 2>/dev/null || true
  mkdir -p "$codex_dest" 2>/dev/null || true

  # ── Try downloading skill tarball from release assets ──────────────────────
  local skill_url
  if [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    skill_url="https://github.com/${REPO}/releases/latest/download/skill.tar.gz"
  else
    skill_url="https://github.com/${REPO}/releases/download/${RELEASE_LOCATOR}/skill.tar.gz"
  fi
  local skill_temp="${WORKDIR}/skill.tar.gz"

  if curl -fsSL --retry 2 --retry-delay 1 -o "$skill_temp" "$skill_url" 2>/dev/null; then
    if tar -xzf "$skill_temp" -C "$HOME/.claude/skills" 2>/dev/null; then
      installed_claude=true
    fi
    if tar -xzf "$skill_temp" -C "$HOME/.codex/skills" 2>/dev/null; then
      installed_codex=true
    fi
    rm -f "$skill_temp"

    if $installed_claude || $installed_codex; then
      $installed_claude && log_info "Skill installed: $claude_dest"
      $installed_codex  && log_info "Skill installed: $codex_dest"
      finish_phase "skill installed from release tarball"
      return 0
    fi
  fi

  # ── Fallback: create minimal inline skill ──────────────────────────────────
  log_info "Installing bundled inline skill"

  local skill_content
  skill_content=$(cat << 'SKILL_EOF'
---
name: sbh
description: >-
  Disk-pressure defense for AI coding workloads. Use when: disk full, low
  space, ballast, cleanup, scan artifacts, emergency, sbh daemon, sbh status.
---

# SBH — Storage Ballast Helper

Prevents disk-full disasters via ballast files, artifact scanning, and predictive pressure monitoring. Three-pronged: ballast (instant space), scanner (stale artifacts), special locations (/tmp, /dev/shm, swap).

## Quick Check

```bash
sbh status                     # Pressure level + free space
sbh status --json | jq '.pressure'  # Machine-parseable
sbh check --need 5G            # "Do I have 5 GB free?"
sbh check --predict 30         # "Will I run out in 30 min?"
```

Exit codes: 0 = healthy, 1 = pressure, 2 = error.

---

## Daemon

```bash
sbh daemon                          # Foreground (debugging)
systemctl --user start sbh          # Systemd user scope
sbh install --systemd --user --auto # Install + start (Linux)
sbh install --launchd --auto        # Install + start (macOS)
sbh install --wizard                # Guided interactive setup
```

**Signals:** `SIGHUP` = reload config, `SIGUSR1` = force scan now, `SIGTERM` = graceful stop.

---

## Ballast

Pre-allocated sacrificial files — released in milliseconds, no scanning needed.

```bash
sbh ballast status             # Per-volume inventory
sbh ballast provision          # Create/rebuild pool
sbh ballast release 3          # Free 3 files NOW
sbh ballast replenish          # Rebuild after pressure passes
```

Defaults: 10 x 1 GiB = 10 GiB. Ensure ballast dir is on **same mount** as pressure source.

---

## Scanning & Cleanup

```bash
sbh scan /data/projects --top 20       # Rank artifacts by score
sbh clean /data/projects --dry-run     # Preview what would go
sbh clean --target-free 50G --yes      # Delete until 50 GB free
```

Scoring: Location (.25) + Name (.25) + Age (.20) + Size (.15) + Structure (.15) = 1.0.

---

## Protection

```bash
sbh protect /path              # .sbh-protect marker (subtree)
sbh unprotect /path            # Remove marker
```

Config globs: `scanner.protected_paths`. Hard vetoes (always enforced): `.git/` dirs, open files, age < 10 min, non-writable parents.

---

## Emergency Recovery

Zero-write mode for near-100% full disks. No config file needed.

```bash
sbh emergency /data --yes              # Aggressive cleanup NOW
sbh emergency --target-free 10G        # Stop at 10 GB recovered
```

---

## Observability

```bash
sbh dashboard                  # TUI: 7 screens (1-7 to jump)
sbh stats --window 24h         # Activity over last 24 hours
sbh blame --top 10             # Top 10 pressure sources
sbh explain --id <ID>          # Why was this decision made?
```

---

## Configuration

Config: `~/.config/sbh/config.toml` | Env: `SBH_` prefix | Fallback: `/etc/sbh/config.toml`

```bash
sbh config show                # Current values
sbh config validate            # Check constraints
sbh config set KEY VALUE       # Change a value
sbh tune --apply --yes         # Auto-tune for this system
```

---

## Anti-Patterns

| Don't | Do Instead |
|-------|------------|
| Ballast on `/tmp` | `paths.ballast_dir` on same mount as pressure source |
| Daemon as root, CLI as user | `--user` scope — avoids state file permission mismatch |
| Skip pre-build check | `sbh check --need 10G` in CI/hook |
| Delete `.sbh-protect` by hand | `sbh unprotect /path` |
| Wait for Red to act | Act at Yellow — agent swarms escalate fast |
| `min_file_age_minutes = 0` | Keep >= 5 to protect in-flight writes |

---

## Docs

Full documentation: https://github.com/Dicklesworthstone/storage_ballast_helper
SKILL_EOF
)

  printf '%s\n' "$skill_content" > "$claude_dest/SKILL.md"
  installed_claude=true
  printf '%s\n' "$skill_content" > "$codex_dest/SKILL.md"
  installed_codex=true

  log_info "Skill created: $claude_dest/SKILL.md"
  log_info "Skill created: $codex_dest/SKILL.md"
  finish_phase "inline skill installed"
}

is_safe_launchd_label() {
  local label="$1"
  [[ -n "$label" && "$label" =~ ^[A-Za-z0-9._-]+$ ]]
}

launchd_labels_for_sync() {
  printf '%s\n' "com.sbh.daemon"
  if is_safe_launchd_label "${SBH_LAUNCHD_LABEL:-}" && [[ "${SBH_LAUNCHD_LABEL}" != "com.sbh.daemon" ]]; then
    printf '%s\n' "${SBH_LAUNCHD_LABEL}"
  fi
}

launchd_plist_binary() {
  local plist="$1"
  awk '
    /<key>ProgramArguments<\/key>/ { in_args = 1; next }
    in_args && /<\/array>/ { exit }
    in_args && /<string>/ {
      line = $0
      sub(/^[[:space:]]*<string>/, "", line)
      sub(/<\/string>.*/, "", line)
      print line
      exit
    }
  ' "$plist"
}

launchd_loaded_target() {
  local label="$1"

  local gui_target
  gui_target="gui/$(id -u)/${label}"
  if launchctl print "$gui_target" >/dev/null 2>&1; then
    printf '%s' "$gui_target"
    return 0
  fi

  local user_target
  user_target="user/$(id -u)/${label}"
  if launchctl print "$user_target" >/dev/null 2>&1; then
    printf '%s' "$user_target"
    return 0
  fi

  return 1
}

sync_launchd_service() {
  [[ "$(uname -s)" == "Darwin" ]] || return 0
  command -v launchctl >/dev/null 2>&1 || return 0

  local target_path="${DEST_DIR}/${PROGRAM}"
  local service_binary=""
  local plist_path=""
  local unit_scope=""
  local label=""

  while IFS= read -r candidate_label; do
    local user_plist="${HOME}/Library/LaunchAgents/${candidate_label}.plist"
    if [[ -f "$user_plist" ]]; then
      service_binary="$(launchd_plist_binary "$user_plist")"
      plist_path="$user_plist"
      unit_scope="user"
      label="$candidate_label"
      break
    fi

    local system_plist="/Library/LaunchDaemons/${candidate_label}.plist"
    if [[ -f "$system_plist" ]]; then
      service_binary="$(launchd_plist_binary "$system_plist")"
      plist_path="$system_plist"
      unit_scope="system"
      label="$candidate_label"
      break
    fi
  done < <(launchd_labels_for_sync)

  [[ -n "$service_binary" ]] || return 0
  [[ "$service_binary" != "$target_path" ]] || return 0

  if [[ -f "$service_binary" ]] && cmp -s "$target_path" "$service_binary" 2>/dev/null; then
    return 0
  fi

  start_phase "sync_service" "syncing launchd service binary"
  log_header "Syncing launchd service binary"
  log_info "Service (${unit_scope}) plist: ${plist_path}"
  log_info "Service ProgramArguments binary: ${service_binary}"
  log_info "Installer installed to: ${target_path}"

  if [[ "$unit_scope" == "system" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      log_warn "Cannot update ${service_binary} without sudo — restart the daemon manually"
      finish_phase "skipped: sudo not available"
      return 0
    fi

    if sudo install -m 0755 "$target_path" "$service_binary" 2>/dev/null; then
      log_info "Updated ${service_binary}"
    else
      log_warn "Failed to update ${service_binary} — restart the daemon manually"
      finish_phase "failed to update launchd service binary"
      return 0
    fi

    if sudo launchctl print "system/${label}" >/dev/null 2>&1; then
      if sudo launchctl kickstart -k "system/${label}" 2>/dev/null; then
        log_info "LaunchDaemon restarted with updated binary"
      else
        log_warn "LaunchDaemon restart failed — may need manual intervention"
      fi
    fi
  else
    if install -m 0755 "$target_path" "$service_binary" 2>/dev/null; then
      log_info "Updated ${service_binary}"
    else
      log_warn "Failed to update ${service_binary}"
      finish_phase "failed to update launchd user service binary"
      return 0
    fi

    local loaded_target=""
    if loaded_target="$(launchd_loaded_target "$label")"; then
      if launchctl kickstart -k "$loaded_target" 2>/dev/null; then
        log_info "LaunchAgent restarted with updated binary"
      else
        log_warn "LaunchAgent restart failed — may need manual intervention"
      fi
    fi
  fi

  finish_phase "launchd service binary synced"
}

sync_systemd_service() {
  # After installing the binary to the primary destination, check if a systemd
  # service exists whose ExecStart points to a DIFFERENT path. If so, update
  # that binary and restart the service so the running daemon picks up the new
  # version. Handles the common case where `--user` installs to ~/.local/bin
  # but the daemon runs from /usr/local/bin via a system unit.

  [[ "$(uname -s)" == "Linux" ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0

  local target_path="${DEST_DIR}/${PROGRAM}"
  local service_binary=""
  local unit_scope=""

  # Check system-level service
  local sys_unit="/etc/systemd/system/sbh.service"
  if [[ -f "$sys_unit" ]]; then
    # Strip ExecStart= prefix and optional - (systemd ignore-error marker),
    # then take the first whitespace-delimited token (the binary path).
    service_binary=$(grep '^ExecStart=' "$sys_unit" | head -1 | sed 's/^ExecStart=-\{0,1\}//' | awk '{print $1}')
    unit_scope="system"
  fi

  # Fallback: check user-level service
  if [[ -z "$service_binary" ]]; then
    local user_unit="${HOME}/.config/systemd/user/sbh.service"
    if [[ -f "$user_unit" ]]; then
      service_binary=$(grep '^ExecStart=' "$user_unit" | head -1 | sed 's/^ExecStart=-\{0,1\}//' | awk '{print $1}')
      unit_scope="user"
    fi
  fi

  # No service found or can't determine binary path
  [[ -n "$service_binary" ]] || return 0

  # If the service already points to where we installed, nothing to sync
  [[ "$service_binary" != "$target_path" ]] || return 0

  # If the service binary is already identical, skip
  if [[ -f "$service_binary" ]] && cmp -s "$target_path" "$service_binary" 2>/dev/null; then
    return 0
  fi

  start_phase "sync_service" "syncing systemd service binary"
  log_header "Syncing systemd service binary"
  log_info "Service (${unit_scope}) ExecStart: ${service_binary}"
  log_info "Installer installed to: ${target_path}"

  if [[ "$unit_scope" == "system" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      log_warn "Cannot update ${service_binary} without sudo — restart the daemon manually"
      finish_phase "skipped: sudo not available"
      return 0
    fi

    local was_active=false
    if systemctl is-active sbh.service >/dev/null 2>&1; then
      was_active=true
      log_info "Stopping sbh.service for binary update..."
      sudo systemctl stop sbh.service 2>/dev/null || true
    fi

    if sudo install -m 0755 "$target_path" "$service_binary" 2>/dev/null; then
      log_info "Updated ${service_binary}"
    else
      log_warn "Failed to update ${service_binary} — restart the daemon manually"
      if $was_active; then
        sudo systemctl start sbh.service 2>/dev/null || true
      fi
      finish_phase "failed to update service binary"
      return 0
    fi

    if $was_active; then
      log_info "Restarting sbh.service..."
      if sudo systemctl start sbh.service 2>/dev/null; then
        log_info "Service restarted with updated binary"
      else
        log_warn "Service restart failed — may need manual intervention"
      fi
    fi
  else
    # User-scope service — no sudo needed
    local was_active=false
    if systemctl --user is-active sbh.service >/dev/null 2>&1; then
      was_active=true
      systemctl --user stop sbh.service 2>/dev/null || true
    fi

    if install -m 0755 "$target_path" "$service_binary" 2>/dev/null; then
      log_info "Updated ${service_binary}"
    else
      log_warn "Failed to update ${service_binary}"
      if $was_active; then
        systemctl --user start sbh.service 2>/dev/null || true
      fi
      finish_phase "failed to update user service binary"
      return 0
    fi

    if $was_active; then
      systemctl --user start sbh.service 2>/dev/null || true
      log_info "User service restarted"
    fi
  fi

  finish_phase "service binary synced"
}

sync_system_service() {
  case "$(uname -s)" in
    Linux) sync_systemd_service ;;
    Darwin) sync_launchd_service ;;
  esac
}

print_summary() {
  local message="$1"
  local changed="$2"
  if [[ "$JSON_MODE" -eq 1 ]]; then
    emit_json_result "ok" "$message" "$DEST_MODE" "$DEST_DIR" "$TARGET_TRIPLE" "$ASSET_URL" "$(verify_mode_label)" "$changed" "$DRY_RUN"
    return 0
  fi

  log_header "sbh installer summary"
  log_info "Mode:        $DEST_MODE"
  log_info "Version:     $VERSION"
  log_info "Target:      $TARGET_TRIPLE"
  log_info "Destination: ${DEST_DIR}/${PROGRAM}"
  log_info "Skill:       ~/.claude/skills/sbh/"
  log_info "Trace ID:    ${TRACE_ID}"
  log_info "Verify:      $(verify_mode_label)"
  log_info "Asset:       $ASSET_URL"
  if [[ -n "$EVENT_LOG_PATH" ]]; then
    log_info "Event log:   ${EVENT_LOG_PATH}"
  fi
  log_info "Result:      $message"
}

main() {
  parse_args "$@"
  initialize_trace
  start_phase "prepare" "resolving prerequisites and installer contract"

  require_cmd curl
  require_cmd install
  require_cmd mktemp

  resolve_target_triple
  resolve_destination
  normalize_tag
  build_urls
  finish_phase "resolved prerequisites and artifact contract"

  if [[ "$VERIFY" -eq 0 ]]; then
    log_warn "Artifact verification is disabled (--no-verify)."
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    start_phase "dry_run" "rendering dry-run execution plan"
    if [[ "$JSON_MODE" -eq 0 ]]; then
      log_header "sbh installer (dry-run)"
      if [[ "$ASSET_FORMAT" == "none" ]]; then
        log_info "No pre-built binary found for ${TARGET_TRIPLE}"
        log_info "Would fall back to: cargo install --git https://github.com/${REPO}.git"
      else
        log_info "Asset format: ${ASSET_FORMAT}"
        log_info "Would download: ${ASSET_URL}"
        if [[ "$VERIFY" -eq 1 && -n "$CHECKSUM_URL" ]]; then
          log_info "Would download checksum: ${CHECKSUM_URL}"
        fi
      fi
      log_info "Would install to: ${DEST_DIR}/${PROGRAM}"
      log_info "Would install skill to: ~/.claude/skills/sbh/"
      log_info "Would install skill to: ~/.codex/skills/sbh/"
    fi
    finish_phase "dry-run plan generated"
    print_summary "dry-run complete (no changes applied)" false
    emit_event "complete" "success" "installer finished in dry-run mode" 0
    return 0
  fi

  WORKDIR="$(mktemp -d)"
  trap 'if [[ -n "${WORKDIR:-}" ]]; then rm -rf "$WORKDIR"; fi' EXIT

  local target_path
  target_path="${DEST_DIR}/${PROGRAM}"

  if [[ "$ASSET_FORMAT" == "none" ]]; then
    # ── Fallback: cargo install ──────────────────────────────────────────────
    start_phase "cargo_install" "no release binary found; falling back to cargo install"
    log_header "No pre-built binary for ${TARGET_TRIPLE} — building from source"
    if ! command -v cargo >/dev/null 2>&1; then
      die "No release binary for ${TARGET_TRIPLE} and cargo is not installed. Install Rust via https://rustup.rs and retry, or manually download from https://github.com/${REPO}/releases"
    fi
    log_info "Running: cargo install --git https://github.com/${REPO}.git"
    if ! cargo install --git "https://github.com/${REPO}.git" 2>&1; then
      die "cargo install from git (https://github.com/${REPO}.git) failed"
    fi
    finish_phase "built and installed via cargo"
    INSTALL_CHANGED=true
    # cargo install puts the binary on PATH via ~/.cargo/bin — update
    # DEST_DIR and ASSET_URL for the summary.
    DEST_DIR="$(dirname "$(command -v sbh 2>/dev/null || echo "${HOME}/.cargo/bin/sbh")")"
    ASSET_URL="(cargo install)"
    install_skill
    sync_system_service
    print_summary "installed ${PROGRAM} via cargo to ${DEST_DIR}/${PROGRAM}" true
    emit_event "complete" "success" "installer completed via cargo install" 0
    return 0
  fi

  if [[ "$ASSET_FORMAT" == "raw" ]]; then
    # ── Raw binary download ────────────────────────────────────────────────
    local binary_path checksum_path
    binary_path="${WORKDIR}/${PROGRAM}"
    checksum_path="${WORKDIR}/SHA256SUMS.txt"

    start_phase "download_artifact" "downloading release binary"
    log_header "Downloading release binary (raw)"
    if ! download_with_retry "$ASSET_URL" "$binary_path"; then
      die "Failed to download release binary from ${ASSET_URL}"
    fi
    chmod +x "$binary_path"
    finish_phase "release binary downloaded"

    if [[ "$VERIFY" -eq 1 ]]; then
      start_phase "verify_artifact" "verifying artifact checksum"
      log_header "Verifying checksum"
      if [[ -n "$CHECKSUM_URL" ]] && download_with_retry "$CHECKSUM_URL" "$checksum_path"; then
        # SHA256SUMS.txt contains lines like: <hash>  <filename>
        # Find the line matching our asset name.
        local expected actual
        expected="$(awk -v name="$ASSET_NAME" '$2 == name || $2 == "./"name || $2 == "*"name { print $1; exit }' "$checksum_path")"
        if [[ -z "$expected" ]]; then
          # Single-entry checksum file — take the first hash
          expected="$(awk '{print $1; exit}' "$checksum_path")"
        fi
        [[ -n "$expected" ]] || die "Checksum file is empty or does not contain entry for ${ASSET_NAME}"
        actual="$(sha256_file "$binary_path")"
        if [[ "$expected" != "$actual" ]]; then
          die "Checksum mismatch for downloaded binary. Expected ${expected}, got ${actual}."
        fi
        finish_phase "artifact checksum verified"
      else
        log_warn "Checksum file not available — skipping verification"
        finish_phase "checksum file unavailable; skipped"
      fi
      verify_macos_binary_trust "$binary_path"
    fi

    start_phase "install_binary" "installing sbh binary"
    log_header "Installing binary"
    install_binary "$binary_path" "$target_path"
    finish_phase "binary install phase completed"

  else
    # ── Archive (.tar.xz) download ────────────────────────────────────────
    local archive_path checksum_path extract_dir binary_path
    archive_path="${WORKDIR}/artifact.tar.xz"
    checksum_path="${WORKDIR}/artifact.sha256"
    extract_dir="${WORKDIR}/extract"

    if ! command -v tar >/dev/null 2>&1; then
      die "tar is required to extract .tar.xz archives but is not installed"
    fi

    start_phase "download_artifact" "downloading release artifact"
    log_header "Downloading release artifact (archive)"
    if ! download_with_retry "$ASSET_URL" "$archive_path"; then
      die "Failed to download release artifact from ${ASSET_URL}"
    fi
    finish_phase "release artifact downloaded"

    if [[ "$VERIFY" -eq 1 ]]; then
      start_phase "verify_artifact" "verifying artifact checksum"
      log_header "Verifying checksum"
      if ! download_with_retry "$CHECKSUM_URL" "$checksum_path"; then
        die "Failed to download checksum from ${CHECKSUM_URL}"
      fi
      local expected actual
      expected="$(awk '{print $1; exit}' "$checksum_path")"
      [[ -n "$expected" ]] || die "Checksum file is empty or malformed"
      actual="$(sha256_file "$archive_path")"
      if [[ "$expected" != "$actual" ]]; then
        die "Checksum mismatch for downloaded artifact. Expected ${expected}, got ${actual}."
      fi
      finish_phase "artifact checksum verified"
    fi

    start_phase "extract_artifact" "extracting release archive"
    log_header "Extracting archive"
    mkdir -p "$extract_dir"
    if ! tar -xJf "$archive_path" -C "$extract_dir"; then
      die "Failed to extract downloaded archive"
    fi
    binary_path="$(find "$extract_dir" -type f -name "$PROGRAM" | head -n 1 || true)"
    [[ -n "$binary_path" ]] || die "Downloaded archive does not contain '${PROGRAM}' binary"
    finish_phase "release archive extracted"

    if [[ "$VERIFY" -eq 1 ]]; then
      verify_macos_binary_trust "$binary_path"
    fi

    start_phase "install_binary" "installing sbh binary"
    log_header "Installing binary"
    install_binary "$binary_path" "$target_path"
    finish_phase "binary install phase completed"
  fi

  install_skill
  sync_system_service

  if [[ "$INSTALL_CHANGED" == "true" ]]; then
    print_summary "installed ${PROGRAM} to ${target_path}" true
    emit_event "complete" "success" "installer completed with binary update" 0
  else
    print_summary "${PROGRAM} already up to date at ${target_path}" false
    emit_event "complete" "success" "installer completed without changes" 0
  fi
}

main "$@"
