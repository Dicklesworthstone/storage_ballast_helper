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
  --verify                Enforce checksum verification (default)
  --no-verify             Skip checksum verification (unsafe, logged)
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

build_urls() {
  local asset checksum
  asset="${PROGRAM}-${TARGET_TRIPLE}.tar.xz"
  checksum="${asset}.sha256"

  if [[ -n "${SBH_INSTALLER_ASSET_URL:-}" ]]; then
    ASSET_URL="${SBH_INSTALLER_ASSET_URL}"
  elif [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    ASSET_URL="https://github.com/${REPO}/releases/latest/download/${asset}"
  else
    ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_LOCATOR}/${asset}"
  fi

  if [[ -n "${SBH_INSTALLER_CHECKSUM_URL:-}" ]]; then
    CHECKSUM_URL="${SBH_INSTALLER_CHECKSUM_URL}"
  elif [[ "$RELEASE_LOCATOR" == "latest" ]]; then
    CHECKSUM_URL="https://github.com/${REPO}/releases/latest/download/${checksum}"
  else
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${RELEASE_LOCATOR}/${checksum}"
  fi
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
  log_info "Skill tarball unavailable — creating inline skill"

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
  finish_phase "inline skill created (tarball unavailable)"
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
  require_cmd tar
  require_cmd install
  require_cmd mktemp

  resolve_target_triple
  resolve_destination
  normalize_tag
  build_urls
  finish_phase "resolved prerequisites and artifact contract"

  if [[ "$VERIFY" -eq 0 ]]; then
    log_warn "Checksum verification is disabled (--no-verify)."
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    start_phase "dry_run" "rendering dry-run execution plan"
    if [[ "$JSON_MODE" -eq 0 ]]; then
      log_header "sbh installer (dry-run)"
      log_info "Would download: ${ASSET_URL}"
      if [[ "$VERIFY" -eq 1 ]]; then
        log_info "Would download checksum: ${CHECKSUM_URL}"
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

  local archive_path checksum_path extract_dir binary_path target_path expected actual
  archive_path="${WORKDIR}/artifact.tar.xz"
  checksum_path="${WORKDIR}/artifact.sha256"
  extract_dir="${WORKDIR}/extract"
  target_path="${DEST_DIR}/${PROGRAM}"

  start_phase "download_artifact" "downloading release artifact"
  log_header "Downloading release artifact"
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

  start_phase "install_binary" "installing sbh binary"
  log_header "Installing binary"
  install_binary "$binary_path" "$target_path"
  finish_phase "binary install phase completed"

  install_skill

  if [[ "$INSTALL_CHANGED" == "true" ]]; then
    print_summary "installed ${PROGRAM} to ${target_path}" true
    emit_event "complete" "success" "installer completed with binary update" 0
  else
    print_summary "${PROGRAM} already up to date at ${target_path}" false
    emit_event "complete" "success" "installer completed without changes" 0
  fi
}

main "$@"
