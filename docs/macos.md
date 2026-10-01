# macOS Operations Guide

This guide explains how `sbh` behaves on macOS and what an operator should
expect from APFS, launchd, Full Disk Access, Homebrew-style installs, custom
paths, and safety controls.

The 2026-05-03 Mac disk-pressure incident is documented in
`docs/macos-incident-case-study.md`: a 264 GB
`/private/tmp/frankenterm-trash-20260503-092725` staging directory, a 9.8 GB
Claude `vm_bundles` cache, and about 330 GB of active `/private/tmp/ft-*-target`
build directories that sbh should detect but not delete while builds hold them
open.

## Quick Start

For a user-scoped launchd service:

```bash
sbh install --launchd --scope user
sbh doctor --pal
sbh status
```

`sbh install --auto` chooses launchd on macOS, user scope, detected watched
paths, and the medium ballast preset. Use `--scope system` only when the daemon
must monitor system-wide paths or processes; system scope requires root and
installs a LaunchDaemon.

## Platform Defaults

macOS uses native Application Support paths by default:

| Scope | Config | State, logs, ballast, update cache |
| --- | --- | --- |
| User LaunchAgent | `~/Library/Application Support/sbh/config.toml` | `~/Library/Application Support/sbh/` |
| System LaunchDaemon | `/Library/Application Support/sbh/config.toml` | `/private/var/sbh/` |

Config path precedence is:

1. `--config <PATH>`
2. `SBH_CONFIG`
3. Platform-native user default
4. Platform-native system fallback when no user config exists

On macOS, XDG layout is still supported for operators who already use it. `sbh`
uses XDG paths when `SBH_USE_XDG_PATHS=1`, `XDG_CONFIG_HOME`, or
`XDG_DATA_HOME` is set, or when `~/.config/sbh/config.toml` already exists and
the native Application Support config does not.

## launchd Integration

`sbh` generates launchd plists instead of systemd units on macOS.

| Scope | Plist location | Logs |
| --- | --- | --- |
| User | `~/Library/LaunchAgents/` | `~/Library/Logs/sbh/` |
| System | `/Library/LaunchDaemons/` | `/var/log/sbh/` |

The generated plist sets:

- `RunAtLoad=true`, so the daemon starts on login or boot.
- `KeepAlive` with `SuccessfulExit=false`, so crashes restart but clean exits
  stay stopped.
- `ThrottleInterval=60`, to avoid rapid restart loops.
- `Nice=19` and `LowPriorityIO=true`, so cleanup work yields to foreground
  user work and builds.

Use these commands for service health:

```bash
sbh service --launchd --scope user status
sbh service --launchd --scope user restart
sbh doctor --pal
```

`sbh doctor --pal` checks launchd status and prints the exact remediation when
launchctl cannot load or inspect the service.

## APFS Capacity

APFS space accounting is different from fixed Linux filesystems. Multiple
volumes often share one APFS container, so a volume can report a logical size
that is not the actual physical ceiling for disk pressure.

On macOS, `sbh` combines:

- `statfs` for live filesystem capacity.
- `diskutil apfs list -plist` for APFS container and volume metadata.
- Foundation important-usage capacity when available.
- `tmutil listlocalsnapshots` for local Time Machine snapshot inventory.

Status JSON exposes APFS metadata under the mount payload, keyed by
filesystem family. `status --json` and `check --json` carry
`"schema_version": 2` at the top level; version 2 is where the platform
block became family-keyed:

```json
{
  "platform": {
    "darwin": {
      "apfs": {
        "container_id": "/dev/disk3",
        "container_total_bytes": 1000,
        "container_available_bytes": 250,
        "volume_role": "Data",
        "estimated_reclaimable_by_snapshot_thinning": {
          "bytes": 64,
          "method": "foundation"
        },
        "free_excludes_purgeable": true
      }
    }
  }
}
```

A Linux mount carries `{"platform": {"linux": {"fs_type": "ext4",
"is_readonly": false}}}` instead, and the APFS-only mount keys
(`container_id`, `estimated_reclaimable_by_snapshot_thinning`, `free_excludes_purgeable`,
`local_snapshot_reclaim_command`) are absent rather than null. Any other family gets an
empty `platform` object. Consumers should key on the family they know.

The important invariant is `free_excludes_purgeable: true`. `sbh` reports
purgeable storage and snapshot estimates separately, but it does not count those bytes
as free space when making pressure decisions. Purgeable storage is controlled by macOS
and may not be immediately reclaimable when a build or daemon needs space right now.

## Purgeable Space And Snapshot Thinning

Finder and System Settings may show "available" space that includes purgeable
content or space held by local snapshots. Instead of reporting separate and potentially
duplicative purgeable and snapshot bytes, `sbh` reports a unified
`estimated_reclaimable_by_snapshot_thinning` field with the estimation `method`
(`foundation` or `apfs_unattributed`).

Foundation purgeable querying is default-on via `[platform.macos] query_foundation_purgeable = true`
(overridable with the `SBH_MACOS_QUERY_FOUNDATION_PURGEABLE` environment variable).
Treat this estimate as diagnostic context, not as guaranteed emergency headroom.

## Local Time Machine Snapshots

Local snapshots can retain blocks after files are deleted. This matters during
incidents: `sbh ballast release` can unlink ballast files immediately, but APFS
may not show the recovered bytes in `df`, Finder, or status output until the
snapshot retaining those blocks is thinned or expires.

Dry-run the snapshot thinning plan:

```bash
sbh clean --thin-local-snapshots --dry-run
```

Execute it for the root mount:

```bash
sudo sbh clean --thin-local-snapshots --yes
```

Target a specific APFS mount:

```bash
sudo sbh clean --thin-local-snapshots --yes --local-snapshot-mount /System/Volumes/Data
```

The underlying command is:

```bash
sudo tmutil thinlocalsnapshots <mount> 9999999999999999 4
```

Thinning can take 30 seconds or longer. The exact bytes released are controlled
by Time Machine and APFS, not by `sbh`.

## Ballast On APFS

The default user ballast path is:

```text
~/Library/Application Support/sbh/ballast.bin
```

The default system ballast path is:

```text
/private/var/sbh/ballast.bin
```

`[paths].ballast_dir` can move the ballast pool to another volume. Put ballast
on the same volume that needs emergency headroom. A ballast pool on the wrong
mount does not help the full mount.

When APFS local snapshots are present, released ballast blocks may remain
retained by snapshots. If `sbh ballast release` warns about snapshots, thin
snapshots and then re-check:

```bash
sbh status
df -h /
```

## Full Disk Access

macOS Transparency, Consent, and Control protects user data under locations
such as Mail, Messages, and parts of `~/Library`. `sbh` probes Full Disk Access
by attempting to read the Mail Envelope Index under:

```text
~/Library/Mail/V*/MailData/Envelope Index
```

Check the current grant:

```bash
sbh doctor --pal
```

When access is missing, doctor output includes a `macos_full_disk_access`
follow-up and points to `docs/macos-full-disk-access.md`. Grant access before
relying on macOS cleanup scans that need protected user data.

After changing Full Disk Access, restart the launchd service or rerun the
command that needs access:

```bash
sbh service --launchd --scope user restart
sbh doctor --pal
```

Development builds need their own Full Disk Access entry if they run from a
different path than the installed `sbh` binary.

## Homebrew And Install Paths

Apple Silicon Homebrew normally installs under:

```text
/opt/homebrew/bin/sbh
```

Intel Homebrew normally installs under:

```text
/usr/local/bin/sbh
```

Bootstrap and repair checks also inspect common Homebrew sbin paths and Cellar
layouts under `/opt/homebrew` and `/usr/local`. That lets `sbh bootstrap` detect
stale binaries, stale launchd plists, and legacy footprints after a move
between manual and Homebrew-style locations.

The tap skeleton lives in:

```text
packaging/homebrew/Formula/sbh.rb
```

For each release, `scripts/dsr_release.sh tap X.Y.Z` renders that file into
`Dicklesworthstone/homebrew-sbh/Formula/sbh.rb`: it points both archive URLs at
`releases/download/vX.Y.Z`, replaces the placeholder SHA-256 values with the
per-architecture checksums for the released `sbh-v<version>-<target>.tar.xz`
archives, fails if any `REPLACE_WITH_` marker remains, runs `ruby -c` on the
result, and pushes the tap update to the tap's `main` branch. Before rendering,
it downloads the published checksum sidecars for both macOS archives and
refuses to touch the tap when the published checksums differ from the local
ones, so the tap always points at what the release actually serves. The clone
and push use the operator's GitHub CLI login, which therefore needs push access
to `Dicklesworthstone/homebrew-sbh`; no deploy key or repository secret is
involved. The formula installs the prebuilt `sbh` binary, runs
`sbh setup --verify --bin-dir <keg>/bin` as a post-install sanity check, defines
a `brew services` daemon entry, and prints the Full Disk Access reminder in its
caveats.

A manually installed or from-source binary can also live in one of the
standard Homebrew prefixes as long as the launchd plist points at the actual
binary path.

## Code Signing And Hardened Runtime

Released macOS `sbh` binaries are signed with Hardened Runtime enabled. The
entitlements file is intentionally minimal:

```text
packaging/macos/sbh.entitlements.plist
```

That file contains an empty entitlement dictionary. `sbh` does not need JIT,
library-validation bypasses, camera, microphone, or network-server entitlements.

sbh does not use GitHub Actions or any hosted CI for releases. A release is
`dsr build storage_ballast_helper --version X.Y.Z` run from a clean worktree at
the release tag, which leaves the four target archives and raw binaries in the
dsr artifact directory, followed on the release Mac by:

```bash
scripts/dsr_release.sh all X.Y.Z
```

`all` runs the steps `sign`, `notarize`, `package`, `minisign`, `publish`, and
`tap` in that order, and stops at the first failure; each step can also be run
on its own, for example `scripts/dsr_release.sh notarize X.Y.Z`. The `sign`
step signs both darwin raw binaries with:

```bash
codesign --force --options runtime --timestamp \
  --entitlements packaging/macos/sbh.entitlements.plist \
  -s "Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)" sbh_darwin_arm64
```

It then runs `codesign --verify --strict` and fails unless `codesign -dvv`
reports that exact Developer ID authority, repacks the signed binary into the
versioned and legacy archives, rewrites their `.sha256` sidecars, and updates
the darwin hashes in the dsr manifest. `SBH_SIGN_IDENTITY` overrides the
signing identity (for example `Developer ID Application: Example LLC (TEAMID)`),
but the installer and `sbh update` accept only the default identity.

The Unix one-liner installer keeps checksum verification enabled by default.
On macOS, that same `--verify` path also runs
`codesign --verify --strict --verbose=2` and
`codesign --display --verbose=4` against the downloaded `sbh` binary before
writing it to the destination directory. The display output must identify the
exact authority `Authority=Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)`
and `TeamIdentifier=AU8V2Z6NKY`. The explicit `sbh install --no-verify` or
`sbh update --no-verify` flags bypass these installer trust checks and should
only be used for deliberate recovery from a trusted local artifact.

The `notarize` step refuses a binary that lacks the Developer ID authority.
Apple accepts notary uploads as ZIP archives, disk images, or signed flat
packages, while the release artifact remains `sbh-{tag}-{target}.tar.xz`, so the
step wraps each signed `sbh` binary in a temporary ZIP for Apple's scanner and
keeps the tarball naming contract unchanged. It submits with
`xcrun notarytool submit --keychain-profile sbh-notary --wait --timeout 30m`
and fails the release, printing the notary response, unless the status is
`Accepted`. A bare Mach-O cannot be stapled; Gatekeeper finds the ticket online
by code hash, so notarizing also works for a release that is already published.

Release credentials live on the release Mac, never in a repository:

- the Developer ID Application identity (certificate plus private key) in the
  login keychain;
- the `sbh-notary` notarytool keychain profile, created from an App Store
  Connect API key;
- the operator's `gh` login, which creates the GitHub release, uploads the
  assets, and pushes the tap update;
- ssh access to the host that holds the dsr minisign key
  (`SBH_MINISIGN_HOST`, default `css`) for the `minisign` step.

Apple Developer Program enrollment is confirmed for this project. Use the
already-enrolled Apple Developer account or team that owns the Developer ID
Application certificate and notarization credentials. Notarization uses an App
Store Connect API key rather than Apple ID account passwords.

Developer ID certificate setup is intentionally outside the repository because
it handles private key material:

1. Create a certificate signing request on a trusted Mac. The private key should
   stay in the login keychain. Keychain Access can do this through Certificate
   Assistant, or you can use the command-line assistant:

   ```bash
   export CSR_PATH="$HOME/Desktop/sbh-developer-id.certSigningRequest"
   certtool r "$CSR_PATH" u
   certtool V "$CSR_PATH"
   open https://developer.apple.com/account/resources/certificates/add
   ```

2. Upload the CSR in the Apple Developer portal and create a
   `Developer ID Application` certificate for the selected account or team.
3. Install the issued certificate in Keychain Access on the same trusted Mac
   that created the CSR/private key pair and verify that
   `security find-identity -v -p codesigning` lists a `Developer ID
   Application` identity for the selected Team ID.
4. Create the `sbh-notary` keychain profile that `scripts/dsr_release.sh
   notarize` and the release doctor use. `$APPLE_NOTARY_KEY_PATH` is the `.p8`
   App Store Connect API key downloaded from Apple; `notarytool` stores it in
   the keychain, so the file can be moved offline afterwards:

   ```bash
   xcrun notarytool store-credentials sbh-notary \
     --key "$APPLE_NOTARY_KEY_PATH" \
     --key-id "$APPLE_NOTARY_KEY_ID" \
     --issuer "$APPLE_NOTARY_ISSUER_ID"
   ```

5. Confirm the GitHub CLI login can push to the tap:

   ```bash
   gh api repos/Dicklesworthstone/homebrew-sbh --jq .permissions.push
   ```

Rotate the Developer ID certificate and App Store Connect API key every 12
months, or immediately after any maintainer, release-host, or credential
exposure incident. During rotation, install the replacement identity and
re-create the `sbh-notary` profile first, run `sbh doctor --release`, then
publish the next release only after `scripts/dsr_release.sh sign` and
`notarize` succeed with the new identity.

Nothing monitors the certificate's expiry automatically. Check its `notAfter`
date on the release Mac before cutting a release:

```bash
security find-certificate -c "Developer ID Application: Jeffrey Emanuel" -p \
  | openssl x509 -noout -enddate
```

## Release Readiness Diagnostics

Run this before cutting a signed macOS release:

```bash
sbh doctor --release
```

The release doctor does not print secret values. It checks only readiness
signals:

1. `security find-identity -v -p codesigning` must list a `Developer ID
   Application` identity. When `APPLE_DEVELOPER_ID_IDENTITY` is exported, that
   exact configured identity must appear in the available signing identities.
2. `xcrun notarytool history --keychain-profile sbh-notary --output-format json`
   must authenticate successfully with the configured keychain profile.
3. `gh repo view Dicklesworthstone/homebrew-sbh --json nameWithOwner,defaultBranchRef`
   must be able to see the Homebrew tap repository and report `main` as
   `defaultBranchRef.name`, the branch `scripts/dsr_release.sh tap` pushes to.
   The doctor also probes `Formula/sbh.rb` and reports a warning, not a hard failure,
   when the tap exists but the initial formula has not been published yet.
4. Drift checks compare the latest published release with what users get: the
   release must carry the archive and checksum for every release target, and
   the tap formula's version must match the latest release tag.

For automation or handoff checks, use:

```bash
sbh doctor --release --json
```

Treat any `FAIL` result as a release blocker. Treat `WARN` as an attention state:
it does not make the doctor command fail by itself, but the aggregate `ok`
boolean remains false until every release check passes. The command
intentionally reports missing local signing identity, missing notary profile,
and missing tap access as explicit diagnostics so the Apple and GitHub
credential setup can be finished without reading `scripts/dsr_release.sh`.
The JSON report includes an aggregate `ok` boolean plus `passed`, `warnings`, and
`failed` counts so automation can gate on a stable summary before drilling into
individual `checks`.
When any selected doctor check reports `FAIL`, the command exits nonzero after
printing the full human or JSON report so automation can gate release work
without scraping terminal text.

The release doctor also prints a non-secret credential setup plan. The plan
starts with the CSR/keychain request step now that Apple Developer Program
enrollment is confirmed, then uses placeholder environment variables such as
`$APPLE_NOTARY_KEY_PATH`, `$APPLE_NOTARY_KEY_ID`, and
`$APPLE_NOTARY_ISSUER_ID`; it never prints secret values.
After completing the plan, rerun:

```bash
sbh doctor --release --json
```

The JSON `setup_steps` field is stable enough for handoff automation that wants
to display the same Developer ID, notary, Homebrew tap access, and final
recheck commands without scraping this document.

The current CLI tarball flow does not staple a ticket because `stapler` supports
app bundles, disk images, and signed flat packages rather than bare binaries or
the `.tar.xz` artifact. A future `.pkg` or `.dmg` distribution path should
staple and validate that package after notarization.

## Manual Release Fallback

The normal release path is `dsr build` followed by
`scripts/dsr_release.sh all X.Y.Z` (see
[Code Signing And Hardened Runtime](#code-signing-and-hardened-runtime)). Use a
manual fallback only when `dsr build` cannot produce a target and the
operator has explicitly approved publishing outside the dsr path. Do not
publish from chat notes, historical provenance, or a missing `/tmp` directory:
the complete artifact set must exist on disk and pass verification immediately
before upload. The verification is `sbh doctor --release --assets "$ARTIFACT_DIR"`
(a locally built `sbh` is fine): it fails on any missing archive or sidecar,
checksum or `SHA256SUMS.txt` mismatch, missing or differing legacy mirror,
a tarball whose binary is not the labelled architecture, or a provenance
document with the wrong tag. `scripts/dsr_release.sh publish` runs the same
audit against the published release
(`scripts/release_gate_and_package.sh --verify-release`) before the tap update.

The entire fallback build, packaging, and pre-upload audit can be run directly using `scripts/release-manual.sh --tag $TAG` (or previewed with `--dry-run`).

Use a durable working directory outside `/tmp` so cleanup tools do not remove
the prepared bundle before publication:

```bash
export VERSION=0.4.22
export TAG="v${VERSION}"
export SOURCE_SHA="$(git rev-parse "${TAG}^{commit}")"
export ARTIFACT_DIR="$HOME/release-work/storage_ballast_helper/releases/${TAG}"
mkdir -p "$ARTIFACT_DIR"
```

Build fallback artifacts with the same nightly Rust toolchain and feature set as
`dsr build`, whose sbh config builds with
`--no-default-features --features cli,daemon,sqlite`. The repository
`rust-toolchain.toml` pins nightly;
keep `+nightly` in manual release commands so shell-level overrides cannot
accidentally publish stable-built binaries:

```bash
export CI_FEATURES="--no-default-features --features cli,daemon,sqlite"
cargo +nightly build $CI_FEATURES --release --target aarch64-apple-darwin
cargo +nightly build $CI_FEATURES --release --target x86_64-apple-darwin
cross +nightly build $CI_FEATURES --release --target aarch64-unknown-linux-gnu
cargo +nightly build $CI_FEATURES --release --target x86_64-unknown-linux-gnu
```

The fallback artifact set is complete only when all of these files exist:

- `sbh-${TAG}-aarch64-apple-darwin.tar.xz`
- `sbh-${TAG}-aarch64-apple-darwin.tar.xz.sha256`
- `sbh-${TAG}-x86_64-apple-darwin.tar.xz`
- `sbh-${TAG}-x86_64-apple-darwin.tar.xz.sha256`
- `sbh-${TAG}-aarch64-unknown-linux-gnu.tar.xz`
- `sbh-${TAG}-aarch64-unknown-linux-gnu.tar.xz.sha256`
- `sbh-${TAG}-x86_64-unknown-linux-gnu.tar.xz`
- `sbh-${TAG}-x86_64-unknown-linux-gnu.tar.xz.sha256`
- `SHA256SUMS.txt`
- `release-provenance.json`

For macOS artifacts, build the exact tag, sign with the Developer ID Application
identity, verify the hardened-runtime signature, submit the signed binary to
notarytool, download the accepted notary log, and verify the log's
`ticketContents` contains the binary architecture and CDHash before packaging.
For Linux artifacts, use the same no-default-feature release profile as
`dsr build` and verify each extracted binary reports the expected `sbh --version`.

After all four archives and sidecars are present, regenerate the aggregate
manifest from the sidecars and verify it from inside the artifact directory:

```bash
cd "$ARTIFACT_DIR"
: > SHA256SUMS.txt
for checksum_file in sbh-"${TAG}"-*.sha256; do
  archive="${checksum_file%.sha256}"
  test -s "$archive"
  shasum -a 256 -c "$checksum_file"
  awk '{print $1 "  " $2}' "$checksum_file" >> SHA256SUMS.txt
done
sort -k2,2 SHA256SUMS.txt -o SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt
```

Record provenance next to the artifacts:

```bash
cat > release-provenance.json <<EOF
{
  "tag": "${TAG}",
  "sha": "${SOURCE_SHA}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rustc_version": "$(rustc +nightly --version)",
  "release_path": "manual-fallback"
}
EOF
```

Before publication, rerun:

```bash
sbh doctor --release --json
gh release view "$TAG" -R Dicklesworthstone/storage_ballast_helper
```

The doctor must pass. The release view should fail only when the goal is to
create a new release; if it already exists, inspect the existing assets before
uploading anything. Publication is the irreversible handoff point: create the
GitHub Release, upload the verified artifact set, update
`Dicklesworthstone/homebrew-sbh` `Formula/sbh.rb` to the same tag and macOS
checksums, then verify the public tap with `brew fetch`, `brew audit`,
`brew install`, and `brew test`.

## Self-Update Verification

`sbh update` verifies the downloaded archive checksum before extraction. On
macOS, it also verifies the extracted candidate binary before the atomic replacement step:

1. Execute the candidate with `sbh --version` to catch noexec mounts and dynamic
   linker failures.
2. Run `codesign --verify --strict --verbose=2 <candidate>` to reject unsigned
   or malformed signatures.
3. Run `codesign --display --verbose=4 <candidate>` and require the expected
   Developer ID Application identity and `TeamIdentifier=AU8V2Z6NKY`.
4. Rename the verified candidate into place atomically and roll back to the
   previous binary if any pre-swap check or rename fails.

The unsafe `sbh update --no-verify` escape hatch bypasses checksum, Sigstore, and Developer ID checks. The `sbh install --no-verify` escape hatch forwards that same bypass into the macOS release-binary install path before service setup. Use them only for deliberate recovery from a trusted local bundle.

## Watched Paths

The install wizard auto-detects watched paths from:

- `/data/projects`
- platform temp directories, including `/tmp`
- the user's home directory when available

The static config defaults also include common Linux-style roots such as
`/data/projects`, `/tmp`, `/data/tmp`, `/var/tmp`, `/home`, and `/root`.
Review generated config on macOS and keep watched roots intentionally narrow.

Set custom roots in config:

```toml
[scanner]
root_paths = [
  "/Users/me/Projects",
  "/private/tmp",
]
```

Use protections for durable data inside broad roots:

```bash
sbh protect /Users/me/Projects/important-repo
```

Or use config globs:

```toml
[scanner]
protected_paths = [
  "/Users/me/Projects/client-*",
  "/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Client Records/*",
]
```

Sample configs for common Mac scenarios live under `docs/configs/`:

- `docs/configs/developer-mac.toml` for source-heavy developer laptops.
- `docs/configs/creative-mac.toml` for media-heavy Macs where most user data is
  sacred and dry-run-first.
- `docs/configs/shared-mac-launchdaemon.toml` for system-scope shared Macs.

See `docs/cleanup-rules-macos.md` for the exhaustive macOS cleanup contract and
`docs/sacred-paths.md` for the built-in sacred catalog and the reasoning for
every protected pattern.

## Scanner Events

The v2 scanner on macOS runs reconciliation-only: there is no FSEvents
backend, so the daemon does not learn about filesystem changes between
passes. Every configured root is treated as dirty, the maintenance pass
(`pressure.maintenance_interval_secs`) and the pressure-driven passes are
the bound on how stale the candidate index can be, and the daemon logs
`scanner_events: backend=reconciliation-only ... reason=safe kernel scanner
event backend is unavailable on this platform` at startup so nobody has to
guess. Adding FSEvents through a safe crate is tracked on
bd-rc-master-ajg1.8.5; it needs a test run on a Mac to prove it, not a Linux
host.

## Migrating From Visual Cleanup Tools

If you already use CleanMyMac, OmniDiskSweeper, DaisyDisk, or GrandPerspective,
keep those tools for visual review and personal-file decisions. Add `sbh` for
continuous pressure monitoring, ballast headroom, dry-run artifact cleanup,
protected-path vetoes, APFS/Time Machine snapshot warnings, and audit output
that can run under launchd.

See `docs/migrating-from-other-tools.md` for the migration checklist and the
side-by-side comparison.

## macOS Cleanup Safety Model

macOS cleanup rules are specific and conservative. This section is a summary;
the exhaustive operator trust document is `docs/cleanup-rules-macos.md`.

- Xcode DerivedData cleanup targets immediate children of
  `~/Library/Developer/Xcode/DerivedData/`, not the root as one broad delete.
- Electron cleanup targets regenerated cache shapes such as `Cache`,
  `Code Cache`, `GPUCache`, `IndexedDB`, `Service Worker/CacheStorage`, and
  `vm_bundles`.
- `/private/tmp/*-target`, `*_target`, and `target_*` are treated as likely
  build artifacts only after age and safety checks.
- User-named trash directories under temporary roots are ambiguous and require
  review unless another hard veto keeps them.
- Time Machine snapshot thinning uses `tmutil`; it is not path deletion.
- `~/.Trash` and iCloud Drive trash are report-only. `sbh` does not auto-empty
  user trash.
- `~/Library/Caches/<app>` cleanup targets individual application cache directories
  older than 7 days, defaulting to Review unless confirmed Definite.

Every cleanup candidate still passes hard vetoes: sacred-overlap checks,
`.sbh-protect` markers, parent checks, active-reference evidence where visible,
minimum age, and source-root checks.

User-scope macOS runs can have incomplete visibility into other users'
processes. When active-reference checks are incomplete, `sbh` surfaces that
reason in scan output instead of silently pretending visibility is complete.

## Platform Abstraction Layer (PAL) Architecture

`sbh` abstracts all platform-dependent filesystem, process, and service calls behind
the `Platform` trait in `src/platform/pal.rs`:

- `MacOsPal`: The production macOS implementation (`src/platform/macos/pal.rs`) using
  `statfs`, APFS container accounting (`diskutil apfs list -plist`), Foundation
  `important_usage_available_bytes`, `tmutil`, `libproc` (`crates/sbh_mach`), and launchd.
- `LinuxPal`: The production Linux implementation (`src/platform/linux/mod.rs`) using
  `statvfs`, `/proc/mounts`, `/proc/<pid>/fd`, and systemd.
- `MockPlatform`: The in-memory test implementation (`src/platform/pal.rs`) providing
  fully deterministic filesystem, capacity, and process listings for tests.

## Security Model

`sbh` separates observation from mutation:

- `sbh status`, `sbh check`, `sbh scan`, `sbh doctor --pal`, and dry-runs are
  non-destructive.
- `sbh clean --dry-run` prints the plan without deletion.
- `sbh clean --yes`, daemon cleanup in enforcing policy modes, and ballast
  release are mutating operations.
- Protected paths and sacred paths are hard vetoes, not scoring hints.
- Purgeable space is reported separately and excluded from free-space pressure
  decisions.
- launchd runs with low scheduling and IO priority so it yields to foreground
  work.

For incident response, prefer this sequence:

```bash
sbh doctor --pal
sbh status --json
sbh clean --thin-local-snapshots --dry-run
sbh scan /private/tmp --top 20
sbh clean /private/tmp --dry-run
```

Only add `--yes` after the dry-run output names exactly the paths you expect.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `sbh doctor --pal` reports missing Full Disk Access | Follow `docs/macos-full-disk-access.md`, restart launchd, rerun doctor. |
| `df` does not show space after ballast release | Check local snapshots and run snapshot thinning. |
| launchd says the service is not loaded | Run `sbh service --launchd --scope user status`, then use `docs/launchd-troubleshooting.md` for `launchctl print` interpretation and recovery. |
| Status shows purgeable bytes but pressure remains high | Treat purgeable as informational; free real space or thin snapshots. |
| Cleanup cannot see active references for some processes | Use system scope when system-wide process visibility is required. |
