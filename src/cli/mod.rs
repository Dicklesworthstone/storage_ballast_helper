//! CLI contracts shared by installer and updater command paths.
#![allow(missing_docs)]

pub mod assets;
pub mod bootstrap;
/// The pre-cockpit crossterm dashboard.
///
/// Compiled only with the off-by-default `legacy-crossterm-dashboard`
/// feature; the shipped binary carries the frankentui cockpit alone.
#[cfg(feature = "legacy-crossterm-dashboard")]
pub mod dashboard;
pub mod docs;
pub mod from_source;
pub mod install;
pub mod release_audit;
pub mod uninstall;
pub mod update;
pub mod wizard;

use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::errors::{Result, SbhError};
use crate::core::hex_lower;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical GitHub repository for release artifacts.
pub const RELEASE_REPOSITORY: &str = "Dicklesworthstone/storage_ballast_helper";

/// Canonical binary name used in release artifact names.
pub const RELEASE_BINARY_NAME: &str = "sbh";

/// Environment variable that points the release *API* at a fake server.
///
/// Honored only under `SBH_TEST_MODE=1`, like every other injection hook,
/// so a stray variable can never redirect a real update.
pub const RELEASE_API_BASE_ENV: &str = "SBH_RELEASE_API_BASE";

/// Environment variable that points release *downloads* at a fake server.
///
/// Honored only under `SBH_TEST_MODE=1`.
pub const RELEASE_DOWNLOAD_BASE_ENV: &str = "SBH_RELEASE_DOWNLOAD_BASE";

/// The `https://api.github.com` origin, or the test-mode override.
#[must_use]
pub fn release_api_base() -> String {
    test_mode_base_override(RELEASE_API_BASE_ENV)
        .unwrap_or_else(|| "https://api.github.com".to_string())
}

/// The `https://github.com` origin releases download from, or the
/// test-mode override.
#[must_use]
pub fn release_download_base() -> String {
    test_mode_base_override(RELEASE_DOWNLOAD_BASE_ENV)
        .unwrap_or_else(|| "https://github.com".to_string())
}

fn test_mode_base_override(var: &str) -> Option<String> {
    if std::env::var(crate::platform::test_overlay::TEST_MODE_ENV).ok()? != "1" {
        return None;
    }
    let base = std::env::var(var).ok()?;
    let base = base.trim().trim_end_matches('/');
    (!base.is_empty()).then(|| base.to_string())
}

/// Target triples built by `dsr build` and published with every release.
///
/// `scripts/release_gate_and_package.sh` packages exactly these four targets
/// (its `TARGETS` array MUST match this list), and `scripts/dsr_release.sh`
/// signs and notarizes the two `apple-darwin` entries. Tests in this module
/// validate the contract: the packager lists exactly these triples, every
/// target resolves to a valid artifact, and the naming scheme matches what the
/// installer expects.
pub const CI_RELEASE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];

/// Release channels supported by installer/update flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseChannel {
    /// Stable release channel.
    Stable,
    /// Nightly preview channel.
    Nightly,
}

/// Resolved location for the release to install/update from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseLocator {
    /// Use GitHub "latest" release endpoint.
    Latest,
    /// Use a specific release tag.
    Tag(String),
}

/// Offline bundle manifest describing local release artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineBundleManifest {
    /// Manifest schema version.
    pub version: String,
    /// Repository this bundle belongs to.
    pub repository: String,
    /// Release tag contained by the bundle.
    pub release_tag: String,
    /// Artifact set keyed by target triple.
    pub artifacts: Vec<OfflineBundleArtifact>,
}

impl OfflineBundleManifest {
    /// Parse bundle manifest from JSON.
    ///
    /// # Errors
    /// Returns an error when JSON parsing fails.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Read and parse bundle manifest from a local file.
    ///
    /// # Errors
    /// Returns an error when the manifest cannot be read or parsed.
    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|e| SbhError::io(path, e))?;
        Self::from_json(&raw).map_err(|e| SbhError::InvalidConfig {
            details: format!("invalid offline bundle manifest at {}: {e}", path.display()),
        })
    }
}

/// Artifact row inside [`OfflineBundleManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineBundleArtifact {
    /// Target triple this artifact serves.
    pub target: String,
    /// Relative or absolute path to the archive file.
    pub archive: String,
    /// Relative or absolute path to the checksum file.
    pub checksum: String,
    /// Optional relative or absolute path to sigstore bundle JSON.
    #[serde(default)]
    pub sigstore_bundle: Option<String>,
}

/// Runtime host operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    Linux,
    MacOs,
    Windows,
}

/// Runtime host architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArch {
    X86_64,
    Aarch64,
}

/// Runtime host ABI details used for artifact compatibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAbi {
    None,
    Gnu,
    Musl,
    Msvc,
}

/// Concrete host description for artifact resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSpecifier {
    pub os: HostOs,
    pub arch: HostArch,
    pub abi: HostAbi,
}

/// Archive format expected for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    TarXz,
    Zip,
}

impl ArchiveFormat {
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::TarXz => "tar.xz",
            Self::Zip => "zip",
        }
    }
}

/// Target triple + archive format used to fetch release artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactTarget {
    pub triple: &'static str,
    pub archive: ArchiveFormat,
}

/// Shared installer/update release artifact contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifactContract {
    pub repository: &'static str,
    pub binary_name: &'static str,
    pub locator: ReleaseLocator,
    pub target: ArtifactTarget,
}

/// Resolved local bundle artifact paths for a host-specific contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleArtifactResolution {
    pub contract: ReleaseArtifactContract,
    pub archive_path: PathBuf,
    pub checksum_path: PathBuf,
    pub sigstore_bundle_path: Option<PathBuf>,
}

/// Whether integrity verification is enforced or explicitly bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VerificationMode {
    /// Enforce checksum verification (default behavior).
    Enforce,
    /// Explicit `--no-verify` bypass path.
    BypassNoVerify,
}

/// Sigstore verification policy for installer/update flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SigstorePolicy {
    /// Do not run signature verification.
    Disabled,
    /// Run when possible; degrade with warning if unavailable/failing.
    Optional,
    /// Require successful signature verification.
    Required,
}

/// Observed sigstore verification probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SigstoreProbe {
    /// Signature was successfully verified.
    Verified,
    /// `cosign` is not available on the host.
    MissingCosign,
    /// Signature verification was attempted and failed.
    Failed { details: String },
}

/// Final allow/deny decision for the verification pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IntegrityDecision {
    Allow,
    Deny,
}

/// Checksum verification status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ChecksumStatus {
    Verified,
    SkippedBypass,
    Failed {
        expected_sha256: String,
        actual_sha256: String,
    },
}

/// Signature verification status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SignatureStatus {
    NotRequested,
    Verified,
    Degraded { reason: String },
    Failed { reason: String },
}

/// Structured output for machine/human installer summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationOutcome {
    pub decision: IntegrityDecision,
    pub bypass_used: bool,
    pub checksum: ChecksumStatus,
    pub signature: SignatureStatus,
    pub reason_codes: Vec<String>,
    pub warnings: Vec<String>,
}

/// User-Agent every outbound HTTP request from sbh must carry (AGENTS.md rule).
pub const HTTP_USER_AGENT: &str = "OpenAI File Downloader, XaiImageApiFetch/1.0";

/// Aggregate checksum manifest published next to raw `sbh_<os>_<arch>` binaries.
pub const RAW_CHECKSUM_MANIFEST: &str = "SHA256SUMS";

/// Asset layouts a release may use, most preferred first.
///
/// The release workflow publishes `sbh-<tag>-<triple>.tar.xz` with a
/// `.sha256` sidecar; older releases used `sbh-<triple>.tar.xz`; the
/// hand-published v0.5.x releases carry raw `sbh_<os>_<arch>` binaries with a
/// single aggregate `SHA256SUMS`. The updater cannot choose which layout an
/// operator published, so it must resolve against the release's actual asset
/// list instead of guessing one name (which 404'd for every v0.5.x user).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReleaseAssetLayout {
    VersionedArchive,
    LegacyArchive,
    RawBinary,
}

/// One release asset selected for this host, with where its checksum lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReleaseAsset {
    pub layout: ReleaseAssetLayout,
    pub asset_name: String,
    pub checksum_name: String,
    /// `true` when `checksum_name` is an aggregate manifest listing many files.
    pub checksum_is_manifest: bool,
    /// `true` when the asset is an archive that must be extracted.
    pub is_archive: bool,
}

/// Find `asset_name`'s SHA-256 in an aggregate manifest.
///
/// Accepts GNU `hash  name`, GNU binary-mode `hash *name`, and BSD
/// `SHA256 (name) = hash` lines; returns the lowercase 64-hex digest.
#[must_use]
pub fn sha256_from_manifest(manifest: &str, asset_name: &str) -> Option<String> {
    for line in manifest.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(rest) = line.strip_prefix("SHA256 (") {
            if let Some((name, hash)) = rest.split_once(") = ")
                && name == asset_name
            {
                return normalize_hex64(hash);
            }
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name.trim().trim_start_matches('*') == asset_name {
            return normalize_hex64(hash);
        }
    }
    None
}

fn normalize_hex64(raw: &str) -> Option<String> {
    let token = raw.trim().to_ascii_lowercase();
    (token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())).then_some(token)
}

impl ReleaseArtifactContract {
    /// `sbh_<os>_<arch>` spelling of this target's raw binary, when the
    /// target has one (`x86_64`/`aarch64` on Linux or macOS).
    #[must_use]
    pub fn raw_binary_name(&self) -> Option<String> {
        let mut parts = self.target.triple.split('-');
        let arch = match parts.next()? {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return None,
        };
        let rest: Vec<&str> = parts.collect();
        let os = if rest.contains(&"darwin") {
            "darwin"
        } else if rest.contains(&"linux") {
            "linux"
        } else {
            return None;
        };
        Some(format!("{}_{os}_{arch}", self.binary_name))
    }

    /// Candidate assets for `release_tag`, most preferred first.
    #[must_use]
    pub fn release_asset_candidates(&self, release_tag: &str) -> Vec<ResolvedReleaseAsset> {
        let versioned = self.asset_name_for_tag(release_tag);
        let legacy = self.unversioned_asset_name();
        let mut candidates = vec![
            ResolvedReleaseAsset {
                layout: ReleaseAssetLayout::VersionedArchive,
                checksum_name: format!("{versioned}.sha256"),
                asset_name: versioned,
                checksum_is_manifest: false,
                is_archive: true,
            },
            ResolvedReleaseAsset {
                layout: ReleaseAssetLayout::LegacyArchive,
                checksum_name: format!("{legacy}.sha256"),
                asset_name: legacy,
                checksum_is_manifest: false,
                is_archive: true,
            },
        ];
        if let Some(raw) = self.raw_binary_name() {
            candidates.push(ResolvedReleaseAsset {
                layout: ReleaseAssetLayout::RawBinary,
                asset_name: raw,
                checksum_name: RAW_CHECKSUM_MANIFEST.to_string(),
                checksum_is_manifest: true,
                is_archive: false,
            });
        }
        candidates
    }

    /// Pick the first candidate whose asset and checksum both appear in the
    /// release's published asset list.
    #[must_use]
    pub fn resolve_release_asset(
        &self,
        release_tag: &str,
        published: &[String],
    ) -> Option<ResolvedReleaseAsset> {
        self.release_asset_candidates(release_tag)
            .into_iter()
            .find(|candidate| {
                published.contains(&candidate.asset_name)
                    && published.contains(&candidate.checksum_name)
            })
    }

    /// Download URL of a named asset within `release_tag`.
    #[must_use]
    pub fn asset_url_for_tag_and_name(&self, release_tag: &str, asset_name: &str) -> String {
        format!(
            "{}/{}/releases/download/{release_tag}/{asset_name}",
            release_download_base(),
            self.repository
        )
    }

    #[must_use]
    pub fn asset_name(&self) -> String {
        match &self.locator {
            ReleaseLocator::Tag(tag) => self.asset_name_for_tag(tag),
            ReleaseLocator::Latest => self.unversioned_asset_name(),
        }
    }

    #[must_use]
    pub fn asset_name_for_tag(&self, release_tag: &str) -> String {
        format!(
            "{}-{}-{}.{}",
            self.binary_name,
            release_tag,
            self.target.triple,
            self.target.archive.extension()
        )
    }

    #[must_use]
    pub fn checksum_name(&self) -> String {
        format!("{}.sha256", self.asset_name())
    }

    #[must_use]
    pub fn checksum_name_for_tag(&self, release_tag: &str) -> String {
        format!("{}.sha256", self.asset_name_for_tag(release_tag))
    }

    #[must_use]
    pub fn sigstore_bundle_name(&self) -> String {
        format!("{}.sigstore.json", self.asset_name())
    }

    #[must_use]
    pub fn sigstore_bundle_name_for_tag(&self, release_tag: &str) -> String {
        format!("{}.sigstore.json", self.asset_name_for_tag(release_tag))
    }

    #[must_use]
    pub fn expected_release_assets(&self) -> [String; 3] {
        [
            self.asset_name(),
            self.checksum_name(),
            self.sigstore_bundle_name(),
        ]
    }

    #[must_use]
    pub fn asset_url(&self) -> String {
        let asset = self.asset_name();
        match &self.locator {
            ReleaseLocator::Latest => format!(
                "{}/{}/releases/latest/download/{asset}",
                release_download_base(),
                self.repository
            ),
            ReleaseLocator::Tag(tag) => {
                format!(
                    "{}/{}/releases/download/{tag}/{asset}",
                    release_download_base(),
                    self.repository
                )
            }
        }
    }

    fn unversioned_asset_name(&self) -> String {
        format!(
            "{}-{}.{}",
            self.binary_name,
            self.target.triple,
            self.target.archive.extension()
        )
    }
}

impl HostSpecifier {
    /// Detect the current host platform from Rust target constants.
    pub fn detect() -> Result<Self> {
        let os = parse_host_os(std::env::consts::OS)?;
        let arch = parse_host_arch(std::env::consts::ARCH)?;
        let abi = if cfg!(target_env = "gnu") {
            HostAbi::Gnu
        } else if cfg!(target_env = "musl") {
            HostAbi::Musl
        } else if cfg!(target_env = "msvc") {
            HostAbi::Msvc
        } else {
            HostAbi::None
        };

        Ok(Self { os, arch, abi })
    }

    /// Parse host components from installer/updater probes.
    pub fn from_parts(os: &str, arch: &str, abi: Option<&str>) -> Result<Self> {
        let os = parse_host_os(os)?;
        let arch = parse_host_arch(arch)?;
        let abi = parse_host_abi(abi)?;
        Ok(Self { os, arch, abi })
    }
}

/// Resolve installer contract for a host + release selection.
pub fn resolve_installer_artifact_contract(
    host: HostSpecifier,
    channel: ReleaseChannel,
    pinned_version: Option<&str>,
) -> Result<ReleaseArtifactContract> {
    resolve_release_artifact_contract(host, channel, pinned_version)
}

/// Resolve updater contract for a host + release selection.
pub fn resolve_updater_artifact_contract(
    host: HostSpecifier,
    channel: ReleaseChannel,
    pinned_version: Option<&str>,
) -> Result<ReleaseArtifactContract> {
    resolve_release_artifact_contract(host, channel, pinned_version)
}

/// Resolve installer/updater contract from a local offline bundle manifest.
///
/// # Errors
/// Returns an error when manifest schema/content is invalid, the target triple
/// is missing from the bundle, or required local files are absent.
pub fn resolve_bundle_artifact_contract(
    host: HostSpecifier,
    bundle_manifest_path: &Path,
) -> Result<BundleArtifactResolution> {
    let manifest = OfflineBundleManifest::from_path(bundle_manifest_path)?;

    if manifest.version.trim() != "1" {
        return Err(SbhError::InvalidConfig {
            details: format!(
                "unsupported bundle manifest version '{}'; expected '1'",
                manifest.version
            ),
        });
    }

    if manifest.repository != RELEASE_REPOSITORY {
        return Err(SbhError::InvalidConfig {
            details: format!(
                "bundle repository mismatch: expected '{RELEASE_REPOSITORY}', got '{}'",
                manifest.repository
            ),
        });
    }

    let target = resolve_artifact_target(host)?;
    let locator = ReleaseLocator::Tag(normalize_version(&manifest.release_tag)?);
    let contract = ReleaseArtifactContract {
        repository: RELEASE_REPOSITORY,
        binary_name: RELEASE_BINARY_NAME,
        locator,
        target,
    };

    let artifact = manifest
        .artifacts
        .iter()
        .find(|candidate| candidate.target == contract.target.triple)
        .ok_or_else(|| SbhError::InvalidConfig {
            details: format!(
                "bundle manifest missing target '{}' for this host",
                contract.target.triple
            ),
        })?;

    validate_bundle_artifact_names(&contract, artifact)?;

    let manifest_root = bundle_manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let archive_path = resolve_bundle_path(manifest_root, &artifact.archive)?;
    let checksum_path = resolve_bundle_path(manifest_root, &artifact.checksum)?;
    let sigstore_bundle_path = artifact
        .sigstore_bundle
        .as_ref()
        .map(|path| resolve_bundle_path(manifest_root, path))
        .transpose()?;

    ensure_local_file_exists(&archive_path, "bundle archive")?;
    ensure_local_file_exists(&checksum_path, "bundle checksum")?;
    if let Some(sigstore_path) = &sigstore_bundle_path {
        ensure_local_file_exists(sigstore_path, "bundle sigstore")?;
    }

    Ok(BundleArtifactResolution {
        contract,
        archive_path,
        checksum_path,
        sigstore_bundle_path,
    })
}

/// Validate that release assets satisfy the canonical installer/update contract.
pub fn validate_release_assets(
    contract: &ReleaseArtifactContract,
    available_assets: &[String],
) -> Result<()> {
    let expected = contract.expected_release_assets();
    let missing: Vec<String> = expected
        .iter()
        .filter(|required| !available_assets.iter().any(|asset| asset == *required))
        .cloned()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    Err(SbhError::Runtime {
        details: format!(
            "release contract validation failed for {}: missing assets [{}]",
            contract.target.triple,
            missing.join(", ")
        ),
    })
}

/// Verify artifact integrity with mandatory checksum and optional sigstore policy.
pub fn verify_artifact_supply_chain(
    artifact_path: &Path,
    expected_checksum: &str,
    mode: VerificationMode,
    sigstore_policy: SigstorePolicy,
    sigstore_probe: Option<SigstoreProbe>,
) -> Result<VerificationOutcome> {
    if mode == VerificationMode::BypassNoVerify {
        return Ok(VerificationOutcome {
            decision: IntegrityDecision::Allow,
            bypass_used: true,
            checksum: ChecksumStatus::SkippedBypass,
            signature: SignatureStatus::NotRequested,
            reason_codes: vec![String::from("verify_bypass")],
            warnings: vec![String::from(
                "Verification bypassed via --no-verify. This is unsafe and should only be used intentionally.",
            )],
        });
    }

    let normalized_expected = parse_expected_sha256(expected_checksum)?;
    let actual = compute_sha256_hex(artifact_path)?;

    if actual != normalized_expected {
        return Ok(VerificationOutcome {
            decision: IntegrityDecision::Deny,
            bypass_used: false,
            checksum: ChecksumStatus::Failed {
                expected_sha256: normalized_expected,
                actual_sha256: actual,
            },
            signature: SignatureStatus::NotRequested,
            reason_codes: vec![String::from("checksum_mismatch")],
            warnings: Vec::new(),
        });
    }

    let mut reason_codes = Vec::new();
    let mut warnings = Vec::new();
    let signature = evaluate_sigstore_policy(
        sigstore_policy,
        sigstore_probe,
        &mut reason_codes,
        &mut warnings,
    );
    let signature_allows = !matches!(signature, SignatureStatus::Failed { .. });

    Ok(VerificationOutcome {
        decision: if signature_allows {
            IntegrityDecision::Allow
        } else {
            IntegrityDecision::Deny
        },
        bypass_used: false,
        checksum: ChecksumStatus::Verified,
        signature,
        reason_codes,
        warnings,
    })
}

/// Resolve sigstore policy/probe for offline bundle verification.
///
/// If a bundle path is present, signature verification is required and a probe
/// is executed immediately. If no bundle path is present, signature checks are
/// disabled for this verification pass.
#[must_use]
pub fn sigstore_policy_and_probe_for_bundle(
    artifact_path: &Path,
    sigstore_bundle_path: Option<&Path>,
) -> (SigstorePolicy, Option<SigstoreProbe>) {
    sigstore_bundle_path.map_or((SigstorePolicy::Disabled, None), |bundle_path| {
        (
            SigstorePolicy::Required,
            Some(probe_sigstore_bundle(artifact_path, bundle_path)),
        )
    })
}

fn probe_sigstore_bundle(artifact_path: &Path, bundle_path: &Path) -> SigstoreProbe {
    match Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--certificate-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg("--certificate-identity-regexp")
        .arg(format!(
            "https://github\\.com/{}/\\.github/workflows/.*",
            RELEASE_REPOSITORY.replace('/', "\\/")
        ))
        .arg(artifact_path)
        .output()
    {
        Ok(output) if output.status.success() => SigstoreProbe::Verified,
        Ok(output) => SigstoreProbe::Failed {
            details: command_output_details("cosign verify-blob failed", &output),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => SigstoreProbe::MissingCosign,
        Err(err) => SigstoreProbe::Failed {
            details: format!("failed to execute cosign: {err}"),
        },
    }
}

fn command_output_details(prefix: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stderr.is_empty() {
        format!("{prefix}: {stderr}")
    } else if !stdout.is_empty() {
        format!("{prefix}: {stdout}")
    } else {
        format!("{prefix}: status {}", output.status)
    }
}

fn evaluate_sigstore_policy(
    policy: SigstorePolicy,
    probe: Option<SigstoreProbe>,
    reason_codes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> SignatureStatus {
    match policy {
        SigstorePolicy::Disabled => SignatureStatus::NotRequested,
        SigstorePolicy::Optional => match probe {
            Some(SigstoreProbe::Verified) => SignatureStatus::Verified,
            Some(SigstoreProbe::Failed { details }) => {
                reason_codes.push(String::from("sigstore_degraded"));
                warnings.push(format!(
                    "Optional Sigstore verification failed but install/update may continue: {details}"
                ));
                SignatureStatus::Degraded {
                    reason: format!("optional_sigstore_failed: {details}"),
                }
            }
            Some(SigstoreProbe::MissingCosign) | None => {
                reason_codes.push(String::from("sigstore_degraded"));
                warnings.push(String::from(
                    "Optional Sigstore verification skipped because cosign is unavailable.",
                ));
                SignatureStatus::Degraded {
                    reason: String::from("optional_sigstore_missing_cosign"),
                }
            }
        },
        SigstorePolicy::Required => match probe {
            Some(SigstoreProbe::Verified) => SignatureStatus::Verified,
            Some(SigstoreProbe::Failed { details }) => {
                reason_codes.push(String::from("sigstore_required_failed"));
                SignatureStatus::Failed {
                    reason: format!("required_sigstore_failed: {details}"),
                }
            }
            Some(SigstoreProbe::MissingCosign) | None => {
                reason_codes.push(String::from("sigstore_required_unavailable"));
                SignatureStatus::Failed {
                    reason: String::from("required_sigstore_missing_cosign"),
                }
            }
        },
    }
}

fn parse_expected_sha256(expected_checksum: &str) -> Result<String> {
    let token = expected_checksum
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let valid = token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit());
    if valid {
        return Ok(token);
    }

    Err(SbhError::InvalidConfig {
        details: String::from(
            "invalid SHA256 checksum metadata; expected 64 hex characters (optionally followed by filename)",
        ),
    })
}

fn compute_sha256_hex(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|e| SbhError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|e| SbhError::io(path, e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    Ok(hex_lower(digest))
}

fn resolve_release_artifact_contract(
    host: HostSpecifier,
    channel: ReleaseChannel,
    pinned_version: Option<&str>,
) -> Result<ReleaseArtifactContract> {
    let target = resolve_artifact_target(host)?;
    let locator = resolve_release_locator(channel, pinned_version)?;
    Ok(ReleaseArtifactContract {
        repository: RELEASE_REPOSITORY,
        binary_name: RELEASE_BINARY_NAME,
        locator,
        target,
    })
}

fn validate_bundle_artifact_names(
    contract: &ReleaseArtifactContract,
    artifact: &OfflineBundleArtifact,
) -> Result<()> {
    let expected_archive = contract.asset_name();
    let archive_name = bundle_path_file_name(&artifact.archive);
    if archive_name != Some(expected_archive.as_str()) {
        return Err(SbhError::InvalidConfig {
            details: format!(
                "bundle archive mismatch for target '{}': expected '{}', got '{}'",
                contract.target.triple, expected_archive, artifact.archive
            ),
        });
    }

    let expected_checksum = contract.checksum_name();
    let checksum_name = bundle_path_file_name(&artifact.checksum);
    if checksum_name != Some(expected_checksum.as_str()) {
        return Err(SbhError::InvalidConfig {
            details: format!(
                "bundle checksum mismatch for target '{}': expected '{}', got '{}'",
                contract.target.triple, expected_checksum, artifact.checksum
            ),
        });
    }

    if let Some(sigstore_bundle) = &artifact.sigstore_bundle {
        let expected_sigstore = contract.sigstore_bundle_name();
        let sigstore_name = bundle_path_file_name(sigstore_bundle);
        if sigstore_name != Some(expected_sigstore.as_str()) {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "bundle sigstore mismatch for target '{}': expected '{}', got '{}'",
                    contract.target.triple, expected_sigstore, sigstore_bundle
                ),
            });
        }
    }

    Ok(())
}

fn bundle_path_file_name(path: &str) -> Option<&str> {
    Path::new(path).file_name().and_then(|name| name.to_str())
}

fn resolve_bundle_path(manifest_root: &Path, path: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(path);
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SbhError::InvalidConfig {
            details: format!("bundle path cannot contain '..': {path}"),
        });
    }

    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(manifest_root.join(candidate))
    }
}

fn ensure_local_file_exists(path: &Path, label: &str) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }

    Err(SbhError::Runtime {
        details: format!("{label} file not found: {}", path.display()),
    })
}

fn resolve_artifact_target(host: HostSpecifier) -> Result<ArtifactTarget> {
    match (host.os, host.arch, host.abi) {
        (HostOs::Linux, HostArch::X86_64, HostAbi::Gnu) => Ok(ArtifactTarget {
            triple: "x86_64-unknown-linux-gnu",
            archive: ArchiveFormat::TarXz,
        }),
        (HostOs::Linux, HostArch::Aarch64, HostAbi::Gnu) => Ok(ArtifactTarget {
            triple: "aarch64-unknown-linux-gnu",
            archive: ArchiveFormat::TarXz,
        }),
        (HostOs::MacOs, HostArch::X86_64, HostAbi::None) => Ok(ArtifactTarget {
            triple: "x86_64-apple-darwin",
            archive: ArchiveFormat::TarXz,
        }),
        (HostOs::MacOs, HostArch::Aarch64, HostAbi::None) => Ok(ArtifactTarget {
            triple: "aarch64-apple-darwin",
            archive: ArchiveFormat::TarXz,
        }),
        (HostOs::Windows, HostArch::X86_64, HostAbi::Msvc) => Ok(ArtifactTarget {
            triple: "x86_64-pc-windows-msvc",
            archive: ArchiveFormat::Zip,
        }),
        (HostOs::Windows, HostArch::Aarch64, HostAbi::Msvc) => Ok(ArtifactTarget {
            triple: "aarch64-pc-windows-msvc",
            archive: ArchiveFormat::Zip,
        }),
        _ => Err(unsupported_target(host)),
    }
}

fn resolve_release_locator(
    channel: ReleaseChannel,
    pinned_version: Option<&str>,
) -> Result<ReleaseLocator> {
    if let Some(version) = pinned_version {
        let normalized = normalize_version(version)?;
        return Ok(ReleaseLocator::Tag(normalized));
    }

    Ok(match channel {
        ReleaseChannel::Stable => ReleaseLocator::Latest,
        ReleaseChannel::Nightly => ReleaseLocator::Tag(String::from("nightly")),
    })
}

fn normalize_version(version: &str) -> Result<String> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err(SbhError::InvalidConfig {
            details: String::from("empty version pin is invalid"),
        });
    }

    if trimmed.starts_with('v') {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("v{trimmed}"))
    }
}

fn parse_host_os(input: &str) -> Result<HostOs> {
    match input.trim().to_ascii_lowercase().as_str() {
        "linux" => Ok(HostOs::Linux),
        "macos" | "darwin" => Ok(HostOs::MacOs),
        "windows" | "win32" => Ok(HostOs::Windows),
        _ => Err(SbhError::UnsupportedPlatform {
            details: format!(
                "unsupported operating system '{input}'. Supported OS values: linux, macos, windows."
            ),
        }),
    }
}

fn parse_host_arch(input: &str) -> Result<HostArch> {
    match input.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => Ok(HostArch::X86_64),
        "aarch64" | "arm64" => Ok(HostArch::Aarch64),
        _ => Err(SbhError::UnsupportedPlatform {
            details: format!(
                "unsupported architecture '{input}'. Supported arch values: x86_64, aarch64."
            ),
        }),
    }
}

fn parse_host_abi(input: Option<&str>) -> Result<HostAbi> {
    match input.map(str::trim).map(str::to_ascii_lowercase) {
        None => Ok(HostAbi::None),
        Some(v) if v.is_empty() || v == "none" => Ok(HostAbi::None),
        Some(v) if v == "gnu" || v == "glibc" => Ok(HostAbi::Gnu),
        Some(v) if v == "musl" => Ok(HostAbi::Musl),
        Some(v) if v == "msvc" => Ok(HostAbi::Msvc),
        Some(v) => Err(SbhError::UnsupportedPlatform {
            details: format!("unsupported ABI '{v}'. Supported ABI values: none, gnu, musl, msvc."),
        }),
    }
}

fn unsupported_target(host: HostSpecifier) -> SbhError {
    SbhError::UnsupportedPlatform {
        details: format!(
            "unsupported release target ({}/{}/{}). Supported targets: {}. Remediation: use --from-source for local compilation or run on a supported target.",
            host.os,
            host.arch,
            host.abi,
            supported_triples()
        ),
    }
}

fn supported_triples() -> &'static str {
    "x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin, x86_64-pc-windows-msvc, aarch64-pc-windows-msvc"
}

impl fmt::Display for HostOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::MacOs => write!(f, "macos"),
            Self::Windows => write!(f, "windows"),
        }
    }
}

impl fmt::Display for HostArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::Aarch64 => write!(f, "aarch64"),
        }
    }
}

impl fmt::Display for HostAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Gnu => write!(f, "gnu"),
            Self::Musl => write!(f, "musl"),
            Self::Msvc => write!(f, "msvc"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::{NamedTempFile, TempDir};

    fn workflow_block<'a>(workflow: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
        let start = workflow
            .find(start_marker)
            .unwrap_or_else(|| panic!("workflow missing start marker: {start_marker}"));
        let rest = &workflow[start..];
        let end = rest
            .find(end_marker)
            .unwrap_or_else(|| panic!("workflow missing end marker: {end_marker}"));
        &rest[..end]
    }

    #[test]
    fn macos_mount_timeout_uses_whichdisk_fallback() {
        let macos_sys = include_str!("../platform/macos/sys.rs");
        let timeout_branch = workflow_block(
            macos_sys,
            "        Ok(None) => {",
            "        Err(error) => {",
        );

        assert!(
            timeout_branch.contains("falling back to whichdisk"),
            "macOS mount timeout warning must describe the fallback"
        );
        assert!(
            timeout_branch.contains("whichdisk_mount_entries()"),
            "macOS mount timeout must use whichdisk instead of returning an empty inventory"
        );
        assert!(
            timeout_branch.contains("remember_mount_command_failure"),
            "macOS mount timeout must enter backoff before falling back"
        );
        assert!(
            !timeout_branch.contains("Ok(Vec::new())"),
            "macOS mount timeout must not erase mount inventory"
        );
        assert!(
            !timeout_branch.contains("mount inventory unavailable"),
            "macOS mount timeout must not report inventory unavailable when fallback is available"
        );
    }

    #[test]
    fn parses_aliases_for_os_arch_and_abi() {
        let host = HostSpecifier::from_parts("darwin", "arm64", Some("none")).unwrap();
        assert_eq!(
            host,
            HostSpecifier {
                os: HostOs::MacOs,
                arch: HostArch::Aarch64,
                abi: HostAbi::None,
            }
        );

        let linux = HostSpecifier::from_parts("linux", "amd64", Some("glibc")).unwrap();
        assert_eq!(
            linux,
            HostSpecifier {
                os: HostOs::Linux,
                arch: HostArch::X86_64,
                abi: HostAbi::Gnu,
            }
        );
    }

    #[test]
    fn resolves_supported_targets_deterministically() {
        let cases = [
            (
                HostSpecifier {
                    os: HostOs::Linux,
                    arch: HostArch::X86_64,
                    abi: HostAbi::Gnu,
                },
                "x86_64-unknown-linux-gnu",
                ArchiveFormat::TarXz,
            ),
            (
                HostSpecifier {
                    os: HostOs::Linux,
                    arch: HostArch::Aarch64,
                    abi: HostAbi::Gnu,
                },
                "aarch64-unknown-linux-gnu",
                ArchiveFormat::TarXz,
            ),
            (
                HostSpecifier {
                    os: HostOs::MacOs,
                    arch: HostArch::X86_64,
                    abi: HostAbi::None,
                },
                "x86_64-apple-darwin",
                ArchiveFormat::TarXz,
            ),
            (
                HostSpecifier {
                    os: HostOs::MacOs,
                    arch: HostArch::Aarch64,
                    abi: HostAbi::None,
                },
                "aarch64-apple-darwin",
                ArchiveFormat::TarXz,
            ),
            (
                HostSpecifier {
                    os: HostOs::Windows,
                    arch: HostArch::X86_64,
                    abi: HostAbi::Msvc,
                },
                "x86_64-pc-windows-msvc",
                ArchiveFormat::Zip,
            ),
            (
                HostSpecifier {
                    os: HostOs::Windows,
                    arch: HostArch::Aarch64,
                    abi: HostAbi::Msvc,
                },
                "aarch64-pc-windows-msvc",
                ArchiveFormat::Zip,
            ),
        ];

        for (host, expected_triple, expected_format) in cases {
            let contract =
                resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();
            assert_eq!(contract.target.triple, expected_triple);
            assert_eq!(contract.target.archive, expected_format);

            let updater =
                resolve_updater_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();
            assert_eq!(updater.target, contract.target);
        }
    }

    #[test]
    fn release_locator_prefers_pinned_version() {
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };

        let pinned =
            resolve_installer_artifact_contract(host, ReleaseChannel::Nightly, Some("0.1.3"))
                .unwrap();
        assert_eq!(pinned.locator, ReleaseLocator::Tag(String::from("v0.1.3")));

        let nightly =
            resolve_updater_artifact_contract(host, ReleaseChannel::Nightly, None).unwrap();
        assert_eq!(
            nightly.locator,
            ReleaseLocator::Tag(String::from("nightly"))
        );

        let stable = resolve_updater_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();
        assert_eq!(stable.locator, ReleaseLocator::Latest);
    }

    #[test]
    fn builds_expected_asset_names_and_url() {
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let contract =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("v0.1.0"))
                .unwrap();

        assert_eq!(
            contract.asset_name(),
            "sbh-v0.1.0-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            contract.checksum_name(),
            "sbh-v0.1.0-x86_64-unknown-linux-gnu.tar.xz.sha256"
        );
        assert_eq!(
            contract.sigstore_bundle_name(),
            "sbh-v0.1.0-x86_64-unknown-linux-gnu.tar.xz.sigstore.json"
        );
        assert_eq!(
            contract.asset_url(),
            "https://github.com/Dicklesworthstone/storage_ballast_helper/releases/download/v0.1.0/sbh-v0.1.0-x86_64-unknown-linux-gnu.tar.xz"
        );
    }

    #[test]
    fn validates_release_asset_contract() {
        let host = HostSpecifier {
            os: HostOs::Windows,
            arch: HostArch::X86_64,
            abi: HostAbi::Msvc,
        };
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("0.2.1")).unwrap();
        let assets = contract.expected_release_assets().to_vec();

        assert!(validate_release_assets(&contract, &assets).is_ok());

        let partial = vec![contract.asset_name(), contract.checksum_name()];
        let error = validate_release_assets(&contract, &partial).unwrap_err();
        assert_eq!(error.code(), "SBH-3900");
        assert!(
            error
                .to_string()
                .contains("missing assets [sbh-v0.2.1-x86_64-pc-windows-msvc.zip.sigstore.json]")
        );
    }

    #[test]
    fn unsupported_targets_fail_with_actionable_remediation() {
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::Aarch64,
            abi: HostAbi::Musl,
        };
        let error =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap_err();
        assert_eq!(error.code(), "SBH-1101");
        let text = error.to_string();
        assert!(text.contains("unsupported release target"));
        assert!(text.contains("--from-source"));

        let parse_error = HostSpecifier::from_parts("freebsd", "x86_64", None).unwrap_err();
        assert_eq!(parse_error.code(), "SBH-1101");
    }

    #[test]
    fn supply_chain_verification_rejects_tampered_artifact() {
        let artifact = temp_artifact(b"benign artifact bytes");
        let expected = compute_sha256_hex_from_bytes(b"other bytes");

        let outcome = verify_artifact_supply_chain(
            artifact.path(),
            &expected,
            VerificationMode::Enforce,
            SigstorePolicy::Disabled,
            None,
        )
        .unwrap();

        assert_eq!(outcome.decision, IntegrityDecision::Deny);
        assert_eq!(
            outcome.reason_codes,
            vec![String::from("checksum_mismatch")]
        );
        assert!(matches!(outcome.checksum, ChecksumStatus::Failed { .. }));
    }

    #[test]
    fn supply_chain_verification_supports_optional_sigstore_degraded_mode() {
        let artifact = temp_artifact(b"artifact data");
        let expected = compute_sha256_hex_from_bytes(b"artifact data");

        let outcome = verify_artifact_supply_chain(
            artifact.path(),
            &format!("{expected}  sbh-x86_64-unknown-linux-gnu.tar.xz"),
            VerificationMode::Enforce,
            SigstorePolicy::Optional,
            Some(SigstoreProbe::MissingCosign),
        )
        .unwrap();

        assert_eq!(outcome.decision, IntegrityDecision::Allow);
        assert!(matches!(outcome.checksum, ChecksumStatus::Verified));
        assert!(matches!(
            outcome.signature,
            SignatureStatus::Degraded { .. }
        ));
        assert!(
            outcome
                .reason_codes
                .contains(&String::from("sigstore_degraded"))
        );
        assert!(
            !outcome.warnings.is_empty(),
            "a degraded sigstore outcome must surface at least one warning"
        );
    }

    #[test]
    fn supply_chain_verification_required_sigstore_without_cosign_denies() {
        let artifact = temp_artifact(b"artifact data");
        let expected = compute_sha256_hex_from_bytes(b"artifact data");

        let outcome = verify_artifact_supply_chain(
            artifact.path(),
            &expected,
            VerificationMode::Enforce,
            SigstorePolicy::Required,
            Some(SigstoreProbe::MissingCosign),
        )
        .unwrap();

        assert_eq!(outcome.decision, IntegrityDecision::Deny);
        assert_eq!(
            outcome.reason_codes,
            vec![String::from("sigstore_required_unavailable")]
        );
        assert!(matches!(outcome.signature, SignatureStatus::Failed { .. }));
    }

    #[test]
    fn sigstore_policy_requires_probe_when_bundle_path_present() {
        let artifact = temp_artifact(b"artifact data");
        let bundle = temp_artifact(b"{\"invalid\":true}");
        let (policy, probe) =
            sigstore_policy_and_probe_for_bundle(artifact.path(), Some(bundle.path()));

        assert_eq!(policy, SigstorePolicy::Required);
        assert!(probe.is_some());
    }

    #[test]
    fn sigstore_policy_is_disabled_without_bundle_path() {
        let artifact = temp_artifact(b"artifact data");
        let (policy, probe) = sigstore_policy_and_probe_for_bundle(artifact.path(), None);

        assert_eq!(policy, SigstorePolicy::Disabled);
        assert!(probe.is_none());
    }

    #[test]
    fn supply_chain_verification_bypass_is_loud_and_structured() {
        let artifact = temp_artifact(b"artifact data");
        let outcome = verify_artifact_supply_chain(
            artifact.path(),
            "not-a-real-checksum",
            VerificationMode::BypassNoVerify,
            SigstorePolicy::Disabled,
            None,
        )
        .unwrap();

        assert_eq!(outcome.decision, IntegrityDecision::Allow);
        assert!(outcome.bypass_used);
        assert!(matches!(outcome.checksum, ChecksumStatus::SkippedBypass));
        assert_eq!(outcome.reason_codes, vec![String::from("verify_bypass")]);
        assert!(outcome.warnings.iter().any(|w| w.contains("--no-verify")));
    }

    #[test]
    fn supply_chain_verification_invalid_checksum_metadata_errors() {
        let artifact = temp_artifact(b"artifact data");
        let err = verify_artifact_supply_chain(
            artifact.path(),
            "invalid",
            VerificationMode::Enforce,
            SigstorePolicy::Disabled,
            None,
        )
        .unwrap_err();

        assert_eq!(err.code(), "SBH-1001");
        assert!(err.to_string().contains("invalid SHA256 checksum metadata"));
    }

    fn temp_artifact(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file.flush().unwrap();
        file
    }

    fn compute_sha256_hex_from_bytes(contents: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(contents);
        let digest = hasher.finalize();
        hex_lower(digest)
    }

    #[test]
    fn macos_hardened_runtime_entitlements_are_minimal() {
        let entitlements = include_str!("../../packaging/macos/sbh.entitlements.plist");
        assert!(entitlements.contains("<dict/>"));

        for forbidden in [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.network.server",
            "com.apple.security.device.camera",
            "com.apple.security.device.microphone",
        ] {
            assert!(
                !entitlements.contains(forbidden),
                "minimal sbh entitlements must not include {forbidden}"
            );
        }
    }

    /// Body of the shell function `name` in `script`, from its `name() {`
    /// line up to (not including) the next top-level function or loop.
    fn shell_function<'a>(script: &'a str, name: &str) -> &'a str {
        let start_marker = format!("\n{name}() {{\n");
        let start = script
            .find(&start_marker)
            .unwrap_or_else(|| panic!("script missing function {name}"));
        let rest = &script[start + 1..];
        let end = rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("function {name} has no closing brace"));
        &rest[..end + 2]
    }

    fn assert_in_order(haystack: &str, context: &str, fragments: &[&str]) {
        let mut cursor = 0;
        for fragment in fragments {
            let offset = haystack[cursor..].find(fragment).unwrap_or_else(|| {
                panic!("{context}: missing (or out of order) fragment: {fragment}")
            });
            cursor += offset + fragment.len();
        }
    }

    #[test]
    fn dsr_release_signs_macos_binaries_with_developer_id_hardened_runtime() {
        let script = include_str!("../../scripts/dsr_release.sh");
        let installer = include_str!("../../scripts/install.sh");

        assert!(
            script.contains("ENTITLEMENTS=\"${ROOT}/packaging/macos/sbh.entitlements.plist\""),
            "dsr release must sign with the canonical minimal entitlements file"
        );
        assert!(
            script.contains("darwin_triples=(aarch64-apple-darwin x86_64-apple-darwin)"),
            "dsr release must sign both (and only the) apple-darwin targets"
        );

        // The default signing identity must be the exact authority the
        // installer and updater accept, or every signed release is refused.
        let identity = "Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)";
        assert!(
            script.contains(&format!("IDENTITY=\"${{SBH_SIGN_IDENTITY:-{identity}}}\"")),
            "dsr release default signing identity must be {identity}"
        );
        assert!(
            installer.contains(&format!("Authority={identity}")),
            "installer must require the same Developer ID authority dsr signs with"
        );

        let signed_by = shell_function(script, "signed_by_identity");
        assert!(
            signed_by.contains("codesign -dvv \"$1\"")
                && signed_by.contains("*\"Authority=${IDENTITY}\"*"),
            "signed_by_identity must check the Developer ID authority, got:\n{signed_by}"
        );

        let sign = shell_function(script, "step_sign");
        assert_in_order(
            sign,
            "step_sign must lint the entitlements, sign with Hardened Runtime and a secure timestamp, verify, and check the authority before repacking",
            &[
                "plutil -lint \"${ENTITLEMENTS}\"",
                "for triple in \"${darwin_triples[@]}\"; do",
                "codesign --force --options runtime --timestamp --entitlements \"${ENTITLEMENTS}\"",
                "-s \"${IDENTITY}\" \"${raw}\"",
                "codesign --verify --strict \"${raw}\"",
                "signed_by_identity \"${raw}\" || die",
                "tar -cJf \"${DIR}/${versioned}\"",
                "write_sidecar \"${versioned}\"",
                "write_sidecar \"${legacy}\"",
            ],
        );
        assert!(
            sign.contains("artifact[\"sha256\"] = hashlib.sha256(f.read()).hexdigest()"),
            "step_sign must rewrite the dsr manifest hashes of the re-signed darwin archives"
        );
    }

    #[test]
    fn dsr_release_notarizes_signed_macos_binaries_and_requires_accepted() {
        let script = include_str!("../../scripts/dsr_release.sh");

        assert!(
            script.contains("NOTARY_PROFILE=\"${SBH_NOTARY_PROFILE:-sbh-notary}\""),
            "dsr release must default to the sbh-notary keychain profile that sbh doctor --release checks"
        );

        let notarize = shell_function(script, "step_notarize");
        assert_in_order(
            notarize,
            "step_notarize must refuse unsigned binaries, zip, submit with notarytool, and require Accepted",
            &[
                "for triple in \"${darwin_triples[@]}\"; do",
                "signed_by_identity \"${raw}\" || die",
                "ditto -c -k --keepParent \"${raw}\" \"${zip}\"",
                "xcrun notarytool submit \"${zip}\" --keychain-profile \"${NOTARY_PROFILE}\"",
                "--wait",
                "[ \"${status}\" = \"Accepted\" ] || die",
            ],
        );
    }

    #[test]
    fn dsr_release_runs_steps_in_signing_before_publication_order() {
        let script = include_str!("../../scripts/dsr_release.sh");

        // Package hashes the signed binaries, and the tap must point at what
        // publish uploaded, so this order is load-bearing.
        assert!(
            script.contains(
                "all) for s in sign notarize package minisign publish tap; do \"step_${s}\"; done ;;"
            ),
            "`all` must run sign, notarize, package, minisign, publish, tap in that order"
        );
        assert!(
            script.contains("set -euo pipefail"),
            "dsr release must stop at the first failing command"
        );
    }

    #[test]
    fn dsr_release_publishes_full_asset_set_and_verifies_release() {
        let script = include_str!("../../scripts/dsr_release.sh");

        let package = shell_function(script, "step_package");
        assert!(
            package.contains(
                "scripts/release_gate_and_package.sh\" --package --dir \"${DIR}\" --tag \"${TAG}\""
            ),
            "step_package must build the canonical asset set with the release packager"
        );

        let minisign = shell_function(script, "step_minisign");
        assert!(
            minisign.contains("dsr signing sign /tmp/${base} && dsr signing verify /tmp/${base}")
                && minisign.contains("${base}.minisig"),
            "step_minisign must sign and verify the manifest and fetch its .minisig"
        );

        let publish = shell_function(script, "step_publish");
        assert_in_order(
            publish,
            "step_publish must upload the complete asset set and then verify the published release",
            &[
                "gh release upload \"${TAG}\" --repo \"${REPO}\" --clobber",
                "release-provenance.json SHA256SUMS SHA256SUMS.txt",
                "sbh_darwin_amd64 sbh_darwin_arm64 sbh_linux_amd64 sbh_linux_arm64",
                "sbh-*.tar.xz sbh-*.tar.xz.sha256",
                "\"$(basename \"${MANIFEST}\")\" \"$(basename \"${MANIFEST}\").minisig\"",
                "scripts/release_gate_and_package.sh\" --verify-release \"${TAG}\"",
            ],
        );
        assert!(
            publish.contains("--verify-tag"),
            "step_publish must only create a release for an existing tag"
        );
    }

    #[test]
    fn macos_guide_documents_dsr_release_credentials_and_doctor() {
        let macos_guide = include_str!("../../docs/macos.md");

        for required in [
            "sbh does not use GitHub Actions or any hosted CI for releases",
            "scripts/dsr_release.sh all X.Y.Z",
            "packaging/macos/sbh.entitlements.plist",
            "codesign --force --options runtime --timestamp",
            "codesign --verify --strict",
            "Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)",
            "xcrun notarytool submit --keychain-profile sbh-notary --wait",
            "`Accepted`",
            "login keychain",
            "xcrun notarytool store-credentials sbh-notary",
            "Apple Developer Program enrollment is confirmed",
            "already-enrolled Apple Developer account or team",
            "App Store Connect API key",
            "security find-identity -v -p codesigning",
            "When `APPLE_DEVELOPER_ID_IDENTITY` is exported",
            "exact configured identity must appear",
            "gh repo view Dicklesworthstone/homebrew-sbh --json nameWithOwner,defaultBranchRef",
            "`defaultBranchRef.name`",
            "reports a warning, not a hard failure",
            "Rotate the Developer ID certificate and App Store Connect API key every 12",
            "openssl x509 -noout -enddate",
            "Developer ID Application: Example LLC",
            "non-secret credential setup plan",
            "`$APPLE_NOTARY_KEY_PATH`",
            "Treat `WARN` as an attention state",
            "remains false until every release check passes",
            "aggregate `ok` boolean",
            "`passed`, `warnings`, and",
            "`failed` counts",
            "JSON `setup_steps` field",
        ] {
            assert!(
                macos_guide.contains(required),
                "macOS guide must document the dsr release credential fragment: {required}"
            );
        }

        for retired in [
            "gh secret set",
            "gh workflow run",
            "HOMEBREW_TAP_SSH_KEY",
            "APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64",
            "Developer ID Certificate Expiration",
        ] {
            assert!(
                !macos_guide.contains(retired),
                "macOS guide must not document the retired GitHub Actions release path: {retired}"
            );
        }
    }

    #[test]
    fn docs_update_lint_requires_companion_docs_for_user_facing_changes() {
        let docs_lint = include_str!("../../scripts/ci_docs_update_check.sh");
        let testing_guide = include_str!("../../docs/testing-and-logging.md");

        for required in [
            "src/(main|cli_app)\\.rs",
            "src/core/config\\.rs",
            "src/scanner/(patterns|protection|deletion|scoring)\\.rs",
            "README\\.md",
            "CHANGELOG\\.md",
            "docs/",
            "src/cli_app\\.rs",
            "packaging/homebrew/Formula/sbh\\.rb",
            "DOCS_UPDATE_BASE",
            "DOCS_UPDATE_HEAD",
            "::error::",
            "CLI flag/command annotations changed without added help text",
            "configuration fields changed without a config documentation update",
        ] {
            assert!(
                docs_lint.contains(required),
                "docs update lint must enforce user-facing/doc companion fragment: {required}"
            );
        }

        for required in [
            "scripts/ci_docs_update_check.sh",
            "user-facing source",
            "CLI help text",
            "sample configs",
            "DOCS_UPDATE_BASE=origin/main DOCS_UPDATE_HEAD=HEAD bash scripts/ci_docs_update_check.sh",
        ] {
            assert!(
                testing_guide.contains(required),
                "testing guide must document docs update lint behavior: {required}"
            );
        }
    }

    #[test]
    fn homebrew_formula_skeleton_tracks_release_asset_contract() {
        let formula = include_str!("../../packaging/homebrew/Formula/sbh.rb");

        for required in [
            "class Sbh < Formula",
            "depends_on :macos",
            "on_macos do",
            "on_arm do",
            "on_intel do",
            "releases/download/v0.4.8/",
            "sbh-v0.4.8-aarch64-apple-darwin.tar.xz",
            "sbh-v0.4.8-x86_64-apple-darwin.tar.xz",
            "REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256",
            "REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256",
            "sha256 \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "sha256 \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
            "system bin/\"sbh\", \"setup\", \"--verify\", \"--bin-dir\", bin",
            "run [opt_bin/\"sbh\", \"daemon\"]",
            "keep_alive crashed: true",
            "process_type :background",
            "throttle_interval 60",
            "brew services start sbh",
            "Full Disk Access",
        ] {
            assert!(
                formula.contains(required),
                "Homebrew formula skeleton must include contract fragment: {required}"
            );
        }
    }

    #[test]
    fn homebrew_formula_generation_removes_checksum_markers() {
        let formula = include_str!("../../packaging/homebrew/Formula/sbh.rb");
        let arm_sha = "0".repeat(64);
        let intel_sha = "1".repeat(64);

        let generated = formula
            .replace(
                "      # REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256\n      sha256 \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                &format!("      sha256 \"{arm_sha}\""),
            )
            .replace(
                "      # REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256\n      sha256 \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
                &format!("      sha256 \"{intel_sha}\""),
            );

        assert!(
            !generated.contains("REPLACE_WITH_"),
            "generated Homebrew formula must not retain checksum marker comments"
        );
        assert!(
            generated.contains("sbh-v0.4.8-aarch64-apple-darwin.tar.xz"),
            "generated Homebrew formula must contain the release archive version"
        );
        assert!(
            generated.contains(&format!("sha256 \"{arm_sha}\"")),
            "generated Homebrew formula must contain the aarch64 macOS release checksum"
        );
        assert!(
            generated.contains(&format!("sha256 \"{intel_sha}\"")),
            "generated Homebrew formula must contain the x86_64 macOS release checksum"
        );
    }

    #[test]
    fn dsr_release_renders_homebrew_tap_formula_with_both_checksums() {
        let script = include_str!("../../scripts/dsr_release.sh");

        let render = shell_function(script, "render_formula");
        for required in [
            "s/version \"[^\"]+\"/version \"$ENV{VERSION}\"/;",
            "releases\\/download\\/v$ENV{VERSION}\\/",
            "sbh-v$ENV{VERSION}-",
            "# REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256\\n( *)sha256 \"[0-9a-f]{64}\"/$1sha256 \"$ENV{ARM_SHA}\"/g;",
            "# REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256\\n( *)sha256 \"[0-9a-f]{64}\"/$1sha256 \"$ENV{INTEL_SHA}\"/g;",
            "! grep -q 'REPLACE_WITH_' \"${out}\" || die",
            "grep -q \"releases/download/${TAG}/\" \"${out}\" || die",
            "grep -q \"sha256 \\\"${arm_sha}\\\"\" \"${out}\" || die",
            "grep -q \"sha256 \\\"${intel_sha}\\\"\" \"${out}\" || die",
            "ruby -c \"${out}\"",
        ] {
            assert!(
                render.contains(required),
                "render_formula must include tap rendering fragment: {required}"
            );
        }
    }

    /// Runs the real `render_formula` from `scripts/dsr_release.sh` against
    /// the checked-in formula skeleton. `ruby -c` is stubbed only when the
    /// host has no ruby; the text test above pins that the script runs it.
    #[test]
    fn dsr_release_render_formula_output_pins_version_and_checksums() {
        let script = include_str!("../../scripts/dsr_release.sh");
        let render = shell_function(script, "render_formula");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("sbh.rb");
        let arm_sha = "0".repeat(64);
        let intel_sha = "1".repeat(64);

        let program = format!(
            "set -euo pipefail\n\
             die() {{ echo \"render: $*\" >&2; exit 1; }}\n\
             command -v ruby >/dev/null || ruby() {{ :; }}\n\
             VERSION=9.8.7\nTAG=v9.8.7\n{render}\n\
             render_formula \"$1\" \"$2\" \"$3\" \"$4\"\n"
        );
        let output = Command::new("bash")
            .arg("-c")
            .arg(&program)
            .arg("render")
            .arg(root.join("packaging/homebrew/Formula/sbh.rb"))
            .arg(&out)
            .arg(&arm_sha)
            .arg(&intel_sha)
            .output()
            .expect("bash must be available to run render_formula");
        assert!(
            output.status.success(),
            "render_formula failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let rendered = std::fs::read_to_string(&out).unwrap();
        assert!(!rendered.contains("REPLACE_WITH_"), "{rendered}");
        assert!(!rendered.contains("0.4.8"), "{rendered}");
        assert_eq!(
            rendered.matches("releases/download/v9.8.7/").count(),
            2,
            "both archive URLs must point at the rendered tag:\n{rendered}"
        );
        assert_in_order(
            &rendered,
            "rendered formula must pair each archive with its own checksum",
            &[
                "\"sbh-v9.8.7-aarch64-apple-darwin.tar.xz\"",
                &format!("sha256 \"{arm_sha}\""),
                "\"sbh-v9.8.7-x86_64-apple-darwin.tar.xz\"",
                &format!("sha256 \"{intel_sha}\""),
            ],
        );
    }

    #[test]
    fn dsr_release_tap_refuses_checksums_that_differ_from_published() {
        let script = include_str!("../../scripts/dsr_release.sh");
        let macos_guide = include_str!("../../docs/macos.md");

        assert!(
            script.contains("TAP_REPO=\"${SBH_TAP_REPO:-Dicklesworthstone/homebrew-sbh}\""),
            "dsr release must default to the Dicklesworthstone/homebrew-sbh tap"
        );

        let tap_step = shell_function(script, "step_tap");
        assert_in_order(
            tap_step,
            "step_tap must compare local and published checksums before cloning, rendering and pushing the tap",
            &[
                "for triple in \"${darwin_triples[@]}\"; do",
                "gh release download \"${TAG}\" --repo \"${REPO}\"",
                "[ \"${want}\" = \"${published}\" ] || die",
                "gh repo clone \"${TAP_REPO}\"",
                "render_formula \"${ROOT}/packaging/homebrew/Formula/sbh.rb\" \"${tap}/Formula/sbh.rb\" \"${arm_sha}\" \"${intel_sha}\"",
                "git push -q origin HEAD:main",
            ],
        );

        for required in [
            "Dicklesworthstone/homebrew-sbh",
            "packaging/homebrew/Formula/sbh.rb",
            "scripts/dsr_release.sh tap",
            "tap update",
            "published checksums",
        ] {
            assert!(
                macos_guide.contains(required),
                "macOS guide must explain the dsr tap update fragment: {required}"
            );
        }
    }

    #[test]
    fn macos_manual_release_fallback_docs_require_fresh_artifacts_and_approval() {
        let macos_guide = include_str!("../../docs/macos.md");

        for required in [
            "Manual Release Fallback",
            "operator has explicitly approved publishing outside the dsr path",
            "`scripts/dsr_release.sh publish` runs the same",
            "publish from chat notes",
            "historical provenance",
            "missing `/tmp` directory",
            "release-work/storage_ballast_helper/releases",
            "same nightly Rust toolchain and feature set as",
            "cargo +nightly build $CI_FEATURES --release --target aarch64-apple-darwin",
            "cargo +nightly build $CI_FEATURES --release --target x86_64-apple-darwin",
            "cross +nightly build $CI_FEATURES --release --target aarch64-unknown-linux-gnu",
            "cargo +nightly build $CI_FEATURES --release --target x86_64-unknown-linux-gnu",
            "sbh-${TAG}-aarch64-apple-darwin.tar.xz",
            "sbh-${TAG}-x86_64-apple-darwin.tar.xz",
            "sbh-${TAG}-aarch64-unknown-linux-gnu.tar.xz",
            "sbh-${TAG}-x86_64-unknown-linux-gnu.tar.xz",
            "SHA256SUMS.txt",
            "release-provenance.json",
            "rustc +nightly --version",
            "ticketContents",
            "shasum -a 256 -c SHA256SUMS.txt",
            "sbh doctor --release --json",
            "gh release view \"$TAG\" -R Dicklesworthstone/storage_ballast_helper",
            "Publication is the irreversible handoff point",
            "brew fetch",
            "brew audit",
            "brew install",
            "brew test",
        ] {
            assert!(
                macos_guide.contains(required),
                "macOS guide must document manual release fallback safety fragment: {required}"
            );
        }
    }

    fn linux_amd64_contract(tag: &str) -> ReleaseArtifactContract {
        ReleaseArtifactContract {
            repository: "Dicklesworthstone/storage_ballast_helper",
            binary_name: "sbh",
            locator: ReleaseLocator::Tag(tag.to_string()),
            target: ArtifactTarget {
                triple: "x86_64-unknown-linux-gnu",
                archive: ArchiveFormat::TarXz,
            },
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn raw_binary_names_follow_the_hand_published_scheme() {
        let mut contract = linux_amd64_contract("v0.5.1");
        assert_eq!(
            contract.raw_binary_name().as_deref(),
            Some("sbh_linux_amd64")
        );
        contract.target.triple = "aarch64-unknown-linux-gnu";
        assert_eq!(
            contract.raw_binary_name().as_deref(),
            Some("sbh_linux_arm64")
        );
        contract.target.triple = "x86_64-apple-darwin";
        assert_eq!(
            contract.raw_binary_name().as_deref(),
            Some("sbh_darwin_amd64")
        );
        contract.target.triple = "aarch64-apple-darwin";
        assert_eq!(
            contract.raw_binary_name().as_deref(),
            Some("sbh_darwin_arm64")
        );
        contract.target.triple = "riscv64gc-unknown-linux-gnu";
        assert_eq!(
            contract.raw_binary_name(),
            None,
            "unknown arch has no raw spelling"
        );
    }

    /// The exact asset lists of three real releases (`gh release view --json
    /// assets`): the workflow layout, the hand-published raw layout, and a
    /// mixed one. The updater must resolve all of them instead of guessing.
    #[test]
    fn release_asset_resolution_matches_the_published_layouts() {
        // v0.4.28: workflow layout (tarballs + sidecars + provenance).
        let contract = linux_amd64_contract("v0.4.28");
        let v0_4_28 = names(&[
            "sbh-v0.4.28-aarch64-apple-darwin.tar.xz",
            "sbh-v0.4.28-aarch64-apple-darwin.tar.xz.sha256",
            "sbh-v0.4.28-x86_64-unknown-linux-gnu.tar.xz",
            "sbh-v0.4.28-x86_64-unknown-linux-gnu.tar.xz.sha256",
            "SHA256SUMS.txt",
            "release-provenance.json",
        ]);
        let resolved = contract
            .resolve_release_asset("v0.4.28", &v0_4_28)
            .expect("workflow layout resolves");
        assert_eq!(resolved.layout, ReleaseAssetLayout::VersionedArchive);
        assert_eq!(
            resolved.asset_name,
            "sbh-v0.4.28-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            resolved.checksum_name,
            "sbh-v0.4.28-x86_64-unknown-linux-gnu.tar.xz.sha256"
        );
        assert!(resolved.is_archive && !resolved.checksum_is_manifest);

        // v0.5.1: hand-published raw binaries + one aggregate SHA256SUMS.
        let contract = linux_amd64_contract("v0.5.1");
        let v0_5_1 = names(&[
            "sbh_darwin_amd64",
            "sbh_darwin_arm64",
            "sbh_linux_amd64",
            "sbh_linux_arm64",
            "SHA256SUMS",
        ]);
        let resolved = contract
            .resolve_release_asset("v0.5.1", &v0_5_1)
            .expect("raw layout resolves");
        assert_eq!(resolved.layout, ReleaseAssetLayout::RawBinary);
        assert_eq!(resolved.asset_name, "sbh_linux_amd64");
        assert_eq!(resolved.checksum_name, RAW_CHECKSUM_MANIFEST);
        assert!(!resolved.is_archive && resolved.checksum_is_manifest);
        assert_eq!(
            contract.asset_url_for_tag_and_name("v0.5.1", &resolved.asset_name),
            "https://github.com/Dicklesworthstone/storage_ballast_helper/releases/download/v0.5.1/sbh_linux_amd64"
        );

        // v0.4.40: legacy unversioned tarball alongside a typo'd mirror.
        let contract = linux_amd64_contract("v0.4.40");
        let v0_4_40 = names(&[
            "sbh",
            "sbh.sha256",
            "sbh-aarch64-apple-darwin.tar.xz",
            "sbh-aarch64-apple-darwin.tar.xz.sha256",
            "sbh-x86_64-unknown-linux-gnu.tar.xz",
            "sbh-x86_64-unknown-linux-gnu.tar.xz.sha256",
            "sbh-vx86_64-unknown-linux-gnu.tar.xz",
            "SHA256SUMS",
        ]);
        let resolved = contract
            .resolve_release_asset("v0.4.40", &v0_4_40)
            .expect("legacy layout resolves");
        assert_eq!(resolved.layout, ReleaseAssetLayout::LegacyArchive);
        assert_eq!(resolved.asset_name, "sbh-x86_64-unknown-linux-gnu.tar.xz");

        // A tarball without its sidecar is not resolvable (checksum mandatory).
        let missing_sidecar = names(&["sbh-v0.4.28-x86_64-unknown-linux-gnu.tar.xz"]);
        assert_eq!(
            linux_amd64_contract("v0.4.28").resolve_release_asset("v0.4.28", &missing_sidecar),
            None
        );
        assert_eq!(
            linux_amd64_contract("v9").resolve_release_asset("v9", &[]),
            None
        );
    }

    #[test]
    fn sha256_from_manifest_accepts_gnu_binary_and_bsd_forms() {
        let digest_a = "a".repeat(64);
        let digest_b = "B".repeat(64);
        let digest_c = "c".repeat(64);
        let manifest = format!(
            "{digest_a}  sbh_darwin_amd64\n{digest_b} *sbh_linux_amd64\nSHA256 (sbh_linux_arm64) = {digest_c}\n\nnot a checksum line\n"
        );
        assert_eq!(
            sha256_from_manifest(&manifest, "sbh_darwin_amd64").as_deref(),
            Some(digest_a.as_str())
        );
        assert_eq!(
            sha256_from_manifest(&manifest, "sbh_linux_amd64").as_deref(),
            Some(digest_b.to_ascii_lowercase().as_str()),
            "binary-mode marker and uppercase hex are normalized"
        );
        assert_eq!(
            sha256_from_manifest(&manifest, "sbh_linux_arm64").as_deref(),
            Some(digest_c.as_str())
        );
        assert_eq!(sha256_from_manifest(&manifest, "sbh_windows_amd64"), None);
        assert_eq!(
            sha256_from_manifest("deadbeef  sbh_linux_amd64\n", "sbh_linux_amd64"),
            None,
            "a short digest is rejected"
        );
    }

    #[test]
    fn repository_toolchain_pins_nightly_for_release_contracts() {
        let toolchain = include_str!("../../rust-toolchain.toml");

        let channel = toolchain
            .lines()
            .find_map(|line| line.trim().strip_prefix("channel = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("rust-toolchain.toml must declare a channel");
        assert!(
            channel.starts_with("nightly"),
            "release and CI provenance contracts require the repository toolchain to pin nightly, got {channel}"
        );
        // A bare `nightly` re-resolves on every rustup update, which is how
        // clippy drift broke the lint gate twice in August 2026; the channel
        // must carry a date so a toolchain bump is a deliberate commit.
        assert!(
            channel.len() > "nightly-".len() && channel[8..].split('-').count() == 3,
            "toolchain channel must be a dated nightly (nightly-YYYY-MM-DD), got {channel}"
        );
        assert!(
            !toolchain.contains("channel = \"stable\""),
            "stable must not be the repository default toolchain"
        );
    }

    #[test]
    fn macos_completion_audit_maps_goal_to_evidence() {
        let audit = include_str!("../../docs/internal/macos-parity-completion-audit.md");

        for required in [
            "Prompt-To-Artifact Completion Audit",
            "bd-r7m7",
            "bd-r7m7.15",
            "bd-r7m7.16",
            "bd-ykwh",
            "bd-ykwh.20",
            "release CI verified Apple notary log",
            "`scripts/dsr_release.sh notarize` now",
            "requires notarytool status `Accepted`",
            "avoids pinning exact commit hashes",
            "GitHub Actions run ids",
            "git rev-parse HEAD",
            "gh run list --repo Dicklesworthstone/storage_ballast_helper",
            "gh run view <latest-run>",
            "macos_launchd_user_service_lifecycle_bootstrap_kickstart_bootout",
            "macos_status_json_matches_diskutil_apfs_capacity",
            "macos_synthetic_writer_surfaces_in_blame_top_rows",
            "scanner_prescan_does_not_dispatch_protected_rust_fuzz_target",
            "executor_preflight_skips_config_protected_daemon_candidate",
            "macos-platform",
            "macos-15-intel",
            "Do not treat queued CI as",
            "one valid local",
            "notary log ticketContents",
            "sbh-notary",
            "HOMEBREW_TAP_SSH_KEY",
            "sbh doctor --release --json",
            "aggregate `ok` boolean",
            "`passed`,",
            "`warnings`,",
            "`failed` counts",
            "Developer ID Application",
        ] {
            assert!(
                audit.contains(required),
                "macOS parity audit must map completion evidence or blocker fragment: {required}"
            );
        }
    }

    #[test]
    fn macos_incident_case_study_tracks_operator_numbers() {
        let case_study = include_str!("../../docs/macos-incident-case-study.md");
        let readme = include_str!("../../README.md");
        let macos_guide = include_str!("../../docs/macos.md");

        for required in [
            "sbh saved my Mac from the brink",
            "2026-05-03",
            "147 MB free",
            "1.95 TB",
            "/private/tmp/frankenterm-trash-20260503-092725",
            "264 GB",
            "~/Library/Application Support/Claude/vm_bundles/claudevm.bundle",
            "9.8 GB",
            "/private/tmp/ft-*-target",
            "about 330 GB",
            "~/release-work/mcp_agent_mail_rust_buildroot",
            "39 GB",
            "Active `/private/tmp/ft-*-target` directories should remain protected",
            "sacred-overlap reason",
            "SBH-1101 unsupported platform",
            "docs/cleanup-rules-macos.md",
            "docs/migrating-from-other-tools.md",
        ] {
            assert!(
                case_study.contains(required),
                "macOS incident case study must preserve concrete operator evidence: {required}"
            );
        }

        for linked_doc in [readme, macos_guide] {
            assert!(
                linked_doc.contains("docs/macos-incident-case-study.md"),
                "macOS incident case study must be discoverable from README and macOS guide"
            );
        }
    }

    #[test]
    fn macos_full_disk_access_walkthrough_has_screenshot_refresh_policy() {
        let fda_doc = include_str!("../../docs/macos-full-disk-access.md");
        let image_manifest = include_str!("../../docs/images/macos/README.md");
        let readme = include_str!("../../README.md");

        for required in [
            "text walkthrough is authoritative",
            "Do not generate or mock screenshots",
            "macOS major release",
            "within 30 days",
            "full-disk-access-privacy-security.png",
            "full-disk-access-pane.png",
            "full-disk-access-sbh-enabled.png",
            "required alt text",
            "docs/images/macos/README.md",
        ] {
            assert!(
                fda_doc.contains(required) || image_manifest.contains(required),
                "Full Disk Access screenshot policy must include fragment: {required}"
            );
        }

        for required in [
            "sbh doctor --pal",
            "full_disk_access_status",
            "docs/macos-full-disk-access.md",
            "docs/images/macos/README.md",
        ] {
            assert!(
                fda_doc.contains(required) || readme.contains(required),
                "Full Disk Access walkthrough must remain discoverable and verifiable: {required}"
            );
        }
    }

    #[test]
    fn readme_platform_sections_stay_cross_platform() {
        let readme = include_str!("../../README.md");
        let notifications = include_str!("../daemon/notifications.rs");

        for required in [
            "systemd/launchd stdout and stderr capture",
            "The registry asks the active Platform Abstraction Layer (PAL) for mount inventory.",
            "Linux reads `/proc/mounts`; macOS uses its PAL mount inventory from `statfs`/`getmntinfo` and APFS metadata.",
            "The daemon samples its own RSS through the PAL `self_stats()` method on each state file write.",
            "Linux uses `/proc/self` data; macOS uses Mach task and libproc resource usage.",
            "LinuxPal (procfs/statvfs), MacOsPal (statfs/APFS/libproc)",
        ] {
            assert!(
                readme.contains(required),
                "README platform section must document cross-platform fragment: {required}"
            );
        }

        for required in [
            "systemd journals and launchd",
            "stdout/stderr capture both receive the same operator-visible events",
            "Journal/service log (structured stderr)",
            "systemd captures stderr in the journal, while launchd captures it in",
            "StandardErrorPath",
        ] {
            assert!(
                notifications.contains(required),
                "notification source docs must keep journal channel platform-neutral: {required}"
            );
        }

        for stale in [
            "auto-discovers RAM-backed mounts from `/proc/mounts`",
            "reads its own RSS (Resident Set Size) from `/proc/self/statm`",
            "Platform abstraction (Linux: procfs, statvfs, mounts)",
            "Journal notification settings (systemd journal via stderr)",
            "Journal (systemd structured stderr)",
            "systemd captures stderr and annotates with PRIORITY via SyslogIdentifier",
        ] {
            assert!(
                !readme.contains(stale) && !notifications.contains(stale),
                "platform docs retained stale Linux-only wording: {stale}"
            );
        }
    }

    #[test]
    fn macos_cleanup_rules_doc_covers_catalog_contract() {
        let doc = include_str!("../../docs/cleanup-rules-macos.md");

        for required in [
            "xcode-derived-data",
            "~/Library/Developer/Xcode/DerivedData/*",
            "core-simulator-caches",
            "~/Library/Developer/CoreSimulator/Caches/*",
            "electron-cache",
            "electron-cache-root",
            "electron-service-worker-cache",
            "electron-service-worker-cache-root",
            "electron-code-cache",
            "electron-code-cache-root",
            "electron-gpu-cache",
            "electron-gpu-cache-root",
            "electron-indexed-db",
            "electron-indexed-db-root",
            "electron-vm-bundles",
            "electron-vm-bundles-root",
            "tmp-dash-target",
            "/private/tmp/*-target",
            "tmp-underscore-target",
            "/private/tmp/*_target",
            "tmp-target-underscore-prefix",
            "/private/tmp/target_*",
            "user-named-trash-exact",
            "user-named-trashed-exact",
            "user-named-trash",
            "release-work-buildroot",
            "~/release-work/*[-_]buildroot",
            "user-logs",
            "~/Library/Logs/*",
            "ipsw-software-updates",
            "~/Library/iTunes/iPhone Software Updates/*.ipsw",
            "home-trash-report",
            "icloud-trash-report",
            "time-machine-local-snapshots",
            "spotlight-index-report",
            "photos-library-sacred",
            "mail-library-sacred",
            "messages-library-sacred",
            "final-cut-library-sacred",
            "RemoveTree",
            "RemoveMatchingFiles",
            "ThinLocalSnapshots",
            "PromptBeforeRemove",
            "ReportOnly",
            "Refuse",
            "Definite",
            "Likely",
            "Unclear",
            "Sacred",
            ".sbh-protect",
            "scanner.protected_paths",
            "docs/sacred-paths.md",
            "sbh scan /private/tmp --show-protected",
            "sbh protect --list",
        ] {
            assert!(
                doc.contains(required),
                "macOS cleanup rules trust doc must include catalog/safety fragment: {required}"
            );
        }
    }

    #[test]
    fn macos_migration_doc_covers_common_cleanup_tools() {
        let doc = include_str!("../../docs/migrating-from-other-tools.md");
        let readme = include_str!("../../README.md");
        let macos_guide = include_str!("../../docs/macos.md");

        for required in [
            "CleanMyMac",
            "OmniDiskSweeper",
            "DaisyDisk",
            "GrandPerspective",
            "continuous disk-pressure guard",
            "ballast",
            "protected paths",
            ".sbh-protect",
            "scanner.protected_paths",
            "visual treemap",
            "app maintenance suite",
            "sbh install --auto",
            "sbh doctor --pal",
            "sbh clean /Users/me/Projects --dry-run",
            "sbh clean --thin-local-snapshots --dry-run",
            "docs/cleanup-rules-macos.md",
            "docs/sacred-paths.md",
            "docs/macos-full-disk-access.md",
            "docs/launchd-troubleshooting.md",
        ] {
            assert!(
                doc.contains(required),
                "macOS migration doc must include comparison/setup fragment: {required}"
            );
        }

        for linked_doc in [readme, macos_guide] {
            assert!(
                linked_doc.contains("docs/migrating-from-other-tools.md"),
                "macOS migration doc must be discoverable from README and macOS guide"
            );
        }
    }

    #[test]
    fn macos_sample_configs_parse_and_remain_discoverable() {
        let samples = [
            (
                "developer",
                "docs/configs/developer-mac.toml",
                include_str!("../../docs/configs/developer-mac.toml"),
                &[
                    "/Users/me/Projects",
                    "/Users/me/Library/Developer/Xcode/DerivedData",
                    "/private/tmp",
                    "client-*",
                ][..],
            ),
            (
                "creative",
                "docs/configs/creative-mac.toml",
                include_str!("../../docs/configs/creative-mac.toml"),
                &[
                    "/Users/me/Creative Scratch",
                    "Photos Library.photoslibrary",
                    "*.fcpbundle",
                    "dry_run = true",
                ][..],
            ),
            (
                "shared",
                "docs/configs/shared-mac-launchdaemon.toml",
                include_str!("../../docs/configs/shared-mac-launchdaemon.toml"),
                &[
                    "sudo sbh install --launchd --scope system --auto",
                    "/Users",
                    "/Users/*/.ssh/*",
                    "parallelism = 6",
                ][..],
            ),
        ];

        for (name, path, raw, required_fragments) in samples {
            let mut sample = NamedTempFile::new()
                .unwrap_or_else(|error| panic!("create temp config for {name}: {error}"));
            sample
                .write_all(raw.as_bytes())
                .unwrap_or_else(|error| panic!("write temp config for {name}: {error}"));
            crate::core::config::Config::load(Some(sample.path()))
                .unwrap_or_else(|error| panic!("{path} must load as a valid sbh config: {error}"));

            for required in required_fragments {
                assert!(
                    raw.contains(required),
                    "{path} missing required scenario fragment: {required}"
                );
            }
        }

        let readme = include_str!("../../README.md");
        let macos_guide = include_str!("../../docs/macos.md");
        for linked_doc in [readme, macos_guide] {
            assert!(
                linked_doc.contains("docs/configs/"),
                "Mac sample config directory must be linked from README and macOS guide"
            );
        }
    }

    #[test]
    fn changelog_unreleased_macos_entries_include_concrete_savings_examples() {
        let changelog = include_str!("../../CHANGELOG.md");
        let unreleased = changelog
            .split("## [v0.4.6]")
            .next()
            .expect("CHANGELOG must contain an Unreleased section before v0.4.6");

        for required in [
            "### macOS",
            "before/after space-recovery cases",
            "12 GB Xcode DerivedData",
            "24 hours",
            "~/Library/Developer/Xcode/DerivedData/",
            "64 GB Time Machine local snapshot",
            "sudo tmutil thinlocalsnapshots / 9999999999999999 4",
            "Electron caches",
            "Cache",
            "Code Cache",
            "GPUCache",
            "IndexedDB",
            "Service Worker/CacheStorage",
            "vm_bundles",
            "8 GB app cache",
            "~/release-work/*[-_]buildroot",
            "7 days",
            "mcp_agent_mail_rust_buildroot",
            "11 days",
            "39 GB",
            "docs/cleanup-rules-macos.md",
            "docs/macos.md",
            "Full Disk Access",
        ] {
            assert!(
                unreleased.contains(required),
                "Unreleased CHANGELOG macOS entry must include concrete operator detail: {required}"
            );
        }
    }

    #[test]
    fn release_packager_packages_exactly_the_release_targets() {
        let packager = include_str!("../../scripts/release_gate_and_package.sh");
        let block = workflow_block(packager, "\nTARGETS=(\n", "\n)\n");
        let listed_targets: Vec<&str> = block
            .lines()
            .skip(2)
            .map(|line| line.trim().trim_matches('"'))
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            listed_targets, CI_RELEASE_TARGETS,
            "scripts/release_gate_and_package.sh TARGETS must match CI_RELEASE_TARGETS exactly"
        );

        let script = include_str!("../../scripts/dsr_release.sh");
        let darwin: Vec<&str> = CI_RELEASE_TARGETS
            .iter()
            .copied()
            .filter(|triple| triple.ends_with("-apple-darwin"))
            .collect();
        for triple in darwin {
            assert!(
                script.contains(&format!("{triple})")),
                "dsr release must map {triple} to its raw darwin binary for signing"
            );
        }
    }

    #[test]
    fn ci_release_targets_resolve_to_valid_contracts() {
        // Every CI target triple must produce a valid ReleaseArtifactContract
        // with the expected asset naming scheme: sbh-{tag}-{target}.tar.xz
        for triple in CI_RELEASE_TARGETS {
            // Parse the triple to find the matching host specifier.
            let (os, arch, abi) = match *triple {
                "x86_64-unknown-linux-gnu" => ("linux", "x86_64", Some("gnu")),
                "aarch64-unknown-linux-gnu" => ("linux", "aarch64", Some("gnu")),
                "x86_64-apple-darwin" => ("macos", "x86_64", None),
                "aarch64-apple-darwin" => ("macos", "aarch64", None),
                other => panic!("unknown CI target: {other}"),
            };

            let host = HostSpecifier::from_parts(os, arch, abi).unwrap();
            let contract =
                resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("v0.4.6"))
                    .unwrap();

            assert_eq!(contract.target.triple, *triple);
            assert_eq!(contract.binary_name, RELEASE_BINARY_NAME);
            assert_eq!(contract.repository, RELEASE_REPOSITORY);

            // Verify naming contract matches installer expectation.
            let expected_asset = format!("sbh-v0.4.6-{triple}.tar.xz");
            assert_eq!(contract.asset_name(), expected_asset);
            assert_eq!(contract.checksum_name(), format!("{expected_asset}.sha256"));

            // Validate contract round-trips through validation.
            let assets = contract.expected_release_assets().to_vec();
            assert!(validate_release_assets(&contract, &assets).is_ok());
        }
    }

    #[test]
    fn macos_release_targets_use_separate_versioned_tarballs() {
        let x86 = HostSpecifier::from_parts("macos", "x86_64", None).unwrap();
        let arm = HostSpecifier::from_parts("macos", "aarch64", None).unwrap();

        let x86_contract =
            resolve_installer_artifact_contract(x86, ReleaseChannel::Stable, Some("v1.2.3"))
                .unwrap();
        let arm_contract =
            resolve_installer_artifact_contract(arm, ReleaseChannel::Stable, Some("v1.2.3"))
                .unwrap();

        assert_eq!(
            x86_contract.asset_name(),
            "sbh-v1.2.3-x86_64-apple-darwin.tar.xz"
        );
        assert_eq!(
            arm_contract.asset_name(),
            "sbh-v1.2.3-aarch64-apple-darwin.tar.xz"
        );
        assert_ne!(x86_contract.asset_name(), arm_contract.asset_name());
        assert!(!x86_contract.asset_name().contains("universal"));
        assert!(!arm_contract.asset_name().contains("universal"));
        assert!(!x86_contract.asset_name().contains("fat"));
        assert!(!arm_contract.asset_name().contains("fat"));
    }

    #[test]
    fn unix_installer_prefers_versioned_macos_release_tarballs() {
        let installer = include_str!("../../scripts/install.sh");

        for required in [
            "x86_64) TARGET_TRIPLE=\"x86_64-apple-darwin\"",
            "arm64|aarch64) TARGET_TRIPLE=\"aarch64-apple-darwin\"",
            "versioned_archive_name=\"${PROGRAM}-${RELEASE_LOCATOR}-${TARGET_TRIPLE}.tar.xz\"",
            "grep -E \"^${PROGRAM}-v[0-9][A-Za-z0-9._-]*-${TARGET_TRIPLE}[.]tar[.]xz$\"",
            "CHECKSUM_NAME=\"$versioned_archive_checksum\"",
            "ASSET_URL=\"${base_url}/${ASSET_NAME}\"",
            "CHECKSUM_URL=\"${base_url}/${CHECKSUM_NAME}\"",
            "# Probe strategy 2: legacy unversioned .tar.xz archive.",
            "# Probe strategy 3: raw binary",
            "verify_macos_binary_trust \"$binary_path\"",
        ] {
            assert!(
                installer.contains(required),
                "Unix installer must preserve macOS release asset contract fragment: {required}"
            );
        }

        let versioned = installer
            .find("# Probe strategy 1: versioned .tar.xz archive.")
            .expect("installer must probe versioned release archives");
        let legacy = installer
            .find("# Probe strategy 2: legacy unversioned .tar.xz archive.")
            .expect("installer must retain legacy archive fallback after current contract");
        let raw = installer
            .find("# Probe strategy 3: raw binary")
            .expect("installer must retain raw binary fallback after archive contracts");
        assert!(
            versioned < legacy && legacy < raw,
            "installer must prefer current versioned archives before legacy/raw fallbacks"
        );
    }

    #[test]
    fn unix_installer_verifies_macos_binary_trust_before_install() {
        let installer = include_str!("../../scripts/install.sh");
        let readme = include_str!("../../README.md");
        let macos_guide = include_str!("../../docs/macos.md");

        for required in [
            "is_macos_target()",
            "[[ \"${TARGET_TRIPLE:-}\" == *-apple-darwin ]]",
            "start_phase \"verify_macos_trust\"",
            "command -v codesign",
            "codesign --verify --strict --verbose=2 \"$binary_path\"",
            "codesign --display --verbose=4 \"$binary_path\"",
            "Authority=Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)",
            "TeamIdentifier=AU8V2Z6NKY",
            "macOS code signature verification failed",
            "macOS release binary was not signed by the expected Developer ID Application identity",
            "finish_phase \"macOS Developer ID signature verified\"",
        ] {
            assert!(
                installer.contains(required),
                "Unix installer must enforce macOS binary trust fragment: {required}"
            );
        }

        let trust_check = installer
            .find("verify_macos_binary_trust \"$binary_path\"")
            .expect("installer must call the macOS trust verifier");
        let install_phase = installer
            .find("start_phase \"install_binary\" \"installing sbh binary\"")
            .expect("installer must retain install phase");
        assert!(
            trust_check < install_phase,
            "installer must verify macOS binary trust before installing the binary"
        );

        for required in [
            "codesign --verify --strict --verbose=2",
            "codesign --display --verbose=4",
            "Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)",
            "The explicit `sbh install --no-verify` or",
            "`sbh update --no-verify` flags bypass these",
            "installer trust checks",
        ] {
            assert!(
                macos_guide.contains(required),
                "macOS guide must document installer trust check fragment: {required}"
            );
        }

        for required in [
            "Skip artifact verification, including macOS trust checks",
            "macOS binary trust checks",
            "codesign --verify --strict --verbose=2",
            "Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)",
            "including checksum, signature, and macOS trust checks",
        ] {
            assert!(
                readme.contains(required),
                "README must document installer trust check fragment: {required}"
            );
        }
    }

    #[test]
    fn unix_installer_syncs_existing_platform_service_binary() {
        let installer = include_str!("../../scripts/install.sh");

        for required in [
            "sync_systemd_service()",
            "sync_launchd_service()",
            "Linux) sync_systemd_service",
            "Darwin) sync_launchd_service",
            "launchd_labels_for_sync()",
            "SBH_LAUNCHD_LABEL",
            "com.sbh.daemon",
            "${HOME}/Library/LaunchAgents/${candidate_label}.plist",
            "/Library/LaunchDaemons/${candidate_label}.plist",
            "launchd_plist_binary",
            "ProgramArguments<\\/key>",
            "launchctl kickstart -k",
            "sudo launchctl kickstart -k",
        ] {
            assert!(
                installer.contains(required),
                "Unix installer must preserve cross-platform service sync fragment: {required}"
            );
        }
    }

    #[test]
    fn ci_release_targets_are_not_empty() {
        assert!(
            !CI_RELEASE_TARGETS.is_empty(),
            "CI_RELEASE_TARGETS must contain at least one target"
        );
    }

    #[test]
    fn ci_release_targets_have_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for target in CI_RELEASE_TARGETS {
            assert!(seen.insert(target), "duplicate CI target: {target}");
        }
    }

    #[test]
    fn resolves_bundle_contract_for_current_target() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };

        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();
        let archive = expected.asset_name();
        let checksum = expected.checksum_name();
        let sigstore = expected.sigstore_bundle_name();

        std::fs::write(tmp.path().join(&archive), b"archive").unwrap();
        std::fs::write(tmp.path().join(&checksum), b"checksum").unwrap();
        std::fs::write(tmp.path().join(&sigstore), b"{}").unwrap();

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive: archive.clone(),
                checksum: checksum.clone(),
                sigstore_bundle: Some(sigstore.clone()),
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let resolved = resolve_bundle_artifact_contract(host, &manifest_path).unwrap();
        assert_eq!(resolved.contract.target, expected.target);
        assert_eq!(
            resolved.contract.locator,
            ReleaseLocator::Tag(String::from("v0.9.1"))
        );
        assert_eq!(resolved.archive_path, tmp.path().join(&archive));
        assert_eq!(resolved.checksum_path, tmp.path().join(&checksum));
        assert_eq!(
            resolved.sigstore_bundle_path,
            Some(tmp.path().join(&sigstore))
        );
    }

    #[test]
    fn bundle_contract_rejects_mismatched_archive_name() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive: "wrong.tar.xz".to_string(),
                checksum: expected.checksum_name(),
                sigstore_bundle: None,
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = resolve_bundle_artifact_contract(host, &manifest_path).unwrap_err();
        assert_eq!(err.code(), "SBH-1001");
        assert!(err.to_string().contains("bundle archive mismatch"));
    }

    #[test]
    fn bundle_contract_requires_existing_files() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();
        let archive = expected.asset_name();
        let checksum = expected.checksum_name();

        // Only archive exists; checksum is intentionally missing.
        std::fs::write(tmp.path().join(&archive), b"archive").unwrap();

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive,
                checksum,
                sigstore_bundle: None,
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = resolve_bundle_artifact_contract(host, &manifest_path).unwrap_err();
        assert_eq!(err.code(), "SBH-3900");
        assert!(err.to_string().contains("bundle checksum"));
    }

    #[test]
    fn bundle_contract_accepts_nested_relative_paths() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();
        let archive_name = expected.asset_name();
        let checksum_name = expected.checksum_name();

        let archive_rel = format!("artifacts/{archive_name}");
        let checksum_rel = format!("checksums/{checksum_name}");
        let archive_path = tmp.path().join(&archive_rel);
        let checksum_path = tmp.path().join(&checksum_rel);
        std::fs::create_dir_all(archive_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(checksum_path.parent().unwrap()).unwrap();
        std::fs::write(&archive_path, b"archive").unwrap();
        std::fs::write(&checksum_path, b"checksum").unwrap();

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive: archive_rel,
                checksum: checksum_rel,
                sigstore_bundle: None,
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let resolved = resolve_bundle_artifact_contract(host, &manifest_path).unwrap();
        assert_eq!(resolved.archive_path, archive_path);
        assert_eq!(resolved.checksum_path, checksum_path);
    }

    #[test]
    fn bundle_contract_rejects_parent_dir_escape() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive: format!("../{}", expected.asset_name()),
                checksum: expected.checksum_name(),
                sigstore_bundle: None,
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = resolve_bundle_artifact_contract(host, &manifest_path).unwrap_err();
        assert_eq!(err.code(), "SBH-1001");
        assert!(err.to_string().contains("cannot contain '..'"));
    }

    #[test]
    fn bundle_contract_rejects_unsupported_manifest_version() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
            abi: HostAbi::Gnu,
        };
        let expected =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();
        let archive = expected.asset_name();
        let checksum = expected.checksum_name();
        std::fs::write(tmp.path().join(&archive), b"archive").unwrap();
        std::fs::write(tmp.path().join(&checksum), b"checksum").unwrap();

        let manifest = OfflineBundleManifest {
            version: "2".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: "0.9.1".to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: expected.target.triple.to_string(),
                archive,
                checksum,
                sigstore_bundle: None,
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = resolve_bundle_artifact_contract(host, &manifest_path).unwrap_err();
        assert_eq!(err.code(), "SBH-1001");
        assert!(
            err.to_string()
                .contains("unsupported bundle manifest version")
        );
    }
}
