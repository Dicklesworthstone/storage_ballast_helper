//! CLI contracts shared by installer and updater command paths.
#![allow(missing_docs)]

pub mod assets;
pub mod bootstrap;
#[cfg(feature = "tui")]
pub mod dashboard;
pub mod from_source;
pub mod install;
pub mod integrations;
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical GitHub repository for release artifacts.
pub const RELEASE_REPOSITORY: &str = "Dicklesworthstone/storage_ballast_helper";

/// Canonical binary name used in release artifact names.
pub const RELEASE_BINARY_NAME: &str = "sbh";

/// CI/CD target triples built and published in release workflows.
///
/// The release.yml matrix MUST match this list exactly. Tests in this module
/// validate the contract: every CI target resolves to a valid artifact, and
/// the naming scheme matches what the installer expects.
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

impl ReleaseArtifactContract {
    #[must_use]
    pub fn asset_name(&self) -> String {
        format!(
            "{}-{}.{}",
            self.binary_name,
            self.target.triple,
            self.target.archive.extension()
        )
    }

    #[must_use]
    pub fn checksum_name(&self) -> String {
        format!("{}.sha256", self.asset_name())
    }

    #[must_use]
    pub fn sigstore_bundle_name(&self) -> String {
        format!("{}.sigstore.json", self.asset_name())
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
                "https://github.com/{}/releases/latest/download/{asset}",
                self.repository
            ),
            ReleaseLocator::Tag(tag) => {
                format!(
                    "https://github.com/{}/releases/download/{tag}/{asset}",
                    self.repository
                )
            }
        }
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
    Ok(format!("{digest:x}"))
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

        assert_eq!(contract.asset_name(), "sbh-x86_64-unknown-linux-gnu.tar.xz");
        assert_eq!(
            contract.checksum_name(),
            "sbh-x86_64-unknown-linux-gnu.tar.xz.sha256"
        );
        assert_eq!(
            contract.sigstore_bundle_name(),
            "sbh-x86_64-unknown-linux-gnu.tar.xz.sigstore.json"
        );
        assert_eq!(
            contract.asset_url(),
            "https://github.com/Dicklesworthstone/storage_ballast_helper/releases/download/v0.1.0/sbh-x86_64-unknown-linux-gnu.tar.xz"
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
                .contains("missing assets [sbh-x86_64-pc-windows-msvc.zip.sigstore.json]")
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
        assert!(!outcome.warnings.is_empty());
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
        format!("{digest:x}")
    }

    #[test]
    fn ci_release_targets_resolve_to_valid_contracts() {
        // Every CI target triple must produce a valid ReleaseArtifactContract
        // with the expected asset naming scheme: sbh-{target}.tar.xz
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
                resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();

            assert_eq!(contract.target.triple, *triple);
            assert_eq!(contract.binary_name, RELEASE_BINARY_NAME);
            assert_eq!(contract.repository, RELEASE_REPOSITORY);

            // Verify naming contract matches installer expectation.
            let expected_asset = format!("sbh-{triple}.tar.xz");
            assert_eq!(contract.asset_name(), expected_asset);
            assert_eq!(contract.checksum_name(), format!("{expected_asset}.sha256"));

            // Validate contract round-trips through validation.
            let assets = contract.expected_release_assets().to_vec();
            assert!(validate_release_assets(&contract, &assets).is_ok());
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
