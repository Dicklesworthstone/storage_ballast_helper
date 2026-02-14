//! CLI contracts shared by installer and updater command paths.
#![allow(missing_docs)]

pub mod bootstrap;
pub mod integrations;

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::core::errors::{Result, SbhError};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Canonical GitHub repository for release artifacts.
pub const RELEASE_REPOSITORY: &str = "Dicklesworthstone/storage_ballast_helper";

/// Canonical binary name used in release artifact names.
pub const RELEASE_BINARY_NAME: &str = "sbh";

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

    use tempfile::NamedTempFile;

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
}
