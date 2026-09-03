//! Post-publish audit of a release asset set (`sbh doctor --release --assets
//! <dir|tag>`, bd-rc-master-ajg1.5.3).
//!
//! The manual release path is guarded the same way the workflow guards
//! itself: every CI target's versioned archive and `.sha256` sidecar, the
//! legacy unversioned mirror, the aggregate `SHA256SUMS.txt`, the
//! architecture of the binary inside each tarball (the v0.4.23 incident was a
//! tarball labelled for one target that carried another target's binary),
//! and the provenance document. The audit is a pure function of a directory
//! and a tag; the doctor downloads a release into a directory first when a
//! tag is given.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    CI_RELEASE_TARGETS, HostSpecifier, RELEASE_BINARY_NAME, ReleaseChannel,
    resolve_updater_artifact_contract, sha256_from_manifest,
};
use crate::core::errors::{Result, SbhError};

/// The provenance document the Release workflow attaches to every release.
pub const PROVENANCE_ASSET: &str = "release-provenance.json";
/// The aggregate checksum manifest the Release workflow attaches.
pub const AGGREGATE_MANIFEST: &str = "SHA256SUMS.txt";
/// Fields the provenance document must carry, non-empty.
pub const PROVENANCE_FIELDS: [&str; 5] = ["tag", "sha", "run_id", "timestamp", "rustc_version"];

/// One audit finding: `PASS`, `WARN` or `FAIL` about one asset or aspect.
#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub id: &'static str,
    pub status: &'static str,
    pub subject: String,
    pub message: String,
}

/// The audit of one release directory.
#[derive(Debug, Clone, Serialize)]
pub struct AssetAudit {
    pub tag: String,
    pub dir: PathBuf,
    pub ok: bool,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub findings: Vec<AuditFinding>,
}

impl AssetAudit {
    fn from_findings(tag: &str, dir: &Path, findings: Vec<AuditFinding>) -> Self {
        let count = |status: &str| findings.iter().filter(|f| f.status == status).count();
        let failed = count("FAIL");
        Self {
            tag: tag.to_string(),
            dir: dir.to_path_buf(),
            ok: failed == 0,
            passed: count("PASS"),
            warnings: count("WARN"),
            failed,
            findings,
        }
    }

    /// The `FAIL` findings, for error messages.
    #[must_use]
    pub fn failures(&self) -> Vec<&AuditFinding> {
        self.findings
            .iter()
            .filter(|f| f.status == "FAIL")
            .collect()
    }
}

/// The binary format and architecture read from an executable's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    ElfX86_64,
    ElfAarch64,
    MachOX86_64,
    MachOArm64,
    Unknown,
}

impl BinaryKind {
    /// Human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ElfX86_64 => "ELF x86_64",
            Self::ElfAarch64 => "ELF aarch64",
            Self::MachOX86_64 => "Mach-O x86_64",
            Self::MachOArm64 => "Mach-O arm64",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify an executable by its first bytes: ELF (`e_machine` at offset
/// 18, little-endian) or 64-bit Mach-O (`cputype` at offset 4).
#[must_use]
pub fn binary_kind(header: &[u8]) -> BinaryKind {
    if header.len() >= 20 && header.starts_with(b"\x7fELF") {
        return match u16::from_le_bytes([header[18], header[19]]) {
            0x3E => BinaryKind::ElfX86_64,
            0xB7 => BinaryKind::ElfAarch64,
            _ => BinaryKind::Unknown,
        };
    }
    if header.len() >= 8 && header[..4] == [0xcf, 0xfa, 0xed, 0xfe] {
        return match u32::from_le_bytes([header[4], header[5], header[6], header[7]]) {
            0x0100_0007 => BinaryKind::MachOX86_64,
            0x0100_000C => BinaryKind::MachOArm64,
            _ => BinaryKind::Unknown,
        };
    }
    BinaryKind::Unknown
}

/// The binary kind a CI target triple must contain.
#[must_use]
pub fn expected_binary_kind(triple: &str) -> Option<BinaryKind> {
    match triple {
        "x86_64-unknown-linux-gnu" => Some(BinaryKind::ElfX86_64),
        "aarch64-unknown-linux-gnu" => Some(BinaryKind::ElfAarch64),
        "x86_64-apple-darwin" => Some(BinaryKind::MachOX86_64),
        "aarch64-apple-darwin" => Some(BinaryKind::MachOArm64),
        _ => None,
    }
}

/// The host specifier of a CI target triple.
pub fn ci_target_host(triple: &str) -> Result<HostSpecifier> {
    let (os, arch, abi) = match triple {
        "x86_64-unknown-linux-gnu" => ("linux", "x86_64", Some("gnu")),
        "aarch64-unknown-linux-gnu" => ("linux", "aarch64", Some("gnu")),
        "x86_64-apple-darwin" => ("darwin", "x86_64", None),
        "aarch64-apple-darwin" => ("darwin", "aarch64", None),
        other => {
            return Err(SbhError::UnsupportedPlatform {
                details: format!("{other} is not a CI release target"),
            });
        }
    };
    HostSpecifier::from_parts(os, arch, abi)
}

/// SHA-256 of a file, lowercase hex.
pub fn sha256_of_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|source| SbhError::io(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| SbhError::io(path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_of(&hasher.finalize()))
}

/// Lowercase hex of a digest.
fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The release tag a directory of assets belongs to: the provenance
/// document's `tag`, else the version in a `sbh-v…-<triple>.tar.xz` name.
pub fn tag_of_release_dir(dir: &Path) -> Result<String> {
    let provenance = dir.join(PROVENANCE_ASSET);
    if let Ok(text) = fs::read_to_string(&provenance)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(tag) = value.get("tag").and_then(serde_json::Value::as_str)
        && !tag.trim().is_empty()
    {
        return Ok(tag.trim().to_string());
    }
    let entries = fs::read_dir(dir).map_err(|source| SbhError::io(dir, source))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(&format!("{RELEASE_BINARY_NAME}-v")) else {
            continue;
        };
        for triple in CI_RELEASE_TARGETS {
            if let Some(version) = rest.strip_suffix(&format!("-{triple}.tar.xz")) {
                return Ok(format!("v{version}"));
            }
        }
    }
    Err(SbhError::InvalidConfig {
        details: format!(
            "{} has neither {PROVENANCE_ASSET} nor a versioned archive to name the release tag",
            dir.display()
        ),
    })
}

fn finding(
    id: &'static str,
    status: &'static str,
    subject: impl Into<String>,
    message: impl Into<String>,
) -> AuditFinding {
    AuditFinding {
        id,
        status,
        subject: subject.into(),
        message: message.into(),
    }
}

/// The recorded hash for `name` in a checksum file (sidecar or manifest).
fn recorded_hash(dir: &Path, file: &str, name: &str) -> Option<String> {
    let text = fs::read_to_string(dir.join(file)).ok()?;
    sha256_from_manifest(&text, name)
}

/// Audit one archive: sidecar, manifest, legacy mirror, and the binary's
/// architecture.
fn audit_target(dir: &Path, tag: &str, triple: &str, findings: &mut Vec<AuditFinding>) {
    let contract = match ci_target_host(triple)
        .and_then(|host| resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some(tag)))
    {
        Ok(contract) => contract,
        Err(error) => {
            findings.push(finding(
                "assets.contract",
                "FAIL",
                triple,
                error.to_string(),
            ));
            return;
        }
    };
    let archive = contract.asset_name();
    let archive_path = dir.join(&archive);
    if !archive_path.is_file() {
        findings.push(finding("assets.archive", "FAIL", &archive, "missing"));
        return;
    }
    let hash = match sha256_of_file(&archive_path) {
        Ok(hash) => hash,
        Err(error) => {
            findings.push(finding(
                "assets.archive",
                "FAIL",
                &archive,
                error.to_string(),
            ));
            return;
        }
    };
    findings.push(finding(
        "assets.archive",
        "PASS",
        &archive,
        format!("sha256 {hash}"),
    ));

    audit_checksums(dir, &archive, &hash, &contract.checksum_name(), findings);
    let legacy = format!(
        "{RELEASE_BINARY_NAME}-{}.{}",
        contract.target.triple,
        contract.target.archive.extension()
    );
    audit_legacy_mirror(dir, &archive, &hash, &legacy, findings);
    audit_binary(&archive_path, &archive, triple, findings);
}

/// The `.sha256` sidecar and the aggregate manifest both record `hash`.
fn audit_checksums(
    dir: &Path,
    archive: &str,
    hash: &str,
    sidecar: &str,
    findings: &mut Vec<AuditFinding>,
) {
    match recorded_hash(dir, sidecar, archive) {
        Some(recorded) if recorded == hash => {
            findings.push(finding(
                "assets.checksum",
                "PASS",
                sidecar,
                "matches the archive",
            ));
        }
        Some(recorded) => findings.push(finding(
            "assets.checksum",
            "FAIL",
            sidecar,
            format!("records {recorded}, archive is {hash}"),
        )),
        None => findings.push(finding(
            "assets.checksum",
            "FAIL",
            sidecar,
            "missing or does not name the archive",
        )),
    }
    match recorded_hash(dir, AGGREGATE_MANIFEST, archive) {
        Some(recorded) if recorded == hash => findings.push(finding(
            "assets.manifest",
            "PASS",
            archive,
            format!("listed in {AGGREGATE_MANIFEST}"),
        )),
        Some(recorded) => findings.push(finding(
            "assets.manifest",
            "FAIL",
            archive,
            format!("{AGGREGATE_MANIFEST} records {recorded}, archive is {hash}"),
        )),
        None => findings.push(finding(
            "assets.manifest",
            "FAIL",
            archive,
            format!("not listed in {AGGREGATE_MANIFEST}"),
        )),
    }
}

/// Pre-v0.4.8 updaters ask for the unversioned name: it must exist, be the
/// same bytes as the versioned archive, and carry a matching sidecar.
fn audit_legacy_mirror(
    dir: &Path,
    archive: &str,
    hash: &str,
    legacy: &str,
    findings: &mut Vec<AuditFinding>,
) {
    let legacy_path = dir.join(legacy);
    if !legacy_path.is_file() {
        findings.push(finding(
            "assets.legacy",
            "FAIL",
            legacy,
            "missing (older self-updaters request this name)",
        ));
        return;
    }
    match sha256_of_file(&legacy_path) {
        Ok(legacy_hash) if legacy_hash == hash => {
            let legacy_sidecar = format!("{legacy}.sha256");
            match recorded_hash(dir, &legacy_sidecar, legacy) {
                Some(recorded) if recorded == hash => findings.push(finding(
                    "assets.legacy",
                    "PASS",
                    legacy,
                    "byte-identical mirror with a matching sidecar",
                )),
                _ => findings.push(finding(
                    "assets.legacy",
                    "FAIL",
                    legacy_sidecar,
                    "missing or does not match the mirror",
                )),
            }
        }
        Ok(legacy_hash) => findings.push(finding(
            "assets.legacy",
            "FAIL",
            legacy,
            format!("differs from {archive} ({legacy_hash} vs {hash})"),
        )),
        Err(error) => {
            findings.push(finding("assets.legacy", "FAIL", legacy, error.to_string()));
        }
    }
}

/// The binary inside the archive is built for the labelled target.
fn audit_binary(
    archive_path: &Path,
    archive: &str,
    triple: &str,
    findings: &mut Vec<AuditFinding>,
) {
    match binary_kind_in_archive(archive_path) {
        Ok(kind) => {
            let expected = expected_binary_kind(triple).unwrap_or(BinaryKind::Unknown);
            if kind == expected {
                findings.push(finding(
                    "assets.binary",
                    "PASS",
                    archive,
                    format!("contains a {} sbh", kind.label()),
                ));
            } else {
                findings.push(finding(
                    "assets.binary",
                    "FAIL",
                    archive,
                    format!(
                        "labelled {triple} but contains a {} binary (expected {})",
                        kind.label(),
                        expected.label()
                    ),
                ));
            }
        }
        Err(error) => findings.push(finding("assets.binary", "FAIL", archive, error.to_string())),
    }
}

/// Extract the archive into a private scratch directory and classify the
/// `sbh` inside it; the scratch directory is removed again.
pub fn binary_kind_in_archive(archive: &Path) -> Result<BinaryKind> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let scratch =
        std::env::temp_dir().join(format!("sbh-asset-audit-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&scratch).map_err(|source| SbhError::io(&scratch, source))?;
    let result = (|| {
        let status = Command::new("tar")
            .arg("-xJf")
            .arg(archive)
            .arg("-C")
            .arg(&scratch)
            .status()
            .map_err(|source| SbhError::io(archive, source))?;
        if !status.success() {
            return Err(SbhError::Runtime {
                details: format!("tar could not extract {} ({status})", archive.display()),
            });
        }
        let binary = scratch.join(RELEASE_BINARY_NAME);
        let mut file = fs::File::open(&binary).map_err(|source| SbhError::io(&binary, source))?;
        let mut header = [0u8; 64];
        let read = file
            .read(&mut header)
            .map_err(|source| SbhError::io(&binary, source))?;
        Ok(binary_kind(&header[..read]))
    })();
    let _ = fs::remove_dir_all(&scratch);
    result
}

fn audit_provenance(dir: &Path, tag: &str, findings: &mut Vec<AuditFinding>) {
    let path = dir.join(PROVENANCE_ASSET);
    let Ok(text) = fs::read_to_string(&path) else {
        findings.push(finding(
            "assets.provenance",
            "FAIL",
            PROVENANCE_ASSET,
            "missing",
        ));
        return;
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            findings.push(finding(
                "assets.provenance",
                "FAIL",
                PROVENANCE_ASSET,
                format!("not JSON: {error}"),
            ));
            return;
        }
    };
    let empty: Vec<&str> = PROVENANCE_FIELDS
        .iter()
        .copied()
        .filter(|field| {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_none_or(|v| v.trim().is_empty())
        })
        .collect();
    if !empty.is_empty() {
        findings.push(finding(
            "assets.provenance",
            "FAIL",
            PROVENANCE_ASSET,
            format!("missing or empty fields: {}", empty.join(", ")),
        ));
        return;
    }
    let recorded = value["tag"].as_str().unwrap_or_default();
    if recorded == tag {
        findings.push(finding(
            "assets.provenance",
            "PASS",
            PROVENANCE_ASSET,
            format!(
                "tag {tag}, sha {}, run {}",
                value["sha"].as_str().unwrap_or_default(),
                value["run_id"].as_str().unwrap_or_default()
            ),
        ));
    } else {
        findings.push(finding(
            "assets.provenance",
            "FAIL",
            PROVENANCE_ASSET,
            format!("records tag {recorded}, auditing {tag}"),
        ));
    }
}

/// Audit the release assets in `dir` for `tag`.
#[must_use]
pub fn audit_release_dir(dir: &Path, tag: &str) -> AssetAudit {
    let mut findings = Vec::new();
    if dir.join(AGGREGATE_MANIFEST).is_file() {
        findings.push(finding(
            "assets.manifest",
            "PASS",
            AGGREGATE_MANIFEST,
            "present",
        ));
    } else {
        findings.push(finding(
            "assets.manifest",
            "FAIL",
            AGGREGATE_MANIFEST,
            "missing",
        ));
    }
    for triple in CI_RELEASE_TARGETS {
        audit_target(dir, tag, triple, &mut findings);
    }
    audit_provenance(dir, tag, &mut findings);
    findings.push(finding(
        "assets.signing",
        "WARN",
        "macOS archives",
        "codesign identity and notarization ticket are not checked by this audit; run `codesign --verify --strict` and `spctl --assess` on a Mac before publishing",
    ));
    AssetAudit::from_findings(tag, dir, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_kinds_are_read_from_headers() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[18] = 0x3E;
        assert_eq!(binary_kind(&elf), BinaryKind::ElfX86_64);
        elf[18] = 0xB7;
        assert_eq!(binary_kind(&elf), BinaryKind::ElfAarch64);
        let mut macho = vec![0u8; 64];
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        assert_eq!(binary_kind(&macho), BinaryKind::MachOX86_64);
        macho[4..8].copy_from_slice(&0x0100_000Cu32.to_le_bytes());
        assert_eq!(binary_kind(&macho), BinaryKind::MachOArm64);
        assert_eq!(binary_kind(b"#!/bin/sh"), BinaryKind::Unknown);
        assert_eq!(binary_kind(&[]), BinaryKind::Unknown);
        for triple in CI_RELEASE_TARGETS {
            assert!(expected_binary_kind(triple).is_some(), "{triple}");
            assert!(ci_target_host(triple).is_ok(), "{triple}");
        }
        assert!(ci_target_host("riscv64gc-unknown-linux-gnu").is_err());
    }
}
