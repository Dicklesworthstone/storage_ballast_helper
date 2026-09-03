//! Build metadata for `sbh version --verbose` and the Prometheus `sbh_info`
//! line (bd-rc-master-ajg1.5.4).
//!
//! Every build path gets real values: a checkout (git answers), a tarball or
//! remote build without `.git` (the `SBH_BUILD_GIT_SHA` environment variable
//! the packager sets), and a reproducible timestamp (`SOURCE_DATE_EPOCH`,
//! else the commit time, else the build time). The crate reads them with
//! `option_env!`, so a build with none of these still compiles and says
//! "unknown" rather than lying.

use std::env;
use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The commit the binary was built from: git's answer with a `-dirty`
/// suffix when the tree has uncommitted changes, else what the packager set.
fn git_sha() -> Option<String> {
    if let Some(sha) = git(&["rev-parse", "--short=12", "HEAD"]) {
        let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
        return Some(if dirty { format!("{sha}-dirty") } else { sha });
    }
    env::var("SBH_BUILD_GIT_SHA")
        .ok()
        .map(|sha| sha.trim().to_string())
        .filter(|sha| !sha.is_empty())
}

/// RFC 3339 UTC from a unix timestamp, without a date crate.
fn rfc3339_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant), valid for the Unix epoch onwards.
    let z = days.cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// A reproducible build timestamp: `SOURCE_DATE_EPOCH` wins, then the
/// commit time, then the wall clock.
fn build_timestamp() -> String {
    if let Some(epoch) = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return rfc3339_utc(epoch);
    }
    if let Some(commit_time) =
        git(&["log", "-1", "--format=%ct"]).and_then(|value| value.parse::<u64>().ok())
    {
        return rfc3339_utc(commit_time);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339_utc(now)
}

fn main() {
    println!("cargo:rerun-if-env-changed=SBH_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // Rebuild when the checked-out commit changes; the HEAD file is the
    // indirection, the ref it names carries the sha.
    let git_dir = git(&["rev-parse", "--git-dir"]);
    if let Some(dir) = git_dir.as_deref() {
        let head = Path::new(dir).join("HEAD");
        println!("cargo:rerun-if-changed={}", head.display());
        if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!(
                "cargo:rerun-if-changed={}",
                Path::new(dir).join(reference).display()
            );
        }
    }
    if let Some(sha) = git_sha() {
        println!("cargo:rustc-env=SBH_BUILD_GIT_SHA={sha}");
    }
    println!("cargo:rustc-env=SBH_BUILD_TIMESTAMP={}", build_timestamp());
    if let Ok(target) = env::var("TARGET") {
        println!("cargo:rustc-env=SBH_BUILD_TARGET={target}");
    }
    if let Ok(profile) = env::var("PROFILE") {
        println!("cargo:rustc-env=SBH_BUILD_PROFILE={profile}");
    }
}
