//! Prepare and inspect the filesystem grants used by the systemd namespace.
//!
//! Namespace setup happens before ExecStartPre, so a mkdir there cannot repair
//! an absent ReadWritePaths entry (bd-2dzx). Installation prepares exact grants
//! before publishing the unit. It never makes a broader ancestor writable,
//! changes permissions on an existing directory, or disables the sandbox.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::core::errors::{Result, SbhError};

use super::{literal_systemd_word, systemd_exec_path, take_systemd_word};

pub(super) fn render(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| systemd_exec_path(path, false))
        .collect::<Vec<_>>()
        .join(" ")
}

// Retain '-'/'+' in the returned words so drift comparison does not silently
// equate a required grant with an optional or root-relative one. The live
// inspector below interprets the modifiers before inspecting the actual path.
pub(super) fn parse(mut value: &str) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    while !value.trim().is_empty() {
        let (word, tail) = take_systemd_word(value)
            .ok_or_else(|| invalid("malformed ReadWritePaths quoting or escape"))?;
        let literal = literal_systemd_word(&word, false)
            .ok_or_else(|| invalid("ReadWritePaths contains an unresolved specifier or NUL"))?;
        let path = path_from_bytes(literal)?;
        grant_path(&path)?;
        paths.push(path);
        value = tail;
    }
    Ok(paths)
}

// Fallible only where paths must be UTF-8.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn path_from_bytes(bytes: Vec<u8>) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| invalid("ReadWritePaths contains non-native path bytes"))
    }
}

pub(super) fn grant_path(word: &Path) -> Result<(PathBuf, bool)> {
    let mut bytes = word.as_os_str().as_encoded_bytes();
    let optional = bytes.starts_with(b"-");
    if optional {
        bytes = &bytes[1..];
    }
    if bytes.starts_with(b"+") {
        bytes = &bytes[1..];
    }
    let path = path_from_bytes(bytes.to_vec())?;
    if !path.is_absolute() {
        return Err(invalid(
            "ReadWritePaths requires an absolute path after '-'/'+' modifiers",
        ));
    }
    Ok((path, optional))
}

pub(super) fn prepare(paths: &[PathBuf]) -> Result<()> {
    // Reject invalid requests before creating any directory. A partially
    // successful mkdir is harmless and retained if a later I/O operation fails;
    // no existing data, permissions, units, or drop-ins are removed or changed.
    for path in paths {
        validate_directory(path)?;
    }
    for path in paths {
        fs::create_dir_all(path).map_err(|source| SbhError::io(path, source))?;
        validate_directory(path)?;
    }
    Ok(())
}

fn safe_grant(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.starts_with("/proc")
        || path.starts_with("/sys")
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(invalid(&format!(
            "refusing unsafe ReadWritePaths directory {}; require an absolute non-root path outside /proc and /sys without parent traversal",
            path.display()
        )));
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<()> {
    safe_grant(path)?;
    // Resolve the nearest existing ancestor, including ordinary /var aliases.
    // A dangling symlink is not an absent directory we may create through, and
    // an alias into /proc or /sys must not evade the lexical policy above.
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let resolved =
                    fs::canonicalize(ancestor).map_err(|source| SbhError::io(ancestor, source))?;
                let suffix = path
                    .strip_prefix(ancestor)
                    .map_err(|_| invalid("ReadWritePaths ancestor resolution failed"))?;
                safe_grant(&resolved.join(suffix))?;
                let metadata =
                    fs::metadata(ancestor).map_err(|source| SbhError::io(ancestor, source))?;
                if !metadata.is_dir() {
                    return Err(invalid(&format!(
                        "ReadWritePaths directory {} is blocked by non-directory {}; existing data was not replaced",
                        path.display(),
                        ancestor.display()
                    )));
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(SbhError::io(ancestor, source)),
        }
    }
    Err(invalid(
        "ReadWritePaths has no accessible existing ancestor",
    ))
}

// Keep assignment ordering, including resets across file boundaries. Parsing
// each file to a map first loses 'ReadWritePaths=' followed by a replacement.
fn assignments(text: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut section = String::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(prefix) = trimmed.strip_suffix('\\') {
            pending.push_str(prefix);
            pending.push(' ');
            continue;
        }
        pending.push_str(trimmed);
        let line = std::mem::take(&mut pending);
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            section = name.trim().to_string();
        } else if section == "Service"
            && let Some((key, value)) = line.split_once('=')
        {
            result.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    // An unfinished continuation is not a successfully inspected namespace.
    if !pending.is_empty() {
        result.push(("ReadWritePaths".into(), "<unfinished-continuation>".into()));
    }
    result
}

pub(super) fn validate_unit(installed: &str, dropins: &[(PathBuf, String)]) -> Result<()> {
    let mut effective: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for text in std::iter::once(installed).chain(dropins.iter().map(|(_, text)| text.as_str())) {
        for (key, value) in assignments(text) {
            match key.as_str() {
                "ReadWritePaths" => {
                    let values = effective.entry(key).or_default();
                    if value.is_empty() {
                        values.clear();
                    } else {
                        values.push(value);
                    }
                }
                "RootDirectory" | "RootImage" => {
                    effective.insert(key, vec![value]);
                }
                _ => {}
            }
        }
    }
    let Some(values) = effective
        .get("ReadWritePaths")
        .filter(|values| !values.is_empty())
    else {
        return Ok(());
    };
    if ["RootDirectory", "RootImage"].iter().any(|key| {
        effective
            .get(*key)
            .is_some_and(|values| values.iter().any(|value| !value.is_empty()))
    }) {
        return Err(invalid(
            "cannot validate ReadWritePaths inside a custom RootDirectory/RootImage from the host namespace",
        ));
    }
    let mut failures = Vec::new();
    for value in values {
        for word in parse(value)? {
            let (path, optional) = grant_path(&word)?;
            match fs::metadata(&path) {
                Ok(_) => {}
                Err(error) if optional && error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => failures.push(format!("{}: {error}", path.display())),
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(invalid(&format!(
            "systemd ReadWritePaths cannot be resolved (226/NAMESPACE): {}; run sbh service reinstall-unit with the intended config to prepare the configured directories, then restart the service; inspect custom drop-ins separately",
            failures.join("; ")
        )))
    }
}

fn invalid(details: &str) -> SbhError {
    SbhError::Runtime {
        details: details.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{SystemdConfig, SystemdServiceManager};
    use super::*;

    #[test]
    fn fresh_namespace_becomes_startable_without_broadening_the_grants() {
        let temp = tempfile::tempdir().unwrap();
        let paths = vec![
            temp.path().join("state/ballast"),
            temp.path().join("logs"),
            temp.path().join("scratch/builds with spaces"),
        ];
        let manager = SystemdServiceManager::new(SystemdConfig {
            user_scope: false,
            binary_path: "/usr/local/bin/sbh".into(),
            read_write_paths: paths.clone(),
        });
        let before = manager.generate_unit_file();
        let error = validate_unit(&before, &[]).unwrap_err().to_string();
        assert!(error.contains("226/NAMESPACE"));
        for path in &paths {
            assert!(!path.exists());
            assert!(error.contains(&path.display().to_string()));
        }
        prepare(&paths).unwrap();
        assert!(paths.iter().all(|path| path.is_dir()));
        assert!(validate_unit(&before, &[]).is_ok());
        assert_eq!(before, manager.generate_unit_file());
        assert!(before.contains("ProtectSystem=strict\n"));
        assert!(!before.contains("ReadWritePaths=/\n"));
        assert!(!temp.path().join("unconfigured").exists());
    }

    #[test]
    fn existing_data_and_directory_permissions_survive_repeated_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        let payload = root.join("activity.sqlite3");
        fs::write(&payload, b"do not replace this database").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        }
        let before = fs::metadata(&root).unwrap().permissions();
        prepare(std::slice::from_ref(&root)).unwrap();
        prepare(std::slice::from_ref(&root)).unwrap();
        assert_eq!(fs::read(payload).unwrap(), b"do not replace this database");
        assert_eq!(fs::metadata(root).unwrap().permissions(), before);
    }

    #[test]
    fn all_requests_are_validated_before_creating_any_directory() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("not-created");
        let file = temp.path().join("occupied");
        fs::write(&file, b"retained").unwrap();
        for invalid in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            PathBuf::from("/proc/new"),
            PathBuf::from("/sys/new"),
            temp.path().join("../escape"),
            file.clone(),
            file.join("child"),
        ] {
            assert!(prepare(&[missing.clone(), invalid]).is_err());
            assert!(!missing.exists());
            assert_eq!(fs::read(&file).unwrap(), b"retained");
        }
    }

    #[cfg(unix)]
    #[test]
    fn dangling_and_kernel_aliases_are_not_directory_creation_authority() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("target");
        let link = temp.path().join("dangling");
        std::os::unix::fs::symlink(&missing, &link).unwrap();
        assert!(prepare(&[link]).is_err());
        assert!(!missing.exists());
        let kernel = temp.path().join("kernel");
        std::os::unix::fs::symlink("/proc", &kernel).unwrap();
        assert!(prepare(&[kernel.join("sbh-no-create")]).is_err());
    }

    #[test]
    fn grants_round_trip_quotes_backslashes_control_bytes_and_specifiers() {
        let paths = [
            "/tmp/plain",
            "/tmp/with space",
            "/tmp/quote\"and'quote",
            "/tmp/back\\slash",
            "/tmp/%h/${HOME}",
            "/tmp/line\nReadWritePaths=/\ntail",
            "/tmp/tab\there",
        ]
        .map(PathBuf::from);
        let encoded = render(&paths);
        assert!(!encoded.contains('\n'));
        assert!(encoded.contains("%%h"));
        assert!(!encoded.contains("$${HOME}"));
        assert_eq!(parse(&encoded).unwrap(), paths);
        assert!(parse("/tmp/good \"/unfinished").is_err());
        assert!(parse("/tmp/%h").is_err());
        assert!(parse(r"/tmp/\000").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_filename_bytes_survive_sandbox_serialization() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/\xff%h space".to_vec()));
        assert_eq!(
            parse(&render(std::slice::from_ref(&path))).unwrap(),
            vec![path]
        );
    }

    #[test]
    fn live_checks_honor_optional_entries_and_dropin_resets() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let unit = format!(
            "[Service]\nReadWritePaths={}\n",
            render(std::slice::from_ref(&missing))
        );
        assert!(validate_unit(&unit, &[]).is_err());
        let dropins = vec![(
            temp.path().join("reset.conf"),
            format!(
                "[Service]\nReadWritePaths=\nReadWritePaths={}\n",
                render(&[temp.path().to_path_buf()])
            ),
        )];
        assert!(validate_unit(&unit, &dropins).is_ok());
        let optional = format!("[Service]\nReadWritePaths=-{}\n", missing.display());
        assert!(validate_unit(&optional, &[]).is_ok());
        // Parsing for drift preserves modifier distinctions.
        assert_ne!(
            parse(&format!("-{}", missing.display())).unwrap(),
            vec![missing]
        );
    }

    #[test]
    fn diagnostics_read_continued_assignments_without_creating_paths() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let unit = format!(
            "[Service]\nReadWritePaths={} \\\n  {}\n",
            render(&[temp.path().to_path_buf()]),
            render(std::slice::from_ref(&missing))
        );
        assert!(validate_unit(&unit, &[]).is_err());
        assert!(!missing.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and a live systemd manager; creates only a disposable transient unit"]
    fn native_missing_grant_fails_then_prepared_namespace_can_write() {
        use std::process::Command;
        assert!(nix::unistd::geteuid().is_root(), "run this proof as root");
        let temp = tempfile::tempdir().unwrap();
        // No '%': systemd-run hands properties to the manager without
        // specifier expansion, so the unit-file escape `%%h` would name a
        // different path and the prepared run would still fail with 226.
        // Specifier escaping is covered by the unit-file fixtures above.
        let directory = temp.path().join("fresh state");
        let request = render(std::slice::from_ref(&directory));
        let run = |label: &str| {
            Command::new("systemd-run")
                .args(["--wait", "--pipe", "--collect", "--quiet"])
                .arg(format!(
                    "--unit=sbh-namespace-{}-{label}",
                    std::process::id()
                ))
                .arg("--property=Type=oneshot")
                .arg("--property=RuntimeMaxSec=30")
                .arg("--property=ProtectSystem=strict")
                .arg(format!("--property=ReadWritePaths={request}"))
                .args([
                    "--",
                    "/bin/sh",
                    "-c",
                    "printf '%s' verified > \"$1/probe\"",
                    "sbh-proof",
                ])
                .arg(&directory)
                .output()
                .unwrap()
        };
        let before = run("missing");
        assert_eq!(before.status.code(), Some(226), "{before:?}");
        assert!(!directory.exists());
        prepare(std::slice::from_ref(&directory)).unwrap();
        let after = run("prepared");
        assert!(after.status.success(), "{after:?}");
        assert_eq!(fs::read(directory.join("probe")).unwrap(), b"verified");
    }
}
