//! Stage binary replacements without making the installed command disappear.
//!
//! Validation runs against a closed, synced file on the destination filesystem.
//! Unix publishes it with one rename over the old inode, including when that
//! inode is executing. Platforms that cannot rename over an executing image move
//! the old image only after validation, retaining it if recovery fails.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Copy, validate, and publish a candidate. No validation failure changes `dest`.
pub(super) fn install_with_validation<F>(
    source: &Path,
    dest: &Path,
    validate: F,
) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    if dest.file_name().is_none() {
        return Err(format!("invalid binary destination: {}", dest.display()));
    }
    match fs::symlink_metadata(dest) {
        Ok(meta) if !meta.is_file() && !meta.file_type().is_symlink() => {
            return Err(format!("binary destination is not a file: {}", dest.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to inspect binary destination: {error}")),
    }

    let mut input = open_regular_source(source)?;
    let parent = dest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("failed to create install dir: {error}"))?;
    let stage = StagingDir::create(parent)?;
    let candidate = stage.path.join("sbh");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&candidate)
        .map_err(|error| format!("failed to create staged binary: {error}"))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| format!("failed to copy staged binary: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("failed to make staged binary executable: {error}"))?;
    }
    output
        .sync_all()
        .map_err(|error| format!("failed to sync staged binary: {error}"))?;
    // An open writable descriptor makes an ELF self-test fail with ETXTBSY.
    drop(output);
    drop(input);

    validate(&candidate)?;
    stage.publish(dest)?;
    // Publication already succeeded. A directory-sync failure must not report
    // that the old binary was restored when the new one is actually installed.
    #[cfg(unix)]
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
    Ok(())
}

fn open_regular_source(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect candidate binary: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("candidate is not a regular file: {}", path.display()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a symlink swapped in after inspection, and never block opening
        // a FIFO substituted for the candidate before the second metadata check.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let input = options
        .open(path)
        .map_err(|error| format!("failed to open candidate binary: {error}"))?;
    if !input
        .metadata()
        .map_err(|error| format!("failed to inspect open candidate: {error}"))?
        .is_file()
    {
        return Err(format!("candidate is not a regular file: {}", path.display()));
    }
    Ok(input)
}

struct StagingDir {
    path: PathBuf,
    retain: bool,
}

impl StagingDir {
    fn create(parent: &Path) -> Result<Self, String> {
        for _ in 0..32 {
            let path = parent.join(format!(
                ".sbh-install-{}-{:032x}",
                std::process::id(),
                rand::random::<u128>()
            ));
            #[cfg(unix)]
            let created = {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&path)
            };
            #[cfg(not(unix))]
            let created = fs::create_dir(&path);
            match created {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        retain: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("failed to create binary staging dir: {error}")),
            }
        }
        Err("failed to allocate a unique binary staging directory after 32 attempts".to_string())
    }

    #[cfg(unix)]
    fn publish(self, dest: &Path) -> Result<(), String> {
        let candidate = self.path.join("sbh");
        // Never rename `dest` away first: readers see either complete executable,
        // and a failed rename leaves the existing executable untouched.
        fs::rename(&candidate, dest)
            .map_err(|error| format!("failed to atomically replace binary: {error}"))
    }

    #[cfg(not(unix))]
    fn publish(mut self, dest: &Path) -> Result<(), String> {
        let candidate = self.path.join("sbh");
        let previous = self.path.join("previous");
        let moved = match fs::rename(dest, &previous) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(format!("failed to preserve current binary: {error}")),
        };
        if let Err(error) = fs::rename(&candidate, dest) {
            if moved {
                if let Err(recovery_error) = fs::rename(&previous, dest) {
                    // Do not let Drop delete the only remaining installed image.
                    self.retain = true;
                    return Err(format!(
                        "failed to install binary: {error}; recovery failed: {recovery_error}; \
                         previous binary retained at {}",
                        previous.display()
                    ));
                }
            }
            return Err(format!("failed to install binary: {error}; previous state restored"));
        }
        Ok(())
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if !self.retain {
            // Only this invocation's exclusively created directory is removed.
            // Windows may retain a still-executing previous image until exit.
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("candidate");
        let dest = temp.path().join("bin/sbh");
        fs::create_dir(dest.parent().unwrap()).unwrap();
        fs::write(&source, b"new binary").unwrap();
        fs::write(&dest, b"old binary").unwrap();
        (temp, source, dest)
    }

    fn assert_no_staging(dest: &Path) {
        assert!(fs::read_dir(dest.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sbh-install-")
        }));
    }

    #[test]
    fn keeps_installed_binary_available_until_validation_finishes() {
        let (_temp, source, dest) = fixture();
        install_with_validation(&source, &dest, |candidate| {
            assert_eq!(fs::read(&dest).unwrap(), b"old binary");
            assert_eq!(fs::read(candidate).unwrap(), b"new binary");
            assert_ne!(candidate, dest.as_path());
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new binary");
        assert_no_staging(&dest);
    }

    #[test]
    fn failed_validation_preserves_installed_binary_and_cleans_staging() {
        let (_temp, source, dest) = fixture();
        let error = install_with_validation(&source, &dest, |_| Err("rejected".to_string()))
            .unwrap_err();
        assert_eq!(error, "rejected");
        assert_eq!(fs::read(&dest).unwrap(), b"old binary");
        assert_no_staging(&dest);
    }

    #[test]
    fn missing_candidate_never_changes_the_installation() {
        let (temp, _source, dest) = fixture();
        assert!(install_with_validation(&temp.path().join("missing"), &dest, |_| Ok(())).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"old binary");
        assert_no_staging(&dest);
    }

    #[test]
    fn refuses_directory_candidates() {
        let (temp, _source, dest) = fixture();
        assert!(install_with_validation(temp.path(), &dest, |_| Ok(())).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"old binary");
        assert_no_staging(&dest);
    }

    #[test]
    fn refuses_directory_destinations() {
        let (temp, source, _dest) = fixture();
        let dest = temp.path().join("directory");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("keep"), b"keep").unwrap();
        assert!(install_with_validation(&source, &dest, |_| Ok(())).is_err());
        assert_eq!(fs::read(dest.join("keep")).unwrap(), b"keep");
    }

    #[test]
    fn supports_first_install_into_a_missing_parent() {
        let (temp, source, _dest) = fixture();
        let dest = temp.path().join("new/bin/sbh");
        install_with_validation(&source, &dest, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new binary");
        assert_no_staging(&dest);
    }

    #[test]
    fn supports_reinstalling_from_the_destination_itself() {
        let (_temp, _source, dest) = fixture();
        install_with_validation(&dest, &dest, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"old binary");
        assert_no_staging(&dest);
    }

    #[cfg(unix)]
    #[test]
    fn source_symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;
        let (temp, source, dest) = fixture();
        let link = temp.path().join("source-link");
        symlink(&source, &link).unwrap();
        assert!(install_with_validation(&link, &dest, |_| Ok(())).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"old binary");
        assert_no_staging(&dest);
    }

    #[cfg(unix)]
    #[test]
    fn predictable_new_symlink_cannot_redirect_staging_writes() {
        use std::os::unix::fs::symlink;
        let (temp, source, dest) = fixture();
        let victim = temp.path().join("unrelated");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, dest.with_extension("new")).unwrap();
        install_with_validation(&source, &dest, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::read(&dest).unwrap(), b"new binary");
        assert_no_staging(&dest);
    }

    #[cfg(unix)]
    #[test]
    fn replaces_destination_symlink_without_overwriting_its_target() {
        use std::os::unix::fs::symlink;
        let (temp, source, _dest) = fixture();
        let target = temp.path().join("other-binary");
        let dest = temp.path().join("linked-sbh");
        fs::write(&target, b"keep").unwrap();
        symlink(&target, &dest).unwrap();
        install_with_validation(&source, &dest, |_| Ok(())).unwrap();
        assert_eq!(fs::read(target).unwrap(), b"keep");
        assert_eq!(fs::read(&dest).unwrap(), b"new binary");
        assert!(!fs::symlink_metadata(dest).unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn old_open_inode_is_not_overwritten() {
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt;
        let (_temp, source, dest) = fixture();
        let mut old = File::open(&dest).unwrap();
        let old_inode = old.metadata().unwrap().ino();
        install_with_validation(&source, &dest, |_| Ok(())).unwrap();
        let mut contents = String::new();
        old.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "old binary");
        assert_ne!(fs::metadata(&dest).unwrap().ino(), old_inode);
    }

    #[cfg(unix)]
    #[test]
    fn closes_writable_handle_before_executing_self_test() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, source, dest) = fixture();
        fs::write(&source, b"#!/bin/sh\nexit 0\n").unwrap();
        install_with_validation(&source, &dest, |candidate| {
            assert_eq!(fs::metadata(candidate).unwrap().permissions().mode() & 0o777, 0o755);
            assert!(std::process::Command::new(candidate).status().unwrap().success());
            Ok(())
        })
        .unwrap();
        assert_no_staging(&dest);
    }

    #[cfg(unix)]
    #[test]
    fn failed_publish_does_not_remove_the_destination() {
        let (_temp, source, dest) = fixture();
        // Simulate a destination change by a concurrent administrator after
        // initial inspection, but before the commit rename.
        let result = install_with_validation(&source, &dest, |_| {
            fs::remove_file(&dest).unwrap();
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("keep"), b"keep").unwrap();
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read(dest.join("keep")).unwrap(), b"keep");
        assert_no_staging(&dest);
    }
}
