//! A cache-tag name alone is not evidence that an artifact is regenerable.
//! Exercise the single-path replay helper and actual walkers against the same
//! fixtures. The FIFO case runs in a killable child so a regression cannot hang
//! the test runner indefinitely.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use storage_ballast_helper::scanner::patterns::{ArtifactPatternRegistry, StructuralSignals};
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::scoring::{ArtifactCertainty, classify_certainty};
use storage_ballast_helper::scanner::walker::{
    DirectoryWalker, WalkerConfig, structural_signals_for_path,
};

const SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path()).unwrap().join("unclassified-payload");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("retained.bin"), b"not disposable merely because a tag is named").unwrap();
    (temp, path)
}

fn walked(path: &Path, opaque: bool) -> StructuralSignals {
    let walker = DirectoryWalker::new(
        WalkerConfig {
            root_paths: vec![path.parent().unwrap().to_path_buf()],
            max_depth: 2,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths: HashSet::new(),
            opaque_pruning: opaque,
        },
        ProtectionRegistry::marker_only(),
    );
    walker
        .walk()
        .unwrap()
        .into_iter()
        .find(|entry| entry.path == path)
        .expect("fixture directory must be observed, not silently skipped")
        .structural_signals
}

fn assert_tag_evidence(path: &Path, expected: bool) {
    let before = fs::read(path.join("retained.bin")).unwrap();
    for signals in [
        structural_signals_for_path(path),
        walked(path, false),
        walked(path, true),
    ] {
        assert_eq!(signals.has_cachedir_tag, expected, "{path:?}: {signals:?}");
        let classification = ArtifactPatternRegistry::default().classify(path, signals);
        let certainty = classify_certainty(&classification, signals, 0.0);
        assert_eq!(
            certainty == ArtifactCertainty::Definite,
            expected,
            "invalid tag evidence must not become definite regenerability: {certainty:?}"
        );
    }
    assert_eq!(fs::read(path.join("retained.bin")).unwrap(), before);
}

#[test]
fn invalid_signature_never_becomes_replay_only_cache_authority() {
    let (_temp, path) = fixture();
    for bytes in [
        b"".as_slice(),
        b"not a cache tag",
        b"Signature: deadbeef",
        b" Signature: 8a477f597d28d172789f06886806bc55",
        b"signature: 8a477f597d28d172789f06886806bc55",
        b"Signature:  8a477f597d28d172789f06886806bc55",
    ] {
        fs::write(path.join("CACHEDIR.TAG"), bytes).unwrap();
        assert_tag_evidence(&path, false);
    }
}

#[test]
fn every_short_prefix_is_rejected_and_exact_signature_is_sufficient() {
    let (_temp, path) = fixture();
    for length in 0..SIGNATURE.len() {
        fs::write(path.join("CACHEDIR.TAG"), &SIGNATURE[..length]).unwrap();
        assert!(!structural_signals_for_path(&path).has_cachedir_tag, "prefix {length}");
    }
    fs::write(path.join("CACHEDIR.TAG"), SIGNATURE).unwrap();
    assert_tag_evidence(&path, true);
}

#[test]
fn tag_filename_is_case_sensitive_even_on_case_insensitive_filesystems() {
    let (_temp, path) = fixture();
    fs::write(path.join("cachedir.tag"), SIGNATURE).unwrap();
    assert_tag_evidence(&path, false);
}

#[test]
fn large_valid_tags_do_not_require_reading_the_tail() {
    let (_temp, path) = fixture();
    let tag = path.join("CACHEDIR.TAG");
    fs::write(&tag, SIGNATURE).unwrap();
    let file = fs::OpenOptions::new().write(true).open(&tag).unwrap();
    // Sparse extension tests the fixed-prefix reader without creating a large
    // fixture payload. No newline after the signature is required by the spec.
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);
    assert_tag_evidence(&path, true);
    assert_eq!(fs::metadata(tag).unwrap().len(), 64 * 1024 * 1024);
}

#[test]
fn replacing_valid_tag_contents_revokes_replay_evidence() {
    let (_temp, path) = fixture();
    fs::write(path.join("CACHEDIR.TAG"), SIGNATURE).unwrap();
    assert_tag_evidence(&path, true);
    fs::write(path.join("CACHEDIR.TAG"), vec![b'x'; SIGNATURE.len()]).unwrap();
    assert_tag_evidence(&path, false);
}

#[test]
fn a_directory_named_like_a_tag_does_not_classify_its_parent_as_a_cache() {
    let (_temp, path) = fixture();
    let tag = path.join("CACHEDIR.TAG");
    fs::create_dir(&tag).unwrap();
    fs::write(tag.join("signature.txt"), SIGNATURE).unwrap();
    assert_tag_evidence(&path, false);
}

#[cfg(unix)]
#[test]
fn symlinked_tags_are_rejected_even_when_the_target_has_a_valid_signature() {
    let (temp, path) = fixture();
    let actual = temp.path().join("external-tag");
    fs::write(&actual, SIGNATURE).unwrap();
    std::os::unix::fs::symlink(&actual, path.join("CACHEDIR.TAG")).unwrap();
    assert_tag_evidence(&path, false);
    assert_eq!(fs::read(actual).unwrap(), SIGNATURE);
}

#[cfg(unix)]
#[test]
fn dangling_tag_links_do_not_manufacture_cache_evidence() {
    let (temp, path) = fixture();
    std::os::unix::fs::symlink(temp.path().join("absent"), path.join("CACHEDIR.TAG")).unwrap();
    assert_tag_evidence(&path, false);
    assert!(fs::symlink_metadata(path.join("CACHEDIR.TAG")).unwrap().is_symlink());
}

#[cfg(unix)]
#[test]
fn tag_validation_does_not_erase_symlinked_source_safety_markers() {
    let (temp, path) = fixture();
    let source = temp.path().join("metadata");
    fs::write(&source, b"keep source metadata").unwrap();
    for name in [".git", "Cargo.toml"] {
        std::os::unix::fs::symlink(&source, path.join(name)).unwrap();
    }
    fs::write(path.join("CACHEDIR.TAG"), b"invalid").unwrap();
    for signals in [structural_signals_for_path(&path), walked(&path, false)] {
        assert!(signals.has_git && signals.has_cargo_toml);
        assert!(!signals.has_cachedir_tag);
    }
    assert_eq!(fs::read(source).unwrap(), b"keep source metadata");
}

#[cfg(unix)]
#[test]
fn valid_tag_evidence_preserves_non_utf8_directory_names() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .join(std::ffi::OsString::from_vec(b"unclassified-\xff".to_vec()));
    fs::create_dir(&path).unwrap();
    fs::write(path.join("retained.bin"), b"keep").unwrap();
    fs::write(path.join("CACHEDIR.TAG"), SIGNATURE).unwrap();
    assert_tag_evidence(&path, true);
}

#[cfg(unix)]
#[test]
fn fifo_tags_cannot_hang_live_scanning_or_replay() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct RunningChild(Child);
    impl Drop for RunningChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let (_temp, path) = fixture();
    nix::unistd::mkfifo(
        &path.join("CACHEDIR.TAG"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let mut child = RunningChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fifo_tag_worker", "--nocapture"])
        .env("SBH_TEST_FIFO_TAG_ROOT", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "FIFO inspection child failed: {status}");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            panic!("cache-tag inspection blocked on a FIFO without a writer");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(fs::symlink_metadata(path.join("CACHEDIR.TAG")).is_ok());
}

#[cfg(unix)]
#[test]
fn fifo_tag_worker() {
    let Some(root) = std::env::var_os("SBH_TEST_FIFO_TAG_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    // Live traversal first: the old reader blocks in File::open; its replay
    // path separately fabricated a positive signal from the FIFO name alone.
    assert!(!walked(&root, false).has_cachedir_tag);
    assert!(!walked(&root, true).has_cachedir_tag);
    assert!(!structural_signals_for_path(&root).has_cachedir_tag);
}
