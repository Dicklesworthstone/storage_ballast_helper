//! Public-PAL regression for real mappings with non-text and ambiguous names.
//! All children start before the first query so the global snapshot is cold.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use storage_ballast_helper::core::errors::{Result, SbhError};
use storage_ballast_helper::platform::pal::Platform;
use storage_ballast_helper::platform::types::MappedRegion;

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn check_scope(
    result: Result<Vec<MappedRegion>>,
    scope: &Path,
    expected: &[(i32, PathBuf)],
) {
    match result {
        Ok(regions) => {
            assert!(regions.iter().all(|region| region.path.starts_with(scope)));
            for (pid, path) in expected {
                assert!(
                    regions.iter().any(|region| region.pid == *pid
                        && region.path == *path
                        && region.protection.as_deref().is_some_and(|mode| mode.contains('x'))),
                    "a successful maps snapshot omitted running PID {pid} at {path:?}: {regions:?}"
                );
            }
            if expected.is_empty() {
                assert!(regions.is_empty(), "a query must not expand its scope");
            }
        }
        // Other users' processes may be inaccessible. The existing Vec API
        // must refuse that partial observation, not return a misleading list.
        // Controlled readable/denied scopes and an unconditional real-current-
        // PID positive check are separately covered by mmap_scan's unit tests.
        Err(SbhError::Runtime { details }) => {
            assert!(details.starts_with("memory-map inspection incomplete:"), "{details}");
            eprintln!("Public host-wide maps coverage refused: {details}");
        }
        Err(error) => panic!("unexpected maps query failure: {error}"),
    }
}

#[test]
fn public_maps_query_never_silently_omits_live_byte_named_executables() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
        .into_iter()
        .find(|path| path.is_file())
        .expect("Linux integration fixture requires the system sleep utility");
    let original = fs::read(source).unwrap();
    let names = [
        b"sbh-mapped-\xff".as_slice(),
        b"sbh-mapped\nline (deleted)",
        b"sbh-mapped\\012line",
    ];
    let mut children = Vec::new();
    let mut expected = Vec::new();
    for (index, name) in names.into_iter().enumerate() {
        let executable = root.join(OsString::from_vec(name.to_vec()));
        fs::copy(source, &executable).unwrap();
        let mut child = RunningChild(
            Command::new(&executable)
                // BusyBox may implement sleep as a multi-call binary.
                .arg0("sleep")
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(child.0.try_wait().unwrap().is_none());
        let pid = i32::try_from(child.0.id()).unwrap();
        let proc = PathBuf::from(format!("/proc/{pid}"));
        assert_eq!(fs::read_link(proc.join("exe")).unwrap(), executable);
        let raw = fs::read(proc.join("maps")).unwrap();
        let mut rendered = Vec::new();
        for byte in executable.as_os_str().as_bytes() {
            if *byte == b'\n' {
                rendered.extend_from_slice(b"\\012");
            } else {
                rendered.push(*byte);
            }
        }
        assert!(raw.windows(rendered.len()).any(|window| window == rendered.as_slice()));
        if index == 0 {
            assert!(std::str::from_utf8(&raw).is_err(),
                "the old whole-file UTF-8 reader must actually fail on this fixture");
        }
        expected.push((pid, executable));
        children.push(child);
    }

    let platform = storage_ballast_helper::platform::current();
    check_scope(platform.mmap_regions_under(&root), &root, &expected);
    for item in &expected {
        check_scope(platform.mmap_regions_under(&item.1), &item.1, std::slice::from_ref(item));
    }
    let alias = root.join("alias-to-root");
    symlink(&root, &alias).unwrap();
    check_scope(platform.mmap_regions_under(&alias), &root, &expected);
    let unrelated = root.join("not-mapped");
    check_scope(platform.mmap_regions_under(&unrelated), &unrelated, &[]);

    for child in &mut children {
        assert!(child.0.try_wait().unwrap().is_none());
    }
    for (_, executable) in expected {
        assert_eq!(fs::read(executable).unwrap(), original, "inspection must be read-only");
    }
    // RunningChild reaps each process before TempDir removes the fixture.
}
