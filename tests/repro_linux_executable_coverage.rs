//! Exercise executable-reference discovery against a real running Linux process.
//! A non-UTF-8 kernel comm must not hide the executable's byte-preserving path.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use storage_ballast_helper::platform::pal::Platform;

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn public_executable_query_finds_a_live_program_with_a_non_utf8_kernel_name() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let executable = root.join(OsString::from_vec(b"sbh-\xff-sleep".to_vec()));
    // No synthetic proc directory or injected link: execute a real binary at
    // the byte-named path. Child is reaped before TempDir cleans the fixture.
    let source = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
        .into_iter()
        .find(|path| path.is_file())
        .expect("Linux integration fixture requires the system sleep utility");
    fs::copy(source, &executable).unwrap();
    let mut child = RunningChild(
        Command::new(&executable)
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(child.0.try_wait().unwrap().is_none());
    let pid = i32::try_from(child.0.id()).unwrap();
    let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
    let comm = fs::read(proc_path.join("comm")).unwrap();
    assert!(
        std::str::from_utf8(&comm).is_err(),
        "fixture must exercise an actually non-UTF-8 kernel name: {comm:?}"
    );
    assert_eq!(fs::read_link(proc_path.join("exe")).unwrap(), executable);

    let platform = storage_ballast_helper::platform::current();
    let result = platform.executables_under(&root).unwrap();
    // Unrelated PIDs may be inaccessible; that must not erase this observed
    // program. Controlled scope/completeness cases live in reference_scan.
    let observed = result
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .expect("unreadable display metadata must not hide a running executable");
    assert_eq!(observed.executable.as_ref(), Some(&executable));
    assert!(!observed.name.is_empty());
    assert!(child.0.try_wait().unwrap().is_none());

    let unrelated = platform.executables_under(&root.join("other-scope")).unwrap();
    assert!(!unrelated.processes.iter().any(|process| process.pid == pid));
    assert_eq!(fs::metadata(&executable).unwrap().len(), fs::metadata(source).unwrap().len());
}
