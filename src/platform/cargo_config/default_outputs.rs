//! Manifest-based default output scopes for live local Cargo builds.
//!
//! A build can wait on dependencies before opening any artifact. Inspect only
//! manifest metadata, through the same bounded reader/cache as configuration.
//! Membership/exclusion globs are not evaluated: an implicit workspace keeps
//! both its shared output and the package-local possibility as deny-only scopes.

use std::io;
use std::path::{Path, PathBuf};

use super::{
    Cached, MAX_ANCESTORS, MAX_PATH_BYTES, Observation, Resolver, byte_path, cargo_value_option,
};

#[derive(Clone, Default)]
pub(super) struct Manifest {
    package: bool,
    workspace: bool,
    external_workspace: Option<String>,
    invalid: bool,
}

pub(super) fn parse_manifest(document: &toml::Value) -> Manifest {
    let mut manifest = Manifest::default();
    if let Some(package) = document.get("package") {
        manifest.package = package.is_table();
        manifest.invalid |= !package.is_table();
        if let Some(workspace) = package.get("workspace") {
            match workspace.as_str().filter(|path| {
                !path.is_empty() && path.len() <= MAX_PATH_BYTES && !path.contains('\0')
            }) {
                Some(workspace) => manifest.external_workspace = Some(workspace.to_owned()),
                None => manifest.invalid = true,
            }
        }
    }
    if let Some(workspace) = document.get("workspace") {
        manifest.workspace = workspace.is_table();
        manifest.invalid |= !workspace.is_table();
    }
    manifest.invalid |= manifest.workspace && manifest.external_workspace.is_some();
    manifest
}

impl Resolver {
    pub(super) fn default_target(
        &mut self,
        request: ManifestRequest<'_>,
        cwd: Option<&Path>,
        observation: &mut Observation,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) {
        let selected = if let ManifestRequest::Explicit(explicit) = request {
            let Some(path) = byte_path(explicit, cwd) else {
                observation.complete = false;
                return;
            };
            let Cached::Present(parsed) = self.cached(&path, read) else {
                observation.complete = false;
                return;
            };
            Some((path, parsed.manifest))
        } else {
            self.find_manifest(cwd, false, observation, read)
        };
        let Some((path, manifest)) = selected else {
            return;
        };
        let Some(directory) = path.parent() else {
            observation.complete = false;
            return;
        };
        if manifest.invalid || (!manifest.package && !manifest.workspace) {
            observation.complete = false;
            return;
        }
        if manifest.workspace {
            observation.add(Some(directory), "target");
        } else if let Some(external) = manifest.external_workspace {
            let Some(workspace) = byte_path(external.as_bytes(), Some(directory)) else {
                observation.complete = false;
                return;
            };
            // Cargo expects this exact directory to be a workspace root,
            // not another member pointing elsewhere. Never follow a cycle.
            match self.cached(&workspace.join("Cargo.toml"), read) {
                Cached::Present(parsed)
                    if parsed.manifest.workspace && !parsed.manifest.invalid =>
                {
                    observation.add(Some(&workspace), "target");
                }
                _ => observation.complete = false,
            }
        } else {
            observation.add(Some(directory), "target");
            if let Some((workspace, _)) =
                self.find_manifest(directory.parent(), true, observation, read)
            {
                observation.add(workspace.parent(), "target");
            }
        }
    }

    fn find_manifest(
        &mut self,
        start: Option<&Path>,
        workspace_only: bool,
        observation: &mut Observation,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) -> Option<(PathBuf, Manifest)> {
        let start = start?;
        for (index, directory) in start.ancestors().enumerate() {
            if index >= MAX_ANCESTORS {
                observation.complete = false;
                break;
            }
            let path = directory.join("Cargo.toml");
            match self.cached(&path, read) {
                Cached::Missing => {}
                Cached::Unavailable => {
                    observation.complete = false;
                    break;
                }
                Cached::Present(parsed) => {
                    if parsed.manifest.invalid {
                        observation.complete = false;
                        break;
                    }
                    if !workspace_only || parsed.manifest.workspace {
                        return Some((path, parsed.manifest));
                    }
                }
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
pub(super) enum ManifestRequest<'a> {
    Search,
    Explicit(&'a [u8]),
}

/// Only known local build commands without a target-dir override need defaults.
/// Forwarded arguments and operands of other options are not Cargo commands.
pub(super) fn request(argv: &[u8]) -> Option<ManifestRequest<'_>> {
    let mut operands = argv.strip_suffix(b"\0")?.split(|byte| *byte == 0);
    let program = operands.next()?.rsplit(|byte| *byte == b'/').next()?;
    let mut command = match program {
        b"cargo-clippy" => Some(b"clippy".as_slice()),
        b"cargo-nextest" => Some(b"nextest".as_slice()),
        _ => None,
    };
    let mut manifest = ManifestRequest::Search;
    while let Some(arg) = operands.next() {
        if arg == b"--" {
            break;
        }
        if arg == b"--target-dir" || arg.starts_with(b"--target-dir=") {
            return None;
        }
        if arg == b"--manifest-path" {
            let value = operands.next()?;
            if value.is_empty() || value.starts_with(b"-") {
                return None;
            }
            manifest = ManifestRequest::Explicit(value);
        } else if let Some(value) = arg.strip_prefix(b"--manifest-path=") {
            if value.is_empty() {
                return None;
            }
            manifest = ManifestRequest::Explicit(value);
        } else if arg == b"--config" || cargo_value_option(arg) {
            operands.next()?;
        } else if command.is_none() && !arg.starts_with(b"-") && !arg.starts_with(b"+") {
            command = Some(arg);
        }
    }
    matches!(
        command?,
        b"build"
            | b"b"
            | b"check"
            | b"c"
            | b"test"
            | b"t"
            | b"run"
            | b"r"
            | b"bench"
            | b"doc"
            | b"d"
            | b"rustc"
            | b"rustdoc"
            | b"clippy"
            | b"fix"
            | b"nextest"
            | b"package"
            | b"publish"
    )
    .then_some(manifest)
}

#[cfg(test)]
mod tests {
    use super::super::{Evidence, TOTAL_BYTES};
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::ffi::OsStringExt as _;

    const ARGV: &[u8] = b"cargo\0build\0";

    #[derive(Default)]
    struct Files {
        data: BTreeMap<PathBuf, Vec<u8>>,
        reads: Vec<PathBuf>,
        denied: Option<PathBuf>,
    }

    impl Files {
        fn put(&mut self, path: &str, text: &str) {
            self.data.insert(path.into(), text.as_bytes().to_vec());
        }

        fn read(&mut self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            self.reads.push(path.to_path_buf());
            if self.denied.as_deref() == Some(path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let raw = self.data.get(path).ok_or(io::ErrorKind::NotFound)?;
            if raw.len() > limit {
                return Err(io::Error::other("too large"));
            }
            Ok(raw.clone())
        }

        fn observe(&mut self, resolver: &mut Resolver, argv: &[u8], env: &[u8]) -> Evidence {
            resolver.observe(
                argv,
                env,
                Some(Path::new("/work/project")),
                |path, limit| self.read(path, limit),
            )
        }
    }

    #[test]
    fn a_standalone_build_holds_default_outputs_before_any_artifact_exists() {
        let mut files = Files::default();
        files.put(
            "/work/project/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"HOME=/builder\0");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/work/project/target")]
        );
        assert!(
            !files
                .reads
                .iter()
                .any(|path| path.starts_with("/work/project/target"))
        );
    }

    /// Cargo's built-in aliases build into the same default target.
    #[test]
    fn built_in_aliases_hold_the_default_target() {
        let mut files = Files::default();
        files.put(
            "/work/project/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'",
        );
        for argv in [
            b"cargo\0b\0".as_slice(),
            b"cargo\0c\0",
            b"cargo\0t\0",
            b"cargo\0r\0",
            b"cargo\0d\0",
        ] {
            let found = files.observe(&mut Resolver::default(), argv, b"HOME=/builder\0");
            assert!(found.complete);
            assert_eq!(
                found.directories,
                vec![PathBuf::from("/work/project/target")],
                "{}",
                String::from_utf8_lossy(argv)
            );
        }
    }

    #[test]
    fn workspace_members_hold_shared_outputs_and_the_excluded_package_possibility() {
        let mut files = Files::default();
        files.put(
            "/work/project/Cargo.toml",
            "[package]\nname='member'\nversion='0.1.0'",
        );
        files.put("/work/Cargo.toml", "[workspace]\nmembers=['project']");
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                PathBuf::from("/work/project/target"),
                PathBuf::from("/work/target")
            ]
        );
        files.put("/work/project/Cargo.toml", "[workspace]\nmembers=[]");
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/work/project/target")]
        );
    }

    #[test]
    fn explicit_external_workspace_is_verified_without_following_pointer_cycles() {
        let mut files = Files::default();
        files.put(
            "/work/project/Cargo.toml",
            "[package]\nworkspace='/shared/workspace'",
        );
        files.put(
            "/shared/workspace/Cargo.toml",
            "[workspace]\nmembers=['/work/project']",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/shared/workspace/target")]
        );
        files.put(
            "/shared/workspace/Cargo.toml",
            "[package]\nworkspace='/work/project'",
        );
        let before = files.reads.len();
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert!(found.directories.is_empty());
        assert!(files.reads.len() - before < 16);
    }

    #[test]
    fn explicit_manifest_selects_its_project_not_the_observers_cwd() {
        let mut files = Files::default();
        files.put("/work/project/Cargo.toml", "[workspace]");
        files.put("/other/Cargo.toml", "[workspace]");
        let found = files.observe(
            &mut Resolver::default(),
            b"cargo\0check\0--manifest-path=/other/Cargo.toml\0",
            b"",
        );
        assert!(found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/other/target")]);
        assert!(
            !files
                .reads
                .contains(&PathBuf::from("/work/project/Cargo.toml"))
        );
    }

    #[test]
    fn configured_targets_suppress_default_but_split_intermediates_do_not() {
        let mut files = Files::default();
        files.put("/work/project/Cargo.toml", "[workspace]");
        for (argv, env) in [
            (ARGV, b"CARGO_TARGET_DIR=/elsewhere\0".as_slice()),
            (ARGV, b"CARGO_BUILD_TARGET_DIR=/elsewhere\0"),
            (b"cargo\0build\0--target-dir=/elsewhere\0", b""),
            (b"cargo\0build\0--target-dir\0/elsewhere\0", b""),
            (
                b"cargo\0build\0--config=build.target-dir='/elsewhere'\0",
                b"",
            ),
        ] {
            files.reads.clear();
            let found = files.observe(&mut Resolver::default(), argv, env);
            assert!(found.complete);
            assert!(
                !found
                    .directories
                    .contains(&PathBuf::from("/work/project/target"))
            );
            assert!(
                !files
                    .reads
                    .contains(&PathBuf::from("/work/project/Cargo.toml"))
            );
        }
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\nbuild-dir='/intermediate'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                PathBuf::from("/intermediate"),
                PathBuf::from("/work/project/target")
            ]
        );
    }

    #[test]
    fn manifest_failure_keeps_known_intermediates_without_certifying_absence() {
        let mut files = Files::default();
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\nbuild-dir='/known'",
        );
        for text in ["invalid TOML", "[package]\nworkspace=7", "[unrelated]"] {
            files.put("/work/project/Cargo.toml", text);
            let found = files.observe(&mut Resolver::default(), ARGV, b"");
            assert!(!found.complete, "{text}");
            assert_eq!(found.directories, vec![PathBuf::from("/known")]);
        }
        files.denied = Some("/work/project/Cargo.toml".into());
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/known")]);
    }

    #[test]
    fn unreadable_ancestor_keeps_the_readable_package_scope_as_partial() {
        let mut files = Files::default();
        files.put("/work/project/Cargo.toml", "[package]");
        files.denied = Some("/work/Cargo.toml".into());
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/work/project/target")]
        );
    }

    #[test]
    fn ordinary_commands_and_forwarded_arguments_do_not_invent_manifest_queries() {
        let mut files = Files::default();
        files.put("/work/project/Cargo.toml", "[workspace]");
        for argv in [
            b"cargo\0metadata\0".as_slice(),
            b"cargo\0install\0package\0",
            b"cargo\0--config\0build\0",
            b"cargo\0--\0build\0",
        ] {
            files.reads.clear();
            let found = files.observe(&mut Resolver::default(), argv, b"");
            assert!(found.directories.is_empty());
            assert!(
                !files
                    .reads
                    .iter()
                    .any(|path| path.file_name().is_some_and(|n| n == "Cargo.toml"))
            );
        }
        let found = files.observe(
            &mut Resolver::default(),
            b"cargo\0run\0--\0--manifest-path=/not-ours/Cargo.toml\0",
            b"",
        );
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/work/project/target")]
        );
        assert!(!files.reads.contains(&PathBuf::from("/not-ours/Cargo.toml")));
    }

    #[test]
    fn native_manifest_path_bytes_are_preserved_in_the_default_target() {
        let mut files = Files::default();
        let manifest = PathBuf::from(std::ffi::OsString::from_vec(
            b"/project-\xff/Cargo.toml".to_vec(),
        ));
        files.data.insert(manifest, b"[workspace]".to_vec());
        let found = files.observe(
            &mut Resolver::default(),
            b"cargo\0build\0--manifest-path\0/project-\xff/Cargo.toml\0",
            b"",
        );
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from(std::ffi::OsString::from_vec(
                b"/project-\xff/target".to_vec()
            ))]
        );
    }

    #[test]
    fn manifest_reads_share_cache_and_aggregate_admission_with_configuration() {
        let mut files = Files::default();
        files.put("/work/project/Cargo.toml", "[workspace]");
        let mut resolver = Resolver::default();
        let first = files.observe(&mut resolver, ARGV, b"");
        let before = files.reads.len();
        let second = files.observe(&mut resolver, ARGV, b"");
        assert_eq!(first.directories, second.directories);
        assert_eq!(before, files.reads.len());
        let mut full = Resolver {
            bytes: TOTAL_BYTES,
            ..Resolver::default()
        };
        files.reads.clear();
        let found = files.observe(&mut full, ARGV, b"");
        assert!(!found.complete);
        assert!(found.directories.is_empty());
        assert!(files.reads.is_empty());
    }

    #[test]
    fn missing_explicit_manifest_and_unterminated_environment_remain_unknown() {
        let mut files = Files::default();
        let found = files.observe(
            &mut Resolver::default(),
            b"cargo\0build\0--manifest-path=/absent/Cargo.toml\0",
            b"",
        );
        assert!(!found.complete);
        files.put("/work/project/Cargo.toml", "[workspace]");
        let found = files.observe(
            &mut Resolver::default(),
            ARGV,
            b"OTHER=complete\0CARGO_TARGET_DIR=/tail",
        );
        assert!(!found.complete);
        assert!(found.directories.is_empty());
    }
}
