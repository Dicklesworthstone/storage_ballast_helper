//! Read-only, bounded evidence for configured and default Cargo outputs.
//!
//! This is a deny-only observer, not Cargo's configuration evaluator. Retain
//! destinations from all observed layers rather than guessing which override
//! wins. Never run Cargo, evaluate aliases, expand workspace templates, or read
//! this process's HOME. Only an identified Cargo invocation enters this module.
//! The cache lives for one process sweep: neither absence nor a destination is
//! remembered across sweeps. Observations are not atomic filesystem snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

mod default_outputs;

const FILE_BYTES: usize = 64 * 1024;
const TOTAL_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 512;
const MAX_PATH_BYTES: usize = 8192;
const MAX_ANCESTORS: usize = 32;
const MAX_VISITS: usize = 128;
const MAX_INCLUDE_DEPTH: usize = 8;
const MAX_DESTINATIONS: usize = 128;
const MAX_CLI_CONFIGS: usize = 32;

/// Positive directories and whether the attempted configuration observation
/// finished. This does not certify complete process or configuration coverage.
pub struct Evidence {
    pub directories: Vec<PathBuf>,
    pub complete: bool,
}

#[derive(Clone)]
struct Include {
    path: PathBuf,
    optional: bool,
}

#[derive(Clone, Default)]
struct Parsed {
    destinations: Vec<String>,
    includes: Vec<Include>,
    incomplete: bool,
    target_override: bool,
    manifest: default_outputs::Manifest,
}

#[derive(Clone)]
enum Cached {
    Missing,
    Unavailable,
    Present(Parsed),
}

/// Per-sweep cache with aggregate input, pathname and probe bounds. Only the
/// selected directory fields are retained, never unrelated configuration data.
#[derive(Default)]
pub struct Resolver {
    files: BTreeMap<PathBuf, Cached>,
    bytes: usize,
    path_bytes: usize,
}

struct Observation {
    paths: BTreeSet<PathBuf>,
    complete: bool,
    visits: usize,
    target_override: bool,
}

impl Observation {
    fn add(&mut self, base: Option<&Path>, value: &str) {
        let path = Path::new(value);
        if value.is_empty() || value.len() > MAX_PATH_BYTES {
            self.complete = false;
            return;
        }
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else if let Some(base) = base.filter(|base| base.is_absolute()) {
            // Do not lexically erase '..': an intervening symlink matters.
            base.join(path)
        } else {
            self.complete = false;
            return;
        };
        if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
            || (!self.paths.contains(&path) && self.paths.len() >= MAX_DESTINATIONS)
        {
            self.complete = false;
        } else {
            self.paths.insert(path);
        }
    }
}

/// Only complete argv for a known Cargo executable authorizes config reads.
/// rustc/build-script/rch processes retain their independent env/argv evidence.
pub fn is_cargo(argv: &[u8]) -> bool {
    let Some(raw) = argv.strip_suffix(b"\0") else {
        return false;
    };
    let program = raw.split(|byte| *byte == 0).next().unwrap_or_default();
    matches!(
        program.rsplit(|byte| *byte == b'/').next(),
        Some(b"cargo" | b"cargo-clippy" | b"cargo-rch-real" | b"cargo-nextest")
    )
}

impl Resolver {
    /// Observe conventional hierarchy/home files, explicit --config files and
    /// inline build directory values. `read` must enforce the caller's shared
    /// deadline before I/O; this layer enforces byte, path, depth and work caps.
    /// A missing HOME is not replaced with the observer's account information.
    pub fn observe(
        &mut self,
        argv: &[u8],
        environment: &[u8],
        cwd: Option<&Path>,
        mut read: impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) -> Evidence {
        let mut observation = Observation {
            paths: BTreeSet::new(),
            complete: true,
            visits: 0,
            target_override: [b"CARGO_TARGET_DIR".as_slice(), b"CARGO_BUILD_TARGET_DIR"]
                .iter()
                .any(|key| env_value(environment, key).is_some_and(|value| !value.is_empty())),
        };
        if !is_cargo(argv) {
            return Evidence {
                directories: Vec::new(),
                complete: false,
            };
        }
        let cwd = cwd.filter(|path| path.is_absolute());
        if let Some(cwd) = cwd {
            for (index, directory) in cwd.ancestors().enumerate() {
                if index >= MAX_ANCESTORS {
                    observation.complete = false;
                    break;
                }
                self.directory(&directory.join(".cargo"), &mut observation, &mut read);
            }
        } else {
            observation.complete = false;
        }
        // Complete explicit environment entries remain useful even if a later
        // entry was truncated. Defaults require the complete environment.
        let home = env_value(environment, b"CARGO_HOME").filter(|value| !value.is_empty());
        if let Some(home) = home {
            if let Some(home) = byte_path(home, cwd) {
                self.directory(&home, &mut observation, &mut read);
            } else {
                observation.complete = false;
            }
        } else if environment.ends_with(b"\0")
            && let Some(home) =
                env_value(environment, b"HOME").and_then(|home| byte_path(home, None))
        {
            self.directory(&home.join(".cargo"), &mut observation, &mut read);
        }
        self.command_line(argv, cwd, &mut observation, &mut read);
        // Resolve the manifest's default output scope before the first
        // compiler child or artifact exists. An observed target override
        // suppresses that default; an independent build-dir override does not.
        if !observation.target_override {
            if !environment.is_empty() && !environment.ends_with(b"\0") {
                observation.complete = false;
            } else if let Some(request) = default_outputs::request(argv) {
                self.default_target(request, cwd, &mut observation, &mut read);
            }
        }
        Evidence {
            directories: observation.paths.into_iter().collect(),
            complete: observation.complete,
        }
    }

    fn cached(
        &mut self,
        path: &Path,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) -> Cached {
        if let Some(cached) = self.files.get(path) {
            return cached.clone();
        }
        let path_bytes = path.as_os_str().as_encoded_bytes().len();
        if !path.is_absolute()
            || path_bytes > MAX_PATH_BYTES
            || self.files.len() >= MAX_FILES
            || path_bytes > TOTAL_BYTES.saturating_sub(self.path_bytes)
            || self.bytes >= TOTAL_BYTES
        {
            return Cached::Unavailable;
        }
        let limit = FILE_BYTES.min(TOTAL_BYTES - self.bytes);
        let cached = match read(path, limit) {
            Ok(raw) if raw.len() <= limit => {
                self.bytes += raw.len();
                parse(&raw).map_or(Cached::Unavailable, Cached::Present)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Cached::Missing,
            // A reader may have consumed the full allowance before refusing.
            // Charge failed attempts too; errors cannot evade the byte budget.
            Ok(_) | Err(_) => {
                self.bytes += limit;
                Cached::Unavailable
            }
        };
        self.path_bytes += path_bytes;
        self.files.insert(path.to_path_buf(), cached.clone());
        cached
    }

    fn directory(
        &mut self,
        directory: &Path,
        observation: &mut Observation,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) {
        let legacy = directory.join("config");
        // Cargo prefers the extensionless file when both spellings exist.
        // An unreadable legacy file is not proof of its absence.
        match self.cached(&legacy, read) {
            Cached::Missing => {
                self.file(&directory.join("config.toml"), true, 0, observation, read);
            }
            Cached::Unavailable => observation.complete = false,
            Cached::Present(_) => self.file(&legacy, false, 0, observation, read),
        }
    }

    fn file(
        &mut self,
        path: &Path,
        optional: bool,
        depth: usize,
        observation: &mut Observation,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) {
        if observation.visits >= MAX_VISITS || depth > MAX_INCLUDE_DEPTH {
            observation.complete = false;
            return;
        }
        observation.visits += 1;
        match self.cached(path, read) {
            Cached::Missing => observation.complete &= optional,
            Cached::Unavailable => observation.complete = false,
            Cached::Present(parsed) => {
                // File-defined values are relative to TWO levels above the
                // config file, including files supplied with --config.
                let base = path.parent().and_then(Path::parent);
                observation.complete &= !parsed.incomplete;
                observation.target_override |= parsed.target_override;
                for value in parsed.destinations {
                    observation.add(base, &value);
                }
                for include in parsed.includes {
                    // Include paths, unlike build paths, are relative to the
                    // including file's immediate directory. Cycles and repeated
                    // DAG visits are bounded even through pathname aliases.
                    let included = if include.path.is_absolute() {
                        include.path
                    } else if let Some(parent) = path.parent() {
                        parent.join(include.path)
                    } else {
                        observation.complete = false;
                        continue;
                    };
                    self.file(&included, include.optional, depth + 1, observation, read);
                }
            }
        }
    }

    fn command_line(
        &mut self,
        argv: &[u8],
        cwd: Option<&Path>,
        observation: &mut Observation,
        read: &mut impl FnMut(&Path, usize) -> io::Result<Vec<u8>>,
    ) {
        let mut operands = argv[..argv.len() - 1].split(|byte| *byte == 0).skip(1);
        let mut count = 0;
        while let Some(arg) = operands.next() {
            if arg == b"--" {
                break;
            }
            let value = if arg == b"--config" {
                let Some(value) = operands.next() else {
                    observation.complete = false;
                    break;
                };
                value
            } else if let Some(value) = arg.strip_prefix(b"--config=") {
                value
            } else {
                // Operands must not impersonate a new Cargo option. The
                // observed cwd already reflects Cargo's -C, if applied.
                if cargo_value_option(arg) && operands.next().is_none() {
                    observation.complete = false;
                }
                continue;
            };
            count += 1;
            if count > MAX_CLI_CONFIGS || value.is_empty() || value.starts_with(b"-") {
                observation.complete = false;
                break;
            }
            if value.contains(&b'=') {
                match parse(value) {
                    Some(parsed) => {
                        observation.complete &= !parsed.incomplete && parsed.includes.is_empty();
                        observation.target_override |= parsed.target_override;
                        for value in parsed.destinations {
                            observation.add(cwd, &value);
                        }
                    }
                    None => observation.complete = false,
                }
            } else if let Some(path) = byte_path(value, cwd) {
                self.file(&path, false, 0, observation, read);
            } else {
                observation.complete = false;
            }
        }
    }
}

fn cargo_value_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"--manifest-path"
            | b"--target-dir"
            | b"--build-dir"
            | b"--target"
            | b"--package"
            | b"-p"
            | b"--exclude"
            | b"--features"
            | b"-F"
            | b"--jobs"
            | b"-j"
            | b"--profile"
            | b"--message-format"
            | b"--color"
            | b"--lockfile-path"
            | b"--bin"
            | b"--example"
            | b"--test"
            | b"--bench"
            | b"-C"
            | b"-Z"
    )
}

fn env_value<'a>(raw: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    raw.split_inclusive(|byte| *byte == 0).find_map(|entry| {
        let entry = entry.strip_suffix(b"\0")?;
        let suffix = entry.strip_prefix(key)?.strip_prefix(b"=")?;
        Some(suffix)
    })
}

fn byte_path(raw: &[u8], cwd: Option<&Path>) -> Option<PathBuf> {
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return None;
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec()));
    let path = if path.is_absolute() {
        path
    } else {
        cwd?.join(path)
    };
    (path.is_absolute() && path.as_os_str().as_encoded_bytes().len() <= MAX_PATH_BYTES)
        .then_some(path)
}

fn parse(raw: &[u8]) -> Option<Parsed> {
    if raw.len() > FILE_BYTES {
        return None;
    }
    let document: toml::Value = toml::from_str(std::str::from_utf8(raw).ok()?).ok()?;
    let mut parsed = Parsed::default();
    if let Some(build) = document.get("build") {
        if build.is_table() {
            parsed.target_override = build.get("target-dir").is_some();
            for key in ["target-dir", "build-dir"] {
                if let Some(value) = build.get(key) {
                    if let Some(value) = value.as_str().filter(|value| {
                        !value.is_empty()
                            && value.len() <= MAX_PATH_BYTES
                            && !(key == "build-dir" && (value.contains('{') || value.contains('}')))
                    }) {
                        parsed.destinations.push(value.to_owned());
                    } else {
                        parsed.incomplete = true;
                    }
                }
            }
        } else {
            parsed.incomplete = true;
        }
    }
    if let Some(includes) = document.get("include") {
        if let Some(includes) = includes.as_array() {
            for include in includes.iter().take(MAX_CLI_CONFIGS) {
                let (path, optional) = include.as_str().map_or_else(
                    || {
                        (
                            include.get("path").and_then(toml::Value::as_str),
                            include
                                .get("optional")
                                .map_or(Some(false), toml::Value::as_bool),
                        )
                    },
                    |path| (Some(path), Some(false)),
                );
                if let (Some(path), Some(optional)) = (path, optional)
                    && !path.is_empty()
                    && path.len() <= MAX_PATH_BYTES
                    && Path::new(path)
                        .extension()
                        .is_some_and(|extension| extension == "toml")
                {
                    parsed.includes.push(Include {
                        path: path.into(),
                        optional,
                    });
                } else {
                    parsed.incomplete = true;
                }
            }
            parsed.incomplete |= includes.len() > MAX_CLI_CONFIGS;
        } else {
            parsed.incomplete = true;
        }
    }
    parsed.manifest = default_outputs::parse_manifest(&document);
    Some(parsed)
}

/// Bounded regular-file reader used for configuration only. Resolve legitimate
/// dotfile symlinks, reject special files, then verify the opened observation.
/// No write handles, subprocesses or configuration error text are exposed.
pub fn read_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    read_file_with(path, limit, || {})
}

fn read_file_with(path: &Path, limit: usize, before_verify: impl FnOnce()) -> io::Result<Vec<u8>> {
    // Only absence on the first observation can mean an optional layer is
    // missing. Once it existed, ENOENT from opening, reading or revalidation
    // means a changed observation, not Cached::Missing. Otherwise a live
    // Cargo config renamed mid-read silently removes its output protection.
    fs::symlink_metadata(path)?;
    read_observed_file(path, limit, before_verify).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::other("Cargo configuration disappeared during observation")
        } else {
            error
        }
    })
}

fn read_observed_file(
    path: &Path,
    limit: usize,
    before_verify: impl FnOnce(),
) -> io::Result<Vec<u8>> {
    let resolved = fs::canonicalize(path)
        .map_err(|_| io::Error::other("Cargo configuration path cannot be resolved"))?;
    let before = fs::symlink_metadata(&resolved)?;
    if !before.is_file() || before.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(io::Error::other(
            "Cargo configuration is not a bounded regular file",
        ));
    }
    let file = open_config(&resolved)?;
    let opened = file.metadata()?;
    if !same_file(&before, &opened) {
        return Err(io::Error::other(
            "Cargo configuration changed before observation",
        ));
    }
    let mut raw = Vec::new();
    (&file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() > limit || !same_file(&opened, &file.metadata()?) {
        return Err(io::Error::other(
            "Cargo configuration changed during observation",
        ));
    }
    // Production passes a no-op. The seam is between descriptor and pathname
    // verification: a rename here cannot already have been caught by fstat.
    before_verify();
    if !same_file(&opened, &fs::metadata(path)?) {
        return Err(io::Error::other(
            "Cargo configuration changed during observation",
        ));
    }
    Ok(raw)
}

/// Open a configuration file for reading. Any local user can name the path
/// (`cargo --config <path>`, `--manifest-path`, an include) and the daemon
/// reads it as root. On Linux no symlink is followed anywhere in the already
/// canonical path, so a directory swapped for a link into /dev between the
/// checks above and this open cannot make root open a device, and a file on
/// a kernel pseudo-filesystem is refused before a byte is read: reading
/// /proc/kmsg as root drains the kernel log.
#[cfg(target_os = "linux")]
fn open_config(resolved: &Path) -> io::Result<fs::File> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstatfs, openat2};

    let file = fs::File::from(openat2(
        CWD,
        resolved,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    if is_pseudo_filesystem(fstatfs(&file)?.f_type) {
        return Err(io::Error::other(
            "Cargo configuration is on a kernel pseudo-filesystem",
        ));
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_config(resolved: &Path) -> io::Result<fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(resolved)
}

/// procfs, sysfs, debugfs, tracefs, securityfs, configfs, efivarfs, pstore,
/// bpffs and cgroup v1/v2 (`statfs(2)` magic numbers): never where a Cargo
/// configuration lives, and reading some of their files has side effects.
#[cfg(target_os = "linux")]
fn is_pseudo_filesystem<T>(f_type: T) -> bool
where
    u32: TryFrom<T>,
{
    const PSEUDO: [u32; 11] = [
        0x0000_9fa0, // proc
        0x6265_6572, // sysfs
        0x6462_6720, // debugfs
        0x7472_6163, // tracefs
        0x7363_6673, // securityfs
        0x6265_6570, // configfs
        0xde5e_81e4, // efivarfs
        0x6165_676c, // pstore
        0xcafe_4a11, // bpf
        0x0027_e0eb, // cgroup
        0x6367_7270, // cgroup2
    ];
    u32::try_from(f_type).is_ok_and(|magic| PSEUDO.contains(&magic))
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    b.is_file()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
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
    fn hierarchy_and_home_outputs_are_positive_even_when_a_nearer_layer_overrides() {
        let mut files = Files::default();
        files.put("/work/.cargo/config.toml", "[build]\ntarget-dir = 'outer'");
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\ntarget-dir = '/final'\nbuild-dir = '../intermediate'",
        );
        files.put(
            "/builder/.cargo/config.toml",
            "[build]\ntarget-dir = 'shared'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"HOME=/builder\0");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                PathBuf::from("/builder/shared"),
                PathBuf::from("/final"),
                PathBuf::from("/work/outer"),
                PathBuf::from("/work/project/../intermediate"),
            ]
        );
    }

    #[test]
    fn extensionless_config_wins_and_an_unreadable_one_is_not_absent() {
        let mut files = Files::default();
        files.put(
            "/work/project/.cargo/config",
            "[build]\ntarget-dir = '/legacy'",
        );
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\ntarget-dir = '/ignored'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/legacy")]);
        assert!(
            !files
                .reads
                .contains(&PathBuf::from("/work/project/.cargo/config.toml"))
        );
        files.denied = Some("/work/project/.cargo/config".into());
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert!(found.directories.is_empty());
    }

    #[test]
    fn inline_and_explicit_file_paths_use_their_different_cargo_bases() {
        let mut files = Files::default();
        files.put(
            "/work/project/config/extra.toml",
            "[build]\nbuild-dir = 'objects'",
        );
        let args =
            b"cargo\0build\0--config\0config/extra.toml\0--config=build.target-dir='final'\0";
        let found = files.observe(&mut Resolver::default(), args, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                PathBuf::from("/work/project/final"),
                PathBuf::from("/work/project/objects")
            ]
        );
    }

    #[test]
    fn forwarded_arguments_and_other_option_operands_cannot_request_file_reads() {
        let mut files = Files::default();
        for args in [
            b"cargo\0run\0--\0--config=/secret.toml\0".as_slice(),
            b"cargo\0build\0--manifest-path\0--config=/secret.toml\0",
        ] {
            let found = files.observe(&mut Resolver::default(), args, b"");
            assert!(found.complete);
            assert!(found.directories.is_empty());
            assert!(!files.reads.contains(&PathBuf::from("/secret.toml")));
        }
        for args in [
            b"rustc\0--config=/secret.toml\0".as_slice(),
            b"cargo-notes\0",
            b"cargo\0build",
        ] {
            files.reads.clear();
            assert!(!files.observe(&mut Resolver::default(), args, b"").complete);
            assert!(files.reads.is_empty());
        }
    }

    #[test]
    fn required_optional_and_recursive_includes_have_bounded_observation() {
        let mut files = Files::default();
        files.put(
            "/work/project/.cargo/config.toml",
            "include = ['shared.toml', {path='absent.toml', optional=true}]\n[build]\ntarget-dir='/final'",
        );
        files.put(
            "/work/project/.cargo/shared.toml",
            "[build]\nbuild-dir='intermediate'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                PathBuf::from("/final"),
                PathBuf::from("/work/project/intermediate")
            ]
        );
        files.put(
            "/work/project/.cargo/shared.toml",
            "include=['missing.toml']\n[build]\nbuild-dir='/known'",
        );
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert!(found.directories.contains(&PathBuf::from("/known")));
        files.put(
            "/work/project/.cargo/shared.toml",
            "include=['shared.toml']\n[build]\nbuild-dir='/cycle-positive'",
        );
        let before = files.reads.len();
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert!(
            found
                .directories
                .contains(&PathBuf::from("/cycle-positive"))
        );
        assert!(
            files.reads.len() - before < 16,
            "a cycle must not repeat I/O"
        );
    }

    #[test]
    fn malformed_layers_templates_and_deadlines_keep_independent_positives() {
        let mut files = Files::default();
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\ntarget-dir='/known'\nbuild-dir='{workspace-root}/objects'",
        );
        files.put("/work/.cargo/config.toml", "not valid TOML");
        let found = files.observe(&mut Resolver::default(), ARGV, b"");
        assert!(!found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/known")]);
        let mut resolver = Resolver::default();
        let found = resolver.observe(
            b"cargo\0--config=build.target-dir='/inline'\0",
            b"",
            Some(Path::new("/work")),
            |_, _| Err(io::ErrorKind::TimedOut.into()),
        );
        assert!(!found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/inline")]);
    }

    #[test]
    fn cache_is_shared_within_a_sweep_not_across_sweeps() {
        let mut files = Files::default();
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\ntarget-dir='/first'",
        );
        let mut resolver = Resolver::default();
        let first = files.observe(&mut resolver, ARGV, b"HOME=/builder\0");
        let reads = files.reads.len();
        files.put(
            "/work/project/.cargo/config.toml",
            "[build]\ntarget-dir='/next'",
        );
        let second = files.observe(&mut resolver, ARGV, b"HOME=/builder\0");
        assert_eq!(first.directories, second.directories);
        assert_eq!(reads, files.reads.len());
        let fresh = files.observe(&mut Resolver::default(), ARGV, b"HOME=/builder\0");
        assert_eq!(fresh.directories, vec![PathBuf::from("/next")]);
    }

    #[test]
    fn missing_cwd_does_not_erase_absolute_inline_or_home_evidence() {
        let mut files = Files::default();
        files.put(
            "/selected/config.toml",
            "[build]\ntarget-dir='/home-output'",
        );
        let found = Resolver::default().observe(
            b"cargo\0--config=build.build-dir='/inline'\0",
            b"CARGO_HOME=/selected\0HOME=/wrong\0",
            None,
            |path, limit| files.read(path, limit),
        );
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/home-output"), PathBuf::from("/inline")]
        );
        assert!(!files.reads.iter().any(|path| path.starts_with("/wrong")));
    }

    #[test]
    fn input_and_aggregate_limits_cannot_certify_missing_evidence() {
        let mut files = Files::default();
        files.data.insert(
            "/work/project/.cargo/config.toml".into(),
            vec![b' '; FILE_BYTES + 1],
        );
        assert!(!files.observe(&mut Resolver::default(), ARGV, b"").complete);
        let mut resolver = Resolver {
            bytes: TOTAL_BYTES,
            ..Resolver::default()
        };
        files.reads.clear();
        assert!(!files.observe(&mut resolver, ARGV, b"").complete);
        assert!(files.reads.is_empty());
        let mut args = b"cargo\0".to_vec();
        for _ in 0..=MAX_CLI_CONFIGS {
            args.extend_from_slice(b"--config=build.target-dir='/one'\0");
        }
        let found = files.observe(&mut Resolver::default(), &args, b"");
        assert!(!found.complete);
        assert_eq!(found.directories, vec![PathBuf::from("/one")]);
    }

    #[test]
    fn byte_named_config_paths_and_relative_symlink_spelling_are_preserved() {
        let mut files = Files::default();
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/work/project/cfg-\xff/extra.toml".to_vec(),
        ));
        files
            .data
            .insert(path.clone(), b"[build]\ntarget-dir='../out'".to_vec());
        let found = files.observe(
            &mut Resolver::default(),
            b"cargo\0--config\0cfg-\xff/extra.toml\0",
            b"",
        );
        assert!(found.complete);
        assert!(files.reads.contains(&path));
        assert_eq!(
            found.directories,
            vec![PathBuf::from("/work/project/../out")]
        );
    }

    #[test]
    fn real_reader_accepts_dotfile_aliases_but_refuses_special_and_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(&path, b"[build]\ntarget-dir='out'").unwrap();
        let alias = temp.path().join("alias.toml");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert_eq!(
            read_file(&alias, FILE_BYTES).unwrap(),
            fs::read(&path).unwrap()
        );
        assert!(read_file(&path, 2).is_err());
        let fifo = temp.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read_file(&fifo, FILE_BYTES).is_err());
        assert!(read_file(temp.path(), FILE_BYTES).is_err());
        let broken = temp.path().join("broken.toml");
        std::os::unix::fs::symlink(temp.path().join("missing"), &broken).unwrap();
        assert_ne!(
            read_file(&broken, FILE_BYTES).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn only_initial_absence_is_an_optional_missing_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let absent = temp.path().join("absent.toml");
        assert_eq!(
            read_file(&absent, FILE_BYTES).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let mut resolver = Resolver::default();
        assert!(matches!(
            resolver.cached(&absent, &mut read_file),
            Cached::Missing
        ));
    }

    #[test]
    fn disappearing_optional_layer_is_unavailable_and_preserves_other_positives() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let saved = temp.path().join("saved.toml");
        fs::write(&path, b"[build]\ntarget-dir='/active'").unwrap();
        let mut observation = Observation {
            paths: BTreeSet::from([PathBuf::from("/independent")]),
            complete: true,
            visits: 0,
            target_override: false,
        };
        let mut resolver = Resolver::default();
        resolver.file(&path, true, 0, &mut observation, &mut |path, limit| {
            read_file_with(path, limit, || fs::rename(path, &saved).unwrap())
        });
        assert!(
            !observation.complete,
            "an optional layer existed but was lost mid-read"
        );
        assert_eq!(
            observation.paths,
            BTreeSet::from([PathBuf::from("/independent")])
        );
        assert!(matches!(
            resolver.cached(&path, &mut |_, _| panic!("cached failure must not retry")),
            Cached::Unavailable
        ));
        assert_eq!(fs::read(saved).unwrap(), b"[build]\ntarget-dir='/active'");
    }

    #[test]
    fn replacement_inode_cannot_validate_bytes_from_the_old_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let saved = temp.path().join("saved.toml");
        let bytes = b"[build]\ntarget-dir='/active'";
        fs::write(&path, bytes).unwrap();
        let result = read_file_with(&path, FILE_BYTES, || {
            fs::rename(&path, &saved).unwrap();
            fs::write(&path, bytes).unwrap();
        });
        assert!(
            result.is_err(),
            "same bytes and length do not preserve inode identity"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(saved).unwrap(), bytes);
    }

    #[test]
    fn same_inode_change_after_read_is_not_a_valid_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(&path, b"[build]\ntarget-dir='/a'").unwrap();
        let result = read_file_with(&path, FILE_BYTES, || {
            fs::write(&path, b"[build]\ntarget-dir='/different-output'").unwrap();
        });
        assert!(result.is_err());
    }

    #[test]
    fn retargeted_alias_invalidates_the_observation_without_reading_the_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original.toml");
        let replacement = temp.path().join("replacement.toml");
        let alias = temp.path().join("config.toml");
        let saved_alias = temp.path().join("saved-alias.toml");
        fs::write(&original, b"[build]\ntarget-dir='/original'").unwrap();
        fs::write(&replacement, b"[build]\ntarget-dir='/replacement'").unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let result = read_file_with(&alias, FILE_BYTES, || {
            fs::rename(&alias, &saved_alias).unwrap();
            std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(&original).unwrap(),
            b"[build]\ntarget-dir='/original'"
        );
        assert_eq!(
            fs::read(&replacement).unwrap(),
            b"[build]\ntarget-dir='/replacement'"
        );
    }

    /// A local user names the path and the daemon reads it as root: a regular
    /// file on procfs (as /proc/kmsg is, whose read drains the kernel log)
    /// is refused before any byte is read.
    #[cfg(target_os = "linux")]
    #[test]
    fn configuration_on_a_kernel_pseudo_filesystem_is_never_read() {
        let error = read_file(Path::new("/proc/self/status"), FILE_BYTES).unwrap_err();
        assert!(error.to_string().contains("pseudo-filesystem"), "{error}");
        assert!(is_pseudo_filesystem(0x9fa0_i64));
        assert!(is_pseudo_filesystem(0xde5e_81e4_u32));
        assert!(!is_pseudo_filesystem(0xef53_i64), "ext4");
        assert!(!is_pseudo_filesystem(-1_i64));
    }
}
