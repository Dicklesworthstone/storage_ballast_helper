//! Positive cache-directory evidence for active build tools.
//!
//! Callers bound the input and provide the observed process cwd. This parser
//! reads only documented directory keys, never the daemon's environment. It
//! produces positive references, not proof that an unlisted path is unused.
//!
//! Conventional caches are inferred only for identified build/package tools,
//! from that process's environment, and only when its buffer is complete.
//! Explicit overrides suppress defaults even when they cannot be resolved.
//! Ordinary Node/Python processes do not imply package-manager cache use.
//! Configuration files, command-line overrides, mount namespaces and runtime
//! environment changes can name additional directories. This positive-only
//! evidence is not an exhaustive configuration resolver.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Rust,
    Go,
    Node,
    Npm,
    Python,
    Pip,
    Uv,
    Compiler,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheLayout {
    // Built only by the Linux sweep, and by tests on every platform.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Linux,
    MacOs,
}

pub fn tool(comm: &[u8]) -> Option<Tool> {
    let name = std::str::from_utf8(comm).ok()?.trim_end();
    match name {
        // rch installs its wrapper as `cargo` and renames the real one
        // `cargo-rch-real`: on rch hosts that is the cargo process, so it was
        // never recognised and a live build held its cargo home only while a
        // rustc ran (a release proof deleted it during a build script).
        // `rch exec -- cargo build` runs the build on a worker: locally only
        // `rch` lives, holding nothing open in its CARGO_TARGET_DIR until it
        // syncs the artifacts back (ts2 2026-10-15: an empty mktemp target
        // was deleted mid-build and recreated by the sync-back).
        "cargo" | "cargo-rch-real" | "cargo-nextest" | "rustc" | "rustdoc" | "clippy-driver"
        | "cargo-clippy" | "rch" => Some(Tool::Rust),
        // A build script runs with cargo's environment and its package as cwd;
        // procfs truncates its name (`build_script_ma` for build_script_main).
        _ if ["build-script-", "build_script_"]
            .iter()
            .any(|prefix| name.starts_with(prefix)) =>
        {
            Some(Tool::Rust)
        }
        "go" | "compile" | "link" | "cgo" => Some(Tool::Go),
        "node" | "nodejs" | "pnpm" | "yarn" | "bun" => Some(Tool::Node),
        "npm" | "npx" => Some(Tool::Npm),
        "uv" | "uvx" => Some(Tool::Uv),
        "pip" => Some(Tool::Pip),
        "python" | "pypy" => Some(Tool::Python),
        "sccache" | "ccache" | "cc" | "c++" | "gcc" | "g++" | "clang" | "clang++" | "cc1"
        | "cc1plus" => Some(Tool::Compiler),
        _ if ["npm ", "npx "]
            .iter()
            .any(|prefix| name.starts_with(prefix)) =>
        {
            Some(Tool::Npm)
        }
        _ if ["pnpm ", "yarn "]
            .iter()
            .any(|prefix| name.starts_with(prefix)) =>
        {
            Some(Tool::Node)
        }
        _ if versioned(name, "pip") => Some(Tool::Pip),
        _ if ["python", "pypy"]
            .iter()
            .any(|prefix| versioned(name, prefix)) =>
        {
            Some(Tool::Python)
        }
        _ if ["gcc-", "g++-", "clang-", "clang++-"]
            .iter()
            .any(|prefix| versioned(name, prefix)) =>
        {
            Some(Tool::Compiler)
        }
        _ => None,
    }
}

fn versioned(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Linux's procfs sweep has no argv-aware layer; macOS goes through
/// `build_invocation` with [`CacheLayout::MacOs`].
#[cfg(target_os = "linux")]
pub fn references(tool: Tool, environ: &[u8], cwd: Option<&Path>) -> Vec<PathBuf> {
    references_with_layout(CacheLayout::Linux, tool, environ, cwd)
}

pub fn references_with_layout(
    layout: CacheLayout,
    tool: Tool,
    environ: &[u8],
    cwd: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match tool {
        Tool::Rust => {
            // Cargo's home crate treats absent and empty CARGO_HOME alike.
            let home = nonempty(environ, b"CARGO_HOME").map_or_else(
                || home_subdir(environ, ".cargo"),
                |value| directory(Some(value), cwd),
            );
            if let Some(home) = home {
                for subtree in [
                    "registry/index",
                    "registry/cache",
                    "registry/src",
                    "git/db",
                    "git/checkouts",
                ] {
                    push_unique(&mut paths, home.join(subtree));
                }
            }
            add(&mut paths, environ, b"CARGO_TARGET_DIR", cwd);
        }
        Tool::Go => {
            for path in [go_build_cache(layout, environ), go_module_cache(environ)]
                .into_iter()
                .flatten()
            {
                push_unique(&mut paths, path);
            }
            add(&mut paths, environ, b"GOTMPDIR", None);
        }
        Tool::Node | Tool::Npm => {
            // npm's lowercase script environment takes precedence, including
            // an empty value: it must not fall through to an uppercase key.
            let cache = value(environ, b"npm_config_cache").or_else(|| {
                entries(environ).find_map(|(key, value)| {
                    key.eq_ignore_ascii_case(b"npm_config_cache")
                        .then_some(value)
                })
            });
            if let Some(path) = directory(cache, cwd).or_else(|| {
                (tool == Tool::Npm && cache.is_none())
                    .then(|| home_subdir(environ, ".npm"))
                    .flatten()
            }) {
                push_unique(&mut paths, path);
            }
        }
        Tool::Python | Tool::Pip | Tool::Uv => {
            add(&mut paths, environ, b"UV_CACHE_DIR", cwd);
            add(&mut paths, environ, b"PIP_CACHE_DIR", cwd);
            if tool == Tool::Uv && value(environ, b"UV_CACHE_DIR").is_none() {
                if let Some(path) = xdg_cache(environ, "uv", ".cache/uv") {
                    push_unique(&mut paths, path);
                }
            } else if tool == Tool::Pip && value(environ, b"PIP_CACHE_DIR").is_none() {
                let fallback = match layout {
                    CacheLayout::Linux => ".cache/pip",
                    CacheLayout::MacOs => "Library/Caches/pip",
                };
                if let Some(path) = xdg_cache(environ, "pip", fallback) {
                    push_unique(&mut paths, path);
                }
                // pip 26.2 added XDG_CACHE_HOME on macOS. Without resolving a
                // process's installed pip version, retain the older default
                // as another possible positive, not as additional disk bytes.
                if layout == CacheLayout::MacOs
                    && nonempty(environ, b"XDG_CACHE_HOME").is_some()
                    && let Some(path) = home_subdir(environ, fallback)
                {
                    push_unique(&mut paths, path);
                }
            }
        }
        Tool::Compiler => {}
    }
    if matches!(tool, Tool::Rust | Tool::Compiler) {
        add(&mut paths, environ, b"SCCACHE_DIR", cwd);
        add(&mut paths, environ, b"CCACHE_DIR", cwd);
    }
    paths
}

fn home_subdir(environ: &[u8], subdir: &str) -> Option<PathBuf> {
    if !environ.ends_with(b"\0") {
        return None;
    }
    directory(nonempty(environ, b"HOME"), None).map(|home| home.join(subdir))
}

fn xdg_cache(environ: &[u8], leaf: &str, fallback: &str) -> Option<PathBuf> {
    if !environ.ends_with(b"\0") {
        return None;
    }
    nonempty(environ, b"XDG_CACHE_HOME").map_or_else(
        || home_subdir(environ, fallback),
        |xdg| directory(Some(xdg), None).map(|path| path.join(leaf)),
    )
}

fn go_build_cache(layout: CacheLayout, environ: &[u8]) -> Option<PathBuf> {
    if let Some(cache) = nonempty(environ, b"GOCACHE") {
        // GOCACHE=off and relative values must not select a default instead.
        return directory(Some(cache), None);
    }
    match layout {
        CacheLayout::Linux => xdg_cache(environ, "go-build", ".cache/go-build"),
        // Go's os.UserCacheDir ignores XDG_CACHE_HOME on Darwin.
        CacheLayout::MacOs => home_subdir(environ, "Library/Caches/go-build"),
    }
}

fn go_module_cache(environ: &[u8]) -> Option<PathBuf> {
    if let Some(cache) = nonempty(environ, b"GOMODCACHE") {
        return directory(Some(cache), None);
    }
    if !environ.ends_with(b"\0") {
        return None;
    }
    nonempty(environ, b"GOPATH").map_or_else(
        || home_subdir(environ, "go/pkg/mod"),
        |gopath| {
            // Unix path lists use ':'. Go's gopathDir uses only list[0], not
            // all elements and not the first element that happens to exist.
            let first = gopath.split(|byte| *byte == b':').next();
            directory(first, None).map(|path| path.join("pkg/mod"))
        },
    )
}

fn entries(raw: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    raw.split_inclusive(|byte| *byte == 0).filter_map(|entry| {
        let entry = entry.strip_suffix(b"\0")?;
        let separator = entry.iter().position(|byte| *byte == b'=')?;
        Some((&entry[..separator], &entry[separator + 1..]))
    })
}

fn value<'a>(raw: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    // Match getenv's first entry, not every duplicate in a hostile buffer.
    entries(raw).find_map(|(name, value)| (name == key).then_some(value))
}

fn nonempty<'a>(raw: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    value(raw, key).filter(|value| !value.is_empty())
}

fn directory(value: Option<&[u8]>, cwd: Option<&Path>) -> Option<PathBuf> {
    let value = value.filter(|value| !value.is_empty())?;
    let path = PathBuf::from(OsString::from_vec(value.to_vec()));
    if path.is_absolute() {
        Some(path)
    } else {
        // Preserve .. through symlinks; resolution belongs to the caller.
        cwd.filter(|cwd| cwd.is_absolute())
            .map(|cwd| cwd.join(path))
    }
}

fn add(paths: &mut Vec<PathBuf>, environ: &[u8], key: &[u8], cwd: Option<&Path>) {
    if let Some(path) = directory(value(environ, key), cwd) {
        push_unique(paths, path);
    }
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep the original Linux contract independently testable on macOS too.
    fn references(tool: Tool, environ: &[u8], cwd: Option<&Path>) -> Vec<PathBuf> {
        references_with_layout(CacheLayout::Linux, tool, environ, cwd)
    }

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    fn cargo_paths(home: &str) -> Vec<PathBuf> {
        [
            "registry/index",
            "registry/cache",
            "registry/src",
            "git/db",
            "git/checkouts",
        ]
        .iter()
        .map(|subtree| Path::new(home).join(subtree))
        .collect()
    }

    #[test]
    fn recognized_names_cover_build_tools_without_substring_matches() {
        for name in [
            "cargo",
            "cargo-rch-real",
            "cargo-nextest",
            "rustc",
            "rustdoc",
            "clippy-driver",
            "cargo-clippy",
            "rch",
            "build-script-build",
            "build_script_ma",
            "build-script-bu",
        ] {
            assert_eq!(
                tool(format!("{name}\n").as_bytes()),
                Some(Tool::Rust),
                "{name}"
            );
        }
        for (name, family) in [
            ("go", Tool::Go),
            ("compile", Tool::Go),
            ("node", Tool::Node),
            ("npm install", Tool::Npm),
            ("pnpm run build", Tool::Node),
            ("uv", Tool::Uv),
            ("python3.13", Tool::Python),
            ("pip3", Tool::Pip),
            ("sccache", Tool::Compiler),
            ("clang-20", Tool::Compiler),
        ] {
            assert_eq!(tool(name.as_bytes()), Some(family), "{name}");
        }
        for name in [
            "bash",
            "sbh",
            "rchd",
            "cargo-data",
            "build-scripts",
            "python-notes",
            "python3..1",
            "npmx",
        ] {
            assert_eq!(tool(name.as_bytes()), None, "{name}");
        }
        assert_eq!(tool(b"rustc\xff"), None);
    }

    #[test]
    fn explicit_cargo_home_and_target_keep_the_original_contract() {
        let mut expected = cargo_paths("/cache");
        expected.push(PathBuf::from("/target"));
        assert_eq!(
            references(
                Tool::Rust,
                b"CARGO_HOME=/cache\0CARGO_TARGET_DIR=/target\0",
                None
            ),
            expected
        );
    }

    #[test]
    fn cargo_defaults_use_the_builds_home_when_override_is_absent_or_empty() {
        for env in [
            b"HOME=/build-user\0".as_slice(),
            b"HOME=/build-user\0CARGO_HOME=\0",
        ] {
            assert_eq!(
                references(Tool::Rust, env, None),
                cargo_paths("/build-user/.cargo")
            );
        }
    }

    #[test]
    fn explicit_cargo_override_never_falls_back_to_another_users_home() {
        let env = b"HOME=/fallback\0CARGO_HOME=../cargo-cache\0";
        assert!(references(Tool::Rust, env, None).is_empty());
        assert_eq!(
            references(Tool::Rust, env, Some(Path::new("/workspace/project"))),
            cargo_paths("/workspace/project/../cargo-cache")
        );
        assert_eq!(
            references(Tool::Rust, b"HOME=/fallback\0CARGO_HOME=/chosen\0", None),
            cargo_paths("/chosen")
        );
    }

    #[test]
    fn go_home_defaults_cover_both_build_and_module_caches() {
        assert_eq!(
            references(Tool::Go, b"HOME=/builder\0", None),
            paths(&["/builder/.cache/go-build", "/builder/go/pkg/mod"])
        );
    }

    #[test]
    fn go_xdg_and_first_gopath_element_override_home_defaults() {
        let env = b"HOME=/builder\0XDG_CACHE_HOME=/scratch/cache\0GOPATH=/first:/second\0";
        assert_eq!(
            references(Tool::Go, env, None),
            paths(&["/scratch/cache/go-build", "/first/pkg/mod"])
        );
    }

    #[test]
    fn explicit_go_cache_overrides_take_precedence_over_all_defaults() {
        let env = b"HOME=/builder\0XDG_CACHE_HOME=/xdg\0GOPATH=/gp\0GOCACHE=/build-cache\0GOMODCACHE=/modules\0GOTMPDIR=/go-tmp\0";
        assert_eq!(
            references(Tool::Go, env, None),
            paths(&["/build-cache", "/modules", "/go-tmp"])
        );
    }

    #[test]
    fn go_disabled_relative_and_empty_first_path_values_do_not_invent_caches() {
        let env = b"HOME=/builder\0GOCACHE=off\0GOMODCACHE=relative\0";
        assert!(references(Tool::Go, env, Some(Path::new("/cwd"))).is_empty());
        let env = b"HOME=/builder\0XDG_CACHE_HOME=relative\0GOPATH=:/second\0";
        assert!(references(Tool::Go, env, None).is_empty());
    }

    #[test]
    fn empty_go_overrides_and_empty_xdg_gopath_use_home_defaults() {
        let env = b"HOME=/builder\0GOCACHE=\0GOMODCACHE=\0GOPATH=\0XDG_CACHE_HOME=\0";
        assert_eq!(
            references(Tool::Go, env, None),
            paths(&["/builder/.cache/go-build", "/builder/go/pkg/mod"])
        );
    }

    #[test]
    fn npm_keys_are_case_insensitive_and_lowercase_scripts_win() {
        for env in [
            b"NPM_CONFIG_CACHE=/cache\0".as_slice(),
            b"Npm_Config_Cache=/cache\0",
        ] {
            assert_eq!(references(Tool::Node, env, None), paths(&["/cache"]));
        }
        assert_eq!(
            references(
                Tool::Node,
                b"NPM_CONFIG_CACHE=/upper\0npm_config_cache=/lower\0",
                None
            ),
            paths(&["/lower"])
        );
        assert!(
            references(
                Tool::Node,
                b"NPM_CONFIG_CACHE=/upper\0npm_config_cache=\0",
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn python_and_compiler_cache_keys_are_family_scoped() {
        let env = b"CARGO_HOME=/cargo\0GOCACHE=/go\0npm_config_cache=/npm\0UV_CACHE_DIR=/uv\0PIP_CACHE_DIR=/pip\0SCCACHE_DIR=/sccache\0CCACHE_DIR=/ccache\0";
        assert_eq!(references(Tool::Python, env, None), paths(&["/uv", "/pip"]));
        assert_eq!(
            references(Tool::Compiler, env, None),
            paths(&["/sccache", "/ccache"])
        );
        assert_eq!(references(Tool::Go, env, None), paths(&["/go"]));
    }

    #[test]
    fn relative_directories_use_only_the_observed_process_cwd() {
        let env = b"CARGO_TARGET_DIR=../pooled target\0SCCACHE_DIR=cache\0";
        assert!(references(Tool::Rust, env, None).is_empty());
        assert!(references(Tool::Rust, env, Some(Path::new("relative"))).is_empty());
        assert_eq!(
            references(Tool::Rust, env, Some(Path::new("/workspace/project"))),
            paths(&[
                "/workspace/project/../pooled target",
                "/workspace/project/cache"
            ])
        );
    }

    #[test]
    fn native_path_bytes_spaces_and_equals_survive_parsing() {
        assert_eq!(
            references(Tool::Python, b"UV_CACHE_DIR=/tmp/cache-\xff = data\0", None),
            vec![PathBuf::from(OsString::from_vec(
                b"/tmp/cache-\xff = data".to_vec()
            ))]
        );
        let expected = PathBuf::from(OsString::from_vec(
            b"/home/\xff/.cargo/registry/src".to_vec(),
        ));
        assert!(references(Tool::Rust, b"HOME=/home/\xff\0", None).contains(&expected));
    }

    #[test]
    fn incomplete_buffers_keep_complete_positives_but_cannot_infer_defaults() {
        for env in [
            b"".as_slice(),
            b"CARGO_HOME=\0",
            b"CARGO_HOME\0",
            b"CARGO_HOME=/tail",
        ] {
            assert!(references(Tool::Rust, env, Some(Path::new("/work"))).is_empty());
        }
        let env = b"HOME=/builder\0CARGO_HOME=/truncated";
        assert!(references(Tool::Rust, env, None).is_empty());
        let env = b"HOME=/builder\0GOCACHE=/kept\0GOMODCACHE=/truncated";
        assert_eq!(references(Tool::Go, env, None), paths(&["/kept"]));
        assert_eq!(
            references(
                Tool::Python,
                b"UV_CACHE_DIR=/kept\0PIP_CACHE_DIR=/tail",
                None
            ),
            paths(&["/kept"])
        );
    }

    #[test]
    fn repeated_keys_and_shared_paths_cannot_multiply_results() {
        let mut env = b"UV_CACHE_DIR=/first\0PIP_CACHE_DIR=/first\0".to_vec();
        for _ in 0..10_000 {
            env.extend_from_slice(b"UV_CACHE_DIR=/later\0");
        }
        assert_eq!(references(Tool::Python, &env, None), paths(&["/first"]));
    }

    #[test]
    fn missing_or_relative_home_never_uses_daemon_environment() {
        for family in [
            Tool::Rust,
            Tool::Go,
            Tool::Node,
            Tool::Python,
            Tool::Compiler,
            Tool::Npm,
            Tool::Pip,
            Tool::Uv,
        ] {
            for env in [
                b"".as_slice(),
                b"HOME=\0",
                b"HOME=relative\0",
                b"OTHER=/cache\0",
            ] {
                assert!(references(family, env, Some(Path::new("/workspace"))).is_empty());
            }
        }
        for family in [Tool::Node, Tool::Python, Tool::Compiler] {
            assert!(references(family, b"HOME=/user\0", None).is_empty());
        }
    }

    #[test]
    fn identified_package_managers_protect_their_conventional_caches() {
        for (name, expected) in [
            ("npm install", "/builder/.npm"),
            ("pip3.13", "/builder/.cache/pip"),
            ("uv", "/builder/.cache/uv"),
            ("uvx", "/builder/.cache/uv"),
        ] {
            assert_eq!(
                references(tool(name.as_bytes()).unwrap(), b"HOME=/builder\0", None),
                paths(&[expected])
            );
        }
        for name in ["node", "python3.13", "pnpm", "yarn"] {
            assert!(
                references(tool(name.as_bytes()).unwrap(), b"HOME=/builder\0", None).is_empty()
            );
        }
    }

    #[test]
    fn package_overrides_suppress_defaults_even_when_empty_or_unresolvable() {
        for (family, key) in [
            (Tool::Npm, "npm_config_cache"),
            (Tool::Pip, "PIP_CACHE_DIR"),
            (Tool::Uv, "UV_CACHE_DIR"),
        ] {
            for override_value in ["", "relative"] {
                let env = format!("HOME=/builder\0{key}={override_value}\0");
                assert!(references(family, env.as_bytes(), None).is_empty());
            }
            let env = format!("HOME=/builder\0{key}=/explicit\0");
            assert_eq!(
                references(family, env.as_bytes(), None),
                paths(&["/explicit"])
            );
            let env = format!("HOME=/builder\0{key}=/unterminated");
            assert!(references(family, env.as_bytes(), None).is_empty());
        }
    }

    #[test]
    fn package_xdg_defaults_stay_with_the_observed_user() {
        let env = b"HOME=/builder\0XDG_CACHE_HOME=/shared\0";
        assert_eq!(references(Tool::Uv, env, None), paths(&["/shared/uv"]));
        assert_eq!(references(Tool::Pip, env, None), paths(&["/shared/pip"]));
        assert_eq!(references(Tool::Npm, env, None), paths(&["/builder/.npm"]));
        for family in [Tool::Uv, Tool::Pip] {
            assert!(
                references(family, b"HOME=/builder\0XDG_CACHE_HOME=relative\0", None).is_empty()
            );
        }
    }

    #[test]
    fn darwin_defaults_use_each_tools_native_layout() {
        let env = b"HOME=/builder\0XDG_CACHE_HOME=/xdg\0GOPATH=/first:/second\0";
        assert_eq!(
            references_with_layout(CacheLayout::MacOs, Tool::Go, env, None),
            paths(&["/builder/Library/Caches/go-build", "/first/pkg/mod"])
        );
        assert_eq!(
            references_with_layout(CacheLayout::MacOs, Tool::Uv, env, None),
            paths(&["/xdg/uv"])
        );
        assert_eq!(
            references_with_layout(CacheLayout::MacOs, Tool::Pip, env, None),
            paths(&["/xdg/pip", "/builder/Library/Caches/pip"])
        );
        assert_eq!(
            references_with_layout(CacheLayout::MacOs, Tool::Npm, env, None),
            paths(&["/builder/.npm"])
        );
        assert_eq!(
            references_with_layout(CacheLayout::MacOs, Tool::Rust, env, None),
            cargo_paths("/builder/.cargo")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_entry_point_uses_the_linux_layout() {
        let env = b"HOME=/builder\0";
        assert_eq!(
            super::references(Tool::Go, env, None),
            references_with_layout(CacheLayout::Linux, Tool::Go, env, None)
        );
    }
}
