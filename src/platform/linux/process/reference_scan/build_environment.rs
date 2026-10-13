//! Positive cache-directory evidence for active build tools.
//!
//! Callers bound the input and provide the observed process cwd. This parser
//! reads only documented directory keys, never the daemon's environment. It
//! produces positive references, not proof that an unlisted path is unused.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tool {
    Rust,
    Go,
    Node,
    Python,
    Compiler,
}

pub(super) fn tool(comm: &[u8]) -> Option<Tool> {
    let name = std::str::from_utf8(comm).ok()?.trim_end();
    match name {
        "cargo" | "rustc" | "rustdoc" | "clippy-driver" | "cargo-clippy" => Some(Tool::Rust),
        "go" | "compile" | "link" | "cgo" => Some(Tool::Go),
        "node" | "nodejs" | "npm" | "npx" | "pnpm" | "yarn" | "bun" => Some(Tool::Node),
        "uv" | "uvx" | "python" | "pip" | "pypy" => Some(Tool::Python),
        "sccache" | "ccache" | "cc" | "c++" | "gcc" | "g++" | "clang" | "clang++"
        | "cc1" | "cc1plus" => Some(Tool::Compiler),
        _ if ["npm ", "npx ", "pnpm ", "yarn "]
            .iter()
            .any(|prefix| name.starts_with(prefix)) => Some(Tool::Node),
        _ if ["python", "pip", "pypy"]
            .iter()
            .any(|prefix| versioned(name, prefix)) => Some(Tool::Python),
        _ if ["gcc-", "g++-", "clang-", "clang++-"]
            .iter()
            .any(|prefix| versioned(name, prefix)) => Some(Tool::Compiler),
        _ => None,
    }
}

fn versioned(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

pub(super) fn references(tool: Tool, environ: &[u8], cwd: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match tool {
        Tool::Rust => {
            if let Some(home) = directory(value(environ, b"CARGO_HOME"), cwd) {
                for subtree in [
                    "registry/index", "registry/cache", "registry/src", "git/db", "git/checkouts",
                ] {
                    push_unique(&mut paths, home.join(subtree));
                }
            }
            add(&mut paths, environ, b"CARGO_TARGET_DIR", cwd);
        }
        Tool::Go => {
            // GOCACHE=off is not a path. Go cache locations must be absolute.
            for key in [b"GOCACHE".as_slice(), b"GOMODCACHE", b"GOTMPDIR"] {
                add(&mut paths, environ, key, None);
            }
        }
        Tool::Node => {
            // npm's lowercase script environment takes precedence.
            let cache = value(environ, b"npm_config_cache").or_else(|| {
                entries(environ).find_map(|(key, value)| {
                    key.eq_ignore_ascii_case(b"npm_config_cache").then_some(value)
                })
            });
            if let Some(path) = directory(cache, cwd) {
                push_unique(&mut paths, path);
            }
        }
        Tool::Python => {
            add(&mut paths, environ, b"UV_CACHE_DIR", cwd);
            add(&mut paths, environ, b"PIP_CACHE_DIR", cwd);
        }
        Tool::Compiler => {}
    }
    if matches!(tool, Tool::Rust | Tool::Compiler) {
        add(&mut paths, environ, b"SCCACHE_DIR", cwd);
        add(&mut paths, environ, b"CCACHE_DIR", cwd);
    }
    paths
}

fn entries(raw: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    raw.split_inclusive(|byte| *byte == 0).filter_map(|entry| {
        let entry = entry.strip_suffix(b"\0")?;
        let separator = entry.iter().position(|byte| *byte == b'=')?;
        Some((&entry[..separator], &entry[separator + 1..]))
    })
}

fn value<'a>(raw: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    entries(raw).find_map(|(name, value)| (name == key).then_some(value))
}

fn directory(value: Option<&[u8]>, cwd: Option<&Path>) -> Option<PathBuf> {
    let value = value.filter(|value| !value.is_empty())?;
    let path = PathBuf::from(OsString::from_vec(value.to_vec()));
    if path.is_absolute() {
        Some(path)
    } else {
        // Preserve .. through symlinks; resolution belongs to the caller.
        cwd.filter(|cwd| cwd.is_absolute()).map(|cwd| cwd.join(path))
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
