//! Positive build-cache evidence from an observed process invocation.
//!
//! A Python or Node process may be a package manager without that manager's
//! name appearing in kernel process metadata. Inspect only the interpreter's
//! actual entry point, never arbitrary later arguments or executable code.
//! Inputs are bounded native observations; this module performs no I/O and
//! never reads the daemon's environment or logs the observed argument bytes.

use std::path::{Path, PathBuf};

use super::build_environment::{self, CacheLayout, Tool};

type Arguments<'a> = std::slice::Split<'a, u8, fn(&u8) -> bool>;

/// Recognize the existing build-tool names and Python's framework spelling.
/// Case folding is deliberately limited to the initial P of Python; arbitrary
/// near-matching executable names do not authorize reading their environments.
pub fn observed_tool(name: &[u8]) -> Option<Tool> {
    build_environment::tool(name).or_else(|| {
        name.strip_prefix(b"Python")?;
        let mut normalized = name.to_vec();
        normalized[0] = b'p';
        build_environment::tool(&normalized)
    })
}

/// Resolve cache evidence for a complete NUL-delimited argv and environment.
/// Invalid or unrecognized argv cannot erase existing environment evidence.
/// The layout is explicit so kernel-independent tests can exercise both OSes.
pub fn references(
    layout: CacheLayout,
    observed: Tool,
    argv: &[u8],
    environment: &[u8],
    cwd: Option<&Path>,
) -> Vec<PathBuf> {
    let tool = invocation_tool(observed, argv);
    build_environment::references_with_layout(layout, tool, environment, cwd)
}

// By reference: `slice::split` hands its predicate a `&u8`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn nul(byte: &u8) -> bool {
    *byte == 0
}

fn arguments(argv: &[u8]) -> Option<(&[u8], Arguments<'_>)> {
    // Drop exactly the terminating NUL, not empty arguments preceding it.
    // Without the terminator an incomplete final argument could look like a
    // package name and incorrectly authorize an implicit default cache.
    let bytes = argv.strip_suffix(b"\0")?;
    let mut rest = bytes.split(nul as fn(&u8) -> bool);
    let program = rest.next().filter(|program| !program.is_empty())?;
    Some((program, rest))
}

fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
}

fn invocation_tool(observed: Tool, argv: &[u8]) -> Tool {
    let Some((program, rest)) = arguments(argv) else {
        return observed;
    };
    let manager = match observed {
        Tool::Python => python_manager(rest),
        Tool::Node if matches!(basename(program), b"node" | b"nodejs") => node_manager(rest),
        _ => None,
    };
    manager.unwrap_or(observed)
}

fn python_manager(mut args: Arguments<'_>) -> Option<Tool> {
    while let Some(arg) = args.next() {
        match arg {
            b"-m" => return python_module(args.next()?),
            b"--" => return python_script(args.next()?),
            b"-W" | b"-X" => {
                // Consume their values even when shaped like another option.
                args.next()?;
            }
            _ if arg.starts_with(b"-W") || arg.starts_with(b"-X") => {}
            _ if arg.starts_with(b"-m") => return python_module(&arg[2..]),
            _ if python_switches(arg) => {}
            // -c, stdin, unknown options and scripts end interpretation here.
            // A later "-m pip" is data for that entry point, not a new command.
            _ if arg.starts_with(b"-") => return None,
            _ => return python_script(arg),
        }
    }
    None
}

fn python_switches(arg: &[u8]) -> bool {
    arg.strip_prefix(b"-").is_some_and(|switches| {
        !switches.is_empty() && switches.iter().all(|byte| b"bBdEiIOPqsSuv".contains(byte))
    })
}

fn python_module(module: &[u8]) -> Option<Tool> {
    match module {
        b"pip" | b"pip.__main__" => Some(Tool::Pip),
        b"uv" => Some(Tool::Uv),
        _ => None,
    }
}

fn python_script(script: &[u8]) -> Option<Tool> {
    let name = basename(script);
    // An entry script is run by path (/venv/bin/pip3.13). A bare "pip" is a
    // file in the cwd, or the value an option like -W left behind.
    if script.contains(&b'/') && build_environment::tool(name) == Some(Tool::Pip) {
        return Some(Tool::Pip);
    }
    // python /venv/.../pip/__main__.py, not an unrelated __main__.py.
    let parent = script.strip_suffix(b"/__main__.py")?;
    python_module(basename(parent))
}

fn node_manager(mut args: Arguments<'_>) -> Option<Tool> {
    while let Some(arg) = args.next() {
        match arg {
            b"--" => return node_script(args.next()?),
            b"-r" | b"--require" | b"--import" | b"--loader" | b"--conditions" => {
                args.next()?;
            }
            b"--no-warnings" | b"--enable-source-maps" | b"--trace-warnings" => {}
            _ if [
                b"--require=".as_slice(),
                b"--import=",
                b"--loader=",
                b"--conditions=",
            ]
            .iter()
            .any(|prefix| arg.starts_with(prefix)) => {}
            // In particular, do not inspect source supplied to -e or -p.
            _ if arg.starts_with(b"-") => return None,
            _ => return node_script(arg),
        }
    }
    None
}

fn node_script(script: &[u8]) -> Option<Tool> {
    matches!(
        basename(script),
        b"npm-cli.js" | b"npx-cli.js" | b"npm" | b"npx"
    )
    .then_some(Tool::Npm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for arg in args {
            bytes.extend_from_slice(arg);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn python_module_installations_protect_defaults_on_both_platforms() {
        for (layout, pip_cache) in [
            (CacheLayout::Linux, "/builder/.cache/pip"),
            (CacheLayout::MacOs, "/builder/Library/Caches/pip"),
        ] {
            for args in [
                vec![b"python3".as_slice(), b"-m", b"pip", b"install", b"package"],
                vec![b"python3".as_slice(), b"-I", b"-m", b"pip"],
                vec![b"python3".as_slice(), b"-W", b"ignore", b"-mpip"],
                vec![b"python3".as_slice(), b"-Xdev", b"-m", b"pip.__main__"],
            ] {
                assert_eq!(
                    references(layout, Tool::Python, &argv(&args), b"HOME=/builder\0", None),
                    vec![PathBuf::from(pip_cache)]
                );
            }
        }
    }

    #[test]
    fn node_hosted_npm_and_npx_protect_the_conventional_cache() {
        for script in [
            b"/opt/npm/bin/npm-cli.js".as_slice(),
            b"/bin/npx",
            b"npm-cli.js",
        ] {
            let args = argv(&[b"/bin/node", b"--no-warnings", script, b"install"]);
            assert_eq!(invocation_tool(Tool::Node, &args), Tool::Npm);
            assert_eq!(
                references(
                    CacheLayout::MacOs,
                    Tool::Node,
                    &args,
                    b"HOME=/builder\0",
                    None
                ),
                vec![PathBuf::from("/builder/.npm")]
            );
        }
    }

    #[test]
    fn native_script_path_bytes_do_not_require_utf8() {
        for script in [
            b"/venv-\xff/bin/pip3.13".as_slice(),
            b"/venv-\xff/pip/__main__.py",
        ] {
            assert_eq!(
                invocation_tool(Tool::Python, &argv(&[b"python3", script])),
                Tool::Pip
            );
        }
        assert_eq!(
            invocation_tool(Tool::Node, &argv(&[b"node", b"/prefix-\xff/npm-cli.js"])),
            Tool::Npm
        );
    }

    #[test]
    fn interpreter_code_and_script_arguments_cannot_impersonate_a_manager() {
        for args in [
            vec![b"python3".as_slice(), b"-c", b"-m pip", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"script.py", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"--", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"-", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"-W", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"", b"-m", b"pip"],
            vec![b"python3".as_slice(), b"-m", b"pip-notes"],
        ] {
            assert_eq!(invocation_tool(Tool::Python, &argv(&args)), Tool::Python);
        }
        for args in [
            vec![b"node".as_slice(), b"-e", b"npm-cli.js", b"npm-cli.js"],
            vec![b"node".as_slice(), b"server.js", b"npm-cli.js"],
            vec![
                b"node".as_slice(),
                b"--require",
                b"npm-cli.js",
                b"server.js",
            ],
            vec![b"node".as_slice(), b"npm-cli.js.backup"],
            vec![b"bun".as_slice(), b"npm-cli.js"],
        ] {
            assert_eq!(invocation_tool(Tool::Node, &argv(&args)), Tool::Node);
        }
    }

    #[test]
    fn unreadable_argv_does_not_discard_explicit_environment_evidence() {
        for args in [b"".as_slice(), b"\0", b"python\0-m\0pip", b"python\0-m\0"] {
            assert_eq!(
                references(
                    CacheLayout::Linux,
                    Tool::Python,
                    args,
                    b"HOME=/builder\0PIP_CACHE_DIR=/explicit\0",
                    None,
                ),
                vec![PathBuf::from("/explicit")]
            );
        }
    }

    #[test]
    fn manager_overrides_and_plain_interpreters_keep_the_environment_contract() {
        let args = argv(&[b"python3", b"-m", b"pip"]);
        assert_eq!(
            references(
                CacheLayout::Linux,
                Tool::Python,
                &args,
                b"HOME=/builder\0PIP_CACHE_DIR=relative\0",
                Some(Path::new("/project")),
            ),
            vec![PathBuf::from("/project/relative")]
        );
        for (tool, args) in [
            (Tool::Python, b"python3\0".as_slice()),
            (Tool::Node, b"node\0"),
        ] {
            assert!(
                references(CacheLayout::MacOs, tool, args, b"HOME=/builder\0", None).is_empty()
            );
        }
        assert_eq!(
            references(CacheLayout::MacOs, Tool::Npm, b"", b"HOME=/builder\0", None),
            vec![PathBuf::from("/builder/.npm")]
        );
    }

    #[test]
    fn framework_python_name_is_recognized_without_general_case_folding() {
        for name in [b"Python".as_slice(), b"Python3.13", b"python3.13"] {
            assert_eq!(observed_tool(name), Some(Tool::Python));
        }
        for name in [
            b"Python-notes".as_slice(),
            b"PYTHON",
            b"Python3..1",
            b"Python\xff",
        ] {
            assert_eq!(observed_tool(name), None);
        }
    }
}
