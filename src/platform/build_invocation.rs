//! Positive build-cache evidence from an observed process invocation.
//!
//! A Python or Node process may be a package manager without that manager's
//! name appearing in kernel process metadata. Inspect only the interpreter's
//! actual entry point, never arbitrary later arguments or executable code.
//! Inputs are bounded native observations; this module performs no I/O and
//! never reads the daemon's environment or logs the observed argument bytes.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
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
    let Some(invocation) = invocation(observed, argv) else {
        return build_environment::references_with_layout(layout, observed, environment, cwd);
    };
    let mut paths =
        build_environment::references_with_layout(layout, invocation.tool, environment, cwd);
    // These are additive positive observations, not a complete configuration
    // resolver. A command-line override must not erase environment evidence.
    if let Some(path) = command_directory(invocation, cwd)
        && !paths.contains(&path)
    {
        paths.push(path);
    }
    paths
}

fn nul(byte: &u8) -> bool {
    *byte == 0
}

fn arguments(argv: &[u8]) -> Option<(&[u8], Arguments<'_>)> {
    // Drop exactly the terminating NUL, not empty arguments preceding it.
    // Without the terminator an incomplete final argument could look like a
    // package name and incorrectly authorize an implicit default cache.
    let bytes = argv.strip_suffix(b"\0")?;
    let mut args = bytes.split(nul as fn(&u8) -> bool);
    let program = args.next().filter(|program| !program.is_empty())?;
    Some((program, args))
}

fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
}

struct Invocation<'a> {
    tool: Tool,
    program: &'a [u8],
    args: Arguments<'a>,
}

fn invocation(observed: Tool, argv: &[u8]) -> Option<Invocation<'_>> {
    let (program, args) = arguments(argv)?;
    let manager = match observed {
        Tool::Python => python_manager(args.clone()),
        Tool::Node if matches!(basename(program), b"node" | b"nodejs") => {
            node_manager(args.clone())
        }
        _ => None,
    };
    let (tool, args) = manager.unwrap_or((observed, args));
    Some(Invocation { tool, program, args })
}

fn python_manager(mut args: Arguments<'_>) -> Option<(Tool, Arguments<'_>)> {
    while let Some(arg) = args.next() {
        match arg {
            b"-m" => return Some((python_module(args.next()?)?, args)),
            b"--" => return Some((python_script(args.next()?)?, args)),
            b"-W" | b"-X" => {
                // Consume their values even when shaped like another option.
                args.next()?;
            }
            _ if arg.starts_with(b"-W") || arg.starts_with(b"-X") => {}
            _ if arg.starts_with(b"-m") => return Some((python_module(&arg[2..])?, args)),
            _ if python_switches(arg) => {}
            // -c, stdin, unknown options and scripts end interpretation here.
            // A later "-m pip" is data for that entry point, not a new command.
            _ if arg.starts_with(b"-") => return None,
            _ => return Some((python_script(arg)?, args)),
        }
    }
    None
}

fn python_switches(arg: &[u8]) -> bool {
    arg.strip_prefix(b"-").is_some_and(|switches| {
        !switches.is_empty()
            && switches
                .iter()
                .all(|byte| b"bBdEiIOPqsSuv".contains(byte))
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
    if build_environment::tool(name) == Some(Tool::Pip) {
        return Some(Tool::Pip);
    }
    // python /venv/.../pip/__main__.py, not an unrelated __main__.py.
    let parent = script.strip_suffix(b"/__main__.py")?;
    python_module(basename(parent))
}

fn node_manager(mut args: Arguments<'_>) -> Option<(Tool, Arguments<'_>)> {
    while let Some(arg) = args.next() {
        match arg {
            b"--" => return Some((node_script(args.next()?)?, args)),
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
            _ => return Some((node_script(arg)?, args)),
        }
    }
    None
}

fn node_script(script: &[u8]) -> Option<Tool> {
    matches!(basename(script), b"npm-cli.js" | b"npx-cli.js" | b"npm" | b"npx")
        .then_some(Tool::Npm)
}

/// Read one supported destination without allocating per argument. Keep the
/// last occurrence observed and stop at forwarded arguments. Some tools reject
/// duplicate options before running; this parser only adds positive evidence.
/// A repeated option cannot grow the result or hide its final value behind a
/// result cap. All other cache evidence remains in the environment resolver.
fn command_directory(invocation: Invocation<'_>, cwd: Option<&Path>) -> Option<PathBuf> {
    let program = basename(invocation.program);
    let flag = match invocation.tool {
        Tool::Rust if matches!(program, b"cargo" | b"cargo-clippy") => b"--target-dir".as_slice(),
        Tool::Rust if matches!(program, b"rustc" | b"rustdoc" | b"clippy-driver") => b"--out-dir",
        Tool::Pip | Tool::Uv => b"--cache-dir",
        Tool::Npm => b"--cache",
        _ => return None,
    };
    let mut args = invocation.args;
    let mut destination = None;
    let uv = invocation.tool == Tool::Uv;
    let rustdoc = invocation.tool == Tool::Rust && program == b"rustdoc";
    let mut forwarding = uv && program == b"uvx";
    while let Some(arg) = args.next() {
        if arg == b"--" {
            break;
        }
        if arg == flag || (rustdoc && arg == b"-o") {
            let value = args.next()?;
            // A missing operand must not turn another option into a path.
            // Values starting with '-' are still supported in the = form.
            if value.starts_with(b"-") {
                break;
            }
            destination = Some(value);
            continue;
        }
        if rustdoc && let Some(value) = arg.strip_prefix(b"-o") {
            destination = Some(value);
            continue;
        }
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix(b"="))
        {
            destination = Some(value);
            continue;
        }
        if uv {
            // uv run/tool run and uvx forward the first positional command
            // and everything after it, even without an explicit '--'. Never
            // treat that program's --cache-dir as uv's own configuration.
            if !arg.starts_with(b"-") {
                if forwarding {
                    break;
                }
                forwarding = arg == b"run";
            } else if uv_value_option(arg) {
                args.next()?;
            } else if !uv_switch(arg) && forwarding {
                // Unknown run options may consume an operand. Do not guess
                // where the forwarded command begins on ambiguous input.
                break;
            }
        }
    }
    let value = destination.filter(|value| !value.is_empty())?;
    let path = PathBuf::from(OsString::from_vec(value.to_vec()));
    if path.is_absolute() {
        Some(path)
    } else {
        cwd.filter(|cwd| cwd.is_absolute())
            .map(|cwd| cwd.join(path))
    }
}

fn uv_value_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"--directory" | b"-C" | b"--project" | b"--config-file" | b"--python" | b"-p"
            | b"--from" | b"--extra" | b"--config-setting" | b"--config-settings"
            | b"--with" | b"--with-editable" | b"--with-requirements" | b"--env-file"
            | b"--package" | b"--group" | b"--no-group" | b"--index" | b"--default-index"
            | b"--index-url" | b"--extra-index-url" | b"--find-links" | b"-f" | b"--color"
            | b"--link-mode"
    )
}

fn uv_switch(arg: &[u8]) -> bool {
    // An attached value is self-delimiting, including ones unknown here.
    arg.contains(&b'=')
        || matches!(
            arg,
            b"--offline" | b"--no-cache" | b"-n" | b"--frozen" | b"--locked"
                | b"--no-sync" | b"--no-project" | b"--isolated" | b"--active"
                | b"--all-extras" | b"--no-dev" | b"--quiet" | b"-q" | b"--verbose"
                | b"-v" | b"--module" | b"-m" | b"--script"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation_tool(observed: Tool, argv: &[u8]) -> Tool {
        invocation(observed, argv).map_or(observed, |invocation| invocation.tool)
    }

    fn argv(args: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for arg in args {
            bytes.extend_from_slice(arg);
            bytes.push(0);
        }
        bytes
    }

    fn cli_paths(tool: Tool, args: &[&[u8]], cwd: Option<&Path>) -> Vec<PathBuf> {
        references(CacheLayout::Linux, tool, &argv(args), b"", cwd)
    }

    #[test]
    fn compiler_and_package_manager_cli_directories_need_no_environment_override() {
        for (tool, args) in [
            (Tool::Rust, vec![b"cargo".as_slice(), b"build", b"--target-dir", b"/actual"]),
            (Tool::Rust, vec![b"rustc".as_slice(), b"lib.rs", b"--out-dir=/actual"]),
            (Tool::Rust, vec![b"rustdoc".as_slice(), b"lib.rs", b"-o", b"/actual"]),
            (Tool::Rust, vec![b"rustdoc".as_slice(), b"lib.rs", b"-o/actual"]),
            (Tool::Pip, vec![b"pip".as_slice(), b"install", b"--cache-dir=/actual"]),
            (Tool::Uv, vec![b"uv".as_slice(), b"sync", b"--cache-dir", b"/actual"]),
            (Tool::Npm, vec![b"npm".as_slice(), b"install", b"--cache=/actual"]),
        ] {
            assert_eq!(cli_paths(tool, &args, None), vec![PathBuf::from("/actual")]);
        }
        // rustc -o names a file, unlike rustdoc -o. Do not infer a directory.
        assert!(cli_paths(Tool::Rust, &[b"rustc", b"-o", b"/file"], None).is_empty());
    }

    #[test]
    fn interpreter_entry_points_expose_only_the_managers_own_arguments() {
        for (tool, args) in [
            (Tool::Python, vec![b"python3".as_slice(), b"-m", b"pip", b"--cache-dir=/actual"]),
            (Tool::Python, vec![b"python3".as_slice(), b"/venv/bin/pip3", b"--cache-dir=/actual"]),
            (Tool::Node, vec![b"node".as_slice(), b"--", b"npm-cli.js", b"--cache=/actual"]),
        ] {
            assert_eq!(cli_paths(tool, &args, None), vec![PathBuf::from("/actual")]);
        }
        assert!(cli_paths(
            Tool::Python,
            &[b"python3", b"-c", b"pass", b"--cache-dir=/decoy"],
            None,
        ).is_empty());
        assert!(cli_paths(
            Tool::Node,
            &[b"node", b"server.js", b"--cache=/decoy"],
            None,
        ).is_empty());
    }

    #[test]
    fn forwarded_program_arguments_never_become_build_cache_directories() {
        for (tool, args) in [
            (Tool::Rust, vec![b"cargo".as_slice(), b"run", b"--", b"--target-dir=/decoy"]),
            (Tool::Npm, vec![b"npm".as_slice(), b"run", b"build", b"--", b"--cache=/decoy"]),
            (Tool::Uv, vec![b"uv".as_slice(), b"run", b"python", b"--cache-dir=/decoy"]),
            (Tool::Uv, vec![b"uvx".as_slice(), b"tool", b"--cache-dir=/decoy"]),
        ] {
            assert!(cli_paths(tool, &args, None).is_empty());
        }
        for args in [
            vec![b"uv".as_slice(), b"run", b"--python", b"3.13", b"--cache-dir=/actual", b"python", b"--cache-dir=/decoy"],
            vec![b"uv".as_slice(), b"tool", b"run", b"--from", b"package", b"--cache-dir=/actual", b"tool", b"--cache-dir=/decoy"],
            vec![b"uvx".as_slice(), b"--cache-dir=/actual", b"tool", b"--cache-dir=/decoy"],
        ] {
            assert_eq!(cli_paths(Tool::Uv, &args, None), vec![PathBuf::from("/actual")]);
        }
    }

    #[test]
    fn command_directory_bytes_are_preserved_and_relative_paths_need_process_cwd() {
        let args = [b"rustc".as_slice(), b"--out-dir", b"../objects-\xff = files"];
        assert!(cli_paths(Tool::Rust, &args, None).is_empty());
        assert!(cli_paths(Tool::Rust, &args, Some(Path::new("relative"))).is_empty());
        assert_eq!(
            cli_paths(Tool::Rust, &args, Some(Path::new("/workspace"))),
            vec![PathBuf::from(OsString::from_vec(b"/workspace/../objects-\xff = files".to_vec()))]
        );
    }

    #[test]
    fn cli_evidence_is_additive_and_deduplicated_with_environment_evidence() {
        let args = argv(&[b"cargo", b"build", b"--target-dir=/cli"]);
        let found = references(
            CacheLayout::Linux,
            Tool::Rust,
            &args,
            b"CARGO_TARGET_DIR=/env\0SCCACHE_DIR=/shared\0",
            None,
        );
        assert_eq!(found, vec![PathBuf::from("/env"), PathBuf::from("/shared"), PathBuf::from("/cli")]);
        assert_eq!(
            references(CacheLayout::Linux, Tool::Rust, &args, b"CARGO_TARGET_DIR=/cli\0", None),
            vec![PathBuf::from("/cli")]
        );
    }

    #[test]
    fn repeated_directory_options_retain_the_final_value_with_constant_result_size() {
        let mut args = b"pip\0".to_vec();
        for _ in 0..10_000 {
            args.extend_from_slice(b"--cache-dir=/earlier\0");
        }
        args.extend_from_slice(b"--cache-dir=/final\0");
        assert_eq!(
            references(CacheLayout::Linux, Tool::Pip, &args, b"", None),
            vec![PathBuf::from("/final")]
        );
    }

    #[test]
    fn missing_operands_and_near_matching_options_cannot_invent_paths() {
        for args in [
            vec![b"pip".as_slice(), b"--cache-dir"],
            vec![b"pip".as_slice(), b"--cache-dir="],
            vec![b"pip".as_slice(), b"--cache-dir", b"--unknown"],
            vec![b"pip".as_slice(), b"--cache-directory=/decoy"],
        ] {
            assert!(cli_paths(Tool::Pip, &args, Some(Path::new("/workspace"))).is_empty());
        }
        assert_eq!(
            cli_paths(Tool::Pip, &[b"pip", b"--cache-dir=-valid"], Some(Path::new("/workspace"))),
            vec![PathBuf::from("/workspace/-valid")]
        );
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
        for script in [b"/opt/npm/bin/npm-cli.js".as_slice(), b"/bin/npx", b"npm-cli.js"] {
            let args = argv(&[b"/bin/node", b"--no-warnings", script, b"install"]);
            assert_eq!(invocation_tool(Tool::Node, &args), Tool::Npm);
            assert_eq!(
                references(CacheLayout::MacOs, Tool::Node, &args, b"HOME=/builder\0", None),
                vec![PathBuf::from("/builder/.npm")]
            );
        }
    }

    #[test]
    fn native_script_path_bytes_do_not_require_utf8() {
        for script in [b"/venv-\xff/bin/pip3.13".as_slice(), b"/venv-\xff/pip/__main__.py"] {
            assert_eq!(invocation_tool(Tool::Python, &argv(&[b"python3", script])), Tool::Pip);
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
            vec![b"node".as_slice(), b"--require", b"npm-cli.js", b"server.js"],
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
        for (tool, args) in [(Tool::Python, b"python3\0".as_slice()), (Tool::Node, b"node\0")] {
            assert!(references(CacheLayout::MacOs, tool, args, b"HOME=/builder\0", None).is_empty());
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
        for name in [b"Python-notes".as_slice(), b"PYTHON", b"Python3..1", b"Python\xff"] {
            assert_eq!(observed_tool(name), None);
        }
    }
}
