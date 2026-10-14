//! Decode the framing around Darwin's KERN_PROCARGS2 argument and environment tables.
//!
//! The native transport must first obtain a complete, bounded syscall result.
//! This parser never allocates from argc, logs arguments, or treats argv as
//! environment. It can be tested on Linux without pretending to test libproc.

const ARGC_BYTES: usize = std::mem::size_of::<i32>();

/// Separate, borrowed NUL-terminated tables from a complete process record.
/// Empty later arguments are preserved; executable padding and auxiliary
/// strings are excluded. Neither table is decoded as text or copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinArguments<'a> {
    /// Exactly argc arguments, including argv[0] and each terminating NUL.
    pub argv: &'a [u8],
    /// Environment entries only, excluding a double-NUL auxiliary tail.
    pub environment: &'a [u8],
}

/// Borrow argv and the environment without conflating their contents.
/// Zero argc, missing terminators and truncated tails return None. The
/// conventional nonempty argv[0] delimits executable-path alignment padding.
/// An empty environment is valid. A double NUL ends the environment; any
/// auxiliary strings following it are not configuration evidence.
pub fn darwin_arguments(raw: &[u8]) -> Option<DarwinArguments<'_>> {
    let count = i32::from_ne_bytes(raw.get(..ARGC_BYTES)?.try_into().ok()?);
    let count = usize::try_from(count).ok().filter(|count| *count > 0)?;
    let strings = raw.get(ARGC_BYTES..)?;
    // Every argument requires at least a NUL byte. A corrupt count cannot
    // induce work or allocation beyond the size of the bounded input.
    if count > strings.len() {
        return None;
    }
    let exec_end = next_nul(strings, 0)?;
    if strings.first() != Some(&b'/') || exec_end == 0 {
        return None;
    }
    let mut cursor = exec_end.checked_add(1)?;
    cursor = cursor.checked_add(strings.get(cursor..)?.iter().position(|byte| *byte != 0)?)?;
    let argv_start = cursor;
    for _ in 0..count {
        cursor = next_nul(strings, cursor)?.checked_add(1)?;
    }
    let argv = strings.get(argv_start..cursor)?;
    let start = cursor;
    while cursor < strings.len() {
        let end = next_nul(strings, cursor)?;
        if end == cursor {
            return Some(DarwinArguments {
                argv,
                environment: strings.get(start..cursor)?,
            });
        }
        cursor = end.checked_add(1)?;
    }
    Some(DarwinArguments {
        argv,
        environment: strings.get(start..cursor)?,
    })
}

fn next_nul(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|offset| start.checked_add(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::build_environment::{CacheLayout, Tool, references_with_layout};
    use std::path::{Path, PathBuf};

    // Keep the original environment-only assertions as regression controls
    // while the production caller consumes both tables.
    fn darwin_environment(raw: &[u8]) -> Option<&[u8]> {
        darwin_arguments(raw).map(|arguments| arguments.environment)
    }

    #[test]
    fn argv_is_borrowed_separately_from_environment_and_padding() {
        let env = b"HOME=/builder\0\0npm-cli.js\0";
        for padding in 0..=16 {
            let raw = frame(
                &[b"python3", b"", b"-m", b"pip", b"path-\xff"],
                env,
                padding,
            );
            let parsed = darwin_arguments(&raw).unwrap();
            assert_eq!(parsed.argv, b"python3\0\0-m\0pip\0path-\xff\0");
            assert_eq!(parsed.environment, b"HOME=/builder\0");
            assert!(raw.as_ptr_range().contains(&parsed.argv.as_ptr()));
            assert!(raw.as_ptr_range().contains(&parsed.environment.as_ptr()));
        }
    }

    fn frame(args: &[&[u8]], environment: &[u8], padding: usize) -> Vec<u8> {
        let mut raw = i32::try_from(args.len()).unwrap().to_ne_bytes().to_vec();
        raw.extend_from_slice(b"/usr/bin/build-tool\0");
        raw.resize(raw.len() + padding, 0);
        for arg in args {
            raw.extend_from_slice(arg);
            raw.push(0);
        }
        raw.extend_from_slice(environment);
        raw
    }

    #[test]
    fn alignment_padding_does_not_shift_the_counted_argument_table() {
        let env = b"HOME=/builder\0CARGO_HOME=/shared/cache\0";
        for padding in 0..=16 {
            let raw = frame(&[b"cargo", b"build", b"--release"], env, padding);
            assert_eq!(darwin_environment(&raw), Some(env.as_slice()));
        }
    }

    #[test]
    fn assignment_shaped_arguments_are_not_environment_variables() {
        let env = b"UV_CACHE_DIR=/actual\0";
        let raw = frame(&[b"uv", b"UV_CACHE_DIR=/decoy", b"HOME=/wrong"], env, 3);
        assert_eq!(darwin_environment(&raw), Some(env.as_slice()));
        assert_eq!(
            references_with_layout(
                CacheLayout::MacOs,
                Tool::Uv,
                darwin_environment(&raw).unwrap(),
                None,
            ),
            vec![PathBuf::from("/actual")]
        );
    }

    #[test]
    fn empty_later_arguments_are_counted_not_skipped_as_padding() {
        let env = b"CARGO_HOME=/shared\0";
        let raw = frame(&[b"cargo", b"", b"build", b""], env, 4);
        assert_eq!(darwin_environment(&raw), Some(env.as_slice()));
    }

    #[test]
    fn empty_environment_and_auxiliary_tail_are_not_default_configuration() {
        for env in [b"".as_slice(), b"\0", b"\0HOME=/auxiliary\0"] {
            let raw = frame(&[b"cargo"], env, 0);
            assert_eq!(darwin_environment(&raw), Some(b"".as_slice()));
        }
        let raw = frame(&[b"cargo"], b"HOME=/builder\0\0CARGO_HOME=/auxiliary\0", 0);
        assert_eq!(
            darwin_environment(&raw),
            Some(b"HOME=/builder\0".as_slice())
        );
    }

    #[test]
    fn malformed_counts_and_missing_executable_or_argv_are_rejected() {
        for raw in [Vec::new(), vec![0; 3], vec![0; 4]] {
            assert_eq!(darwin_environment(&raw), None);
        }
        for count in [i32::MIN, -1, 0, i32::MAX] {
            let mut raw = frame(&[b"cargo"], b"HOME=/builder\0", 0);
            raw[..ARGC_BYTES].copy_from_slice(&count.to_ne_bytes());
            assert_eq!(darwin_environment(&raw), None);
        }
        for strings in [
            b"/missing-terminator".as_slice(),
            b"relative\0cargo\0",
            b"\0cargo\0",
            b"/bin/cargo\0\0",
        ] {
            let mut raw = 1_i32.to_ne_bytes().to_vec();
            raw.extend_from_slice(strings);
            assert_eq!(darwin_environment(&raw), None);
        }
        let mut raw = frame(&[b"cargo"], b"", 0);
        raw[..ARGC_BYTES].copy_from_slice(&2_i32.to_ne_bytes());
        assert_eq!(darwin_environment(&raw), None);
    }

    #[test]
    fn unterminated_environment_cannot_authorize_defaults_from_earlier_keys() {
        let raw = frame(&[b"cargo"], b"HOME=/builder\0CARGO_HOME=/truncated", 0);
        assert_eq!(darwin_environment(&raw), None);
        let mut raw = frame(&[b"cargo"], b"", 0);
        raw.pop();
        assert_eq!(darwin_environment(&raw), None);
    }

    #[test]
    fn native_byte_values_spaces_and_relative_directories_reach_the_resolver() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let env = b"CARGO_TARGET_DIR=../target-\xff = cache\0";
        let raw = frame(&[b"rustc", b"source-\xff.rs"], env, 2);
        assert_eq!(darwin_environment(&raw), Some(env.as_slice()));
        assert_eq!(
            references_with_layout(
                CacheLayout::MacOs,
                Tool::Rust,
                darwin_environment(&raw).unwrap(),
                Some(Path::new("/workspace/project")),
            ),
            vec![PathBuf::from(OsString::from_vec(
                b"/workspace/project/../target-\xff = cache".to_vec()
            ))]
        );
    }

    #[test]
    fn darwin_framing_preserves_explicit_overrides_over_platform_defaults() {
        let env = b"HOME=/builder\0XDG_CACHE_HOME=/xdg\0GOCACHE=/explicit\0GOPATH=/first:/second\0";
        let raw = frame(&[b"go", b"build"], env, 7);
        assert_eq!(
            references_with_layout(
                CacheLayout::MacOs,
                Tool::Go,
                darwin_environment(&raw).unwrap(),
                None,
            ),
            vec![PathBuf::from("/explicit"), PathBuf::from("/first/pkg/mod")]
        );
    }
}
