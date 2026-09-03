//! Runs every fuzz harness (`storage_ballast_helper::fuzzing`) over its
//! seed corpus and a deterministic mutation stream, so the "never panics,
//! round-trips when it parses" invariants are checked on every test run
//! without libFuzzer. `cargo fuzz run <target>` in `fuzz/` does the real
//! coverage-guided search; a crash it finds becomes a seed file here.

#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use storage_ballast_helper::fuzzing::{TARGETS, run};

const MUTATIONS_PER_SEED: usize = 400;

fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join(target)
}

fn seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let mut seeds: Vec<(PathBuf, Vec<u8>)> = fs::read_dir(corpus_dir(target))
        .unwrap_or_else(|e| panic!("corpus for {target}: {e}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    seeds.sort();
    assert!(!seeds.is_empty(), "{target} has no seed corpus");
    seeds
}

/// xorshift64*: reproducible mutations with no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n.max(1) as u64).unwrap_or(0)
    }
}

/// One mutation of `seed`: a byte flip, an insertion of interesting bytes,
/// a truncation, a duplication of a slice, or a splice with another seed.
fn mutate(seed: &[u8], others: &[Vec<u8>], rng: &mut Rng) -> Vec<u8> {
    const INTERESTING: &[&[u8]] = &[
        b"\"",
        b"\\",
        b"\n",
        b"{",
        b"}",
        b"[",
        b"]",
        b"=",
        b"-",
        b"9999999999999999999",
        b"1e999",
        b"NaN",
        b"null",
        b"true",
        b"\x00",
        b"\xff",
        b"\xc3\x28",
        b"..",
        b"/",
        b"\"decision_id\":",
        b"[scanner]",
        b"SHA256 (",
        b") = ",
    ];
    let mut out = seed.to_vec();
    match rng.below(6) {
        0 if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] ^= 1 << rng.below(8);
        }
        1 => {
            let piece = INTERESTING[rng.below(INTERESTING.len())];
            let i = rng.below(out.len() + 1);
            out.splice(i..i, piece.iter().copied());
        }
        2 if !out.is_empty() => {
            let i = rng.below(out.len());
            out.truncate(i);
        }
        3 if out.len() > 1 => {
            let a = rng.below(out.len());
            let b = a + rng.below(out.len() - a).min(64);
            let slice = out[a..b].to_vec();
            let at = rng.below(out.len() + 1);
            out.splice(at..at, slice);
        }
        4 if !others.is_empty() => {
            let other = &others[rng.below(others.len())];
            if !other.is_empty() {
                let cut = rng.below(out.len() + 1);
                let from = rng.below(other.len());
                out.truncate(cut);
                out.extend_from_slice(&other[from..]);
            }
        }
        _ if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] = u8::try_from(rng.below(256)).unwrap_or(0);
        }
        _ => out.push(b'{'),
    }
    out
}

#[test]
fn every_target_survives_its_corpus_and_mutations() {
    for target in TARGETS {
        let seeds = seeds(target);
        let bodies: Vec<Vec<u8>> = seeds.iter().map(|(_, b)| b.clone()).collect();
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ target.len() as u64);
        for (path, seed) in &seeds {
            run(target, seed);
            for _ in 0..MUTATIONS_PER_SEED {
                let mutated = mutate(seed, &bodies, &mut rng);
                run(target, &mutated);
            }
            eprintln!(
                "[FUZZ-SMOKE] {target}: {} + {MUTATIONS_PER_SEED} mutations ok",
                path.file_name().unwrap().to_string_lossy()
            );
        }
        run(target, b"");
        run(target, &[0xff, 0xfe, 0x00]);
    }
}

#[test]
fn seeds_parse_for_the_targets_that_expect_valid_input() {
    // Sanity: the curated seeds are valid inputs for their parsers, so the
    // round-trip branches are exercised, not just the reject branches.
    let cfg = fs::read_to_string(corpus_dir("config_parse").join("readme_example.toml")).unwrap();
    let (_, unknown) = storage_ballast_helper::core::config::Config::parse_toml(&cfg)
        .expect("README example config parses");
    assert!(unknown.is_empty(), "{unknown:?}");
    let state = serde_json::to_string(
        &storage_ballast_helper::daemon::self_monitor::DaemonState::default(),
    )
    .unwrap();
    run("state_json", state.as_bytes());
}
