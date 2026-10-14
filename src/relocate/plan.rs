//! Find marked trees under the scratch roots, survey them, and decide which
//! units are dormant.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config::RelocationConfig;
use super::ledger::Ledger;
use super::survey::{self, TreeSurvey, UnitStats};
use crate::platform::pal::Platform;
use crate::scanner::protection::MARKER_FILENAME;
use crate::scanner::walker::{ActiveReferenceIndex, collect_active_reference_index};

/// A directory holding a `.sbh-protect` marker under a scratch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MarkedTree {
    /// The marked directory.
    pub path: PathBuf,
    /// False when the marker says `relocatable = false`.
    pub relocatable: bool,
}

/// Why a unit is, or is not, eligible.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Dormant for the whole window, unheld, and movable.
    Eligible,
    /// Something below it changed within the window.
    Changed {
        /// Days since the newest change.
        idle_days: f64,
    },
    /// A regular file below it was read within the window.
    Read {
        /// Days since the newest regular-file read.
        idle_days: f64,
    },
    /// No atime on this mount; quiet observed for fewer days than the window.
    Observing {
        /// Days of continuous quiet observed so far.
        observed_days: f64,
    },
    /// A live process holds it, or the process sweep was incomplete.
    Held {
        /// What holds it.
        reason: String,
    },
    /// A path component matches a never-relocate pattern.
    Excluded {
        /// The matching pattern.
        pattern: String,
    },
    /// Its marker opts out with `relocatable = false`.
    NotRelocatable,
    /// It contains another mount.
    CrossesMount,
    /// Some directory below it could not be read.
    Unreadable,
    /// The walk budget ran out before the tree was fully seen.
    Truncated,
}

/// One unit and its verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// The marked tree it belongs to.
    pub marked_tree: PathBuf,
    /// The unit's aggregates.
    #[serde(flatten)]
    pub stats: UnitStats,
    /// Whether its mount maintains atime.
    pub atime_evidence: bool,
    /// Days of continuous quiet in the ledger.
    pub observed_days: Option<f64>,
    /// The decision.
    #[serde(flatten)]
    pub verdict: Verdict,
    /// Chosen for relocation: eligible, with no eligible ancestor.
    pub selected: bool,
}

/// The outcome of one planning pass.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// Marked trees found under the roots.
    pub marked_trees: usize,
    /// Units at or above `min_bytes`, parents first.
    pub candidates: Vec<Candidate>,
    /// Entries walked.
    pub entries: u64,
    /// The run's walk budget ran out.
    pub truncated: bool,
}

impl Plan {
    /// Selected candidates, largest first.
    #[must_use]
    pub fn selected(&self) -> Vec<&Candidate> {
        let mut selected: Vec<_> = self.candidates.iter().filter(|c| c.selected).collect();
        selected.sort_by_key(|candidate| std::cmp::Reverse(candidate.stats.bytes));
        selected
    }
}

/// Read a marker's `relocatable` key. A marker that does not parse as TOML
/// (an empty or legacy marker) is relocatable.
#[must_use]
pub fn marker_relocatable(dir: &Path) -> bool {
    let Ok(text) = fs::read_to_string(dir.join(MARKER_FILENAME)) else {
        return true;
    };
    toml::from_str::<toml::Table>(&text)
        .ok()
        .and_then(|table| table.get("relocatable").and_then(toml::Value::as_bool))
        .unwrap_or(true)
}

/// Marked trees under `root`, searched `depth` levels deep. A marker ends
/// the search below it; a component matching an exclusion, a symlink, or
/// another device is not entered.
#[must_use]
pub fn find_marked_trees(root: &Path, config: &RelocationConfig) -> Vec<MarkedTree> {
    let mut found = Vec::new();
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return found;
    };
    if !root_meta.is_dir() {
        return found;
    }
    let device = std::os::unix::fs::MetadataExt::dev(&root_meta);
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if dir.join(MARKER_FILENAME).is_file() {
            found.push(MarkedTree {
                relocatable: marker_relocatable(&dir),
                path: dir,
            });
            continue;
        }
        if depth >= config.marker_depth {
            continue;
        }
        let Ok(reader) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in reader.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_dir() || std::os::unix::fs::MetadataExt::dev(&meta) != device {
                continue;
            }
            if config
                .excluded_by(&entry.file_name().to_string_lossy())
                .is_some()
            {
                continue;
            }
            stack.push((entry.path(), depth + 1));
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// One process sweep over `roots`, retried while it is incomplete.
///
/// A process that exits between listing `/proc` and reading its descriptors
/// leaves the sweep incomplete. That clears on a retry; a process sbh truly
/// cannot inspect does not, and then the caller treats the tree as held.
#[must_use]
pub fn sweep(platform: &dyn Platform, roots: &[PathBuf]) -> ActiveReferenceIndex {
    let mut index = collect_active_reference_index(platform, roots);
    for _ in 0..2 {
        if index.is_complete() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        index = collect_active_reference_index(platform, roots);
    }
    index
}

/// Holder evidence for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holders {
    /// Nobody holds it, and the sweep saw every process.
    None,
    /// A live process holds it.
    Held(String),
    /// The sweep was incomplete: no evidence either way.
    Unknown(String),
}

impl Holders {
    /// Read the evidence for `path` from a sweep.
    #[must_use]
    pub fn of(index: &ActiveReferenceIndex, path: &Path) -> Self {
        let summary = index.summary_for(path);
        let Some(reason) = summary.safe_reclaim_reason() else {
            return Self::None;
        };
        if summary.processes.iter().any(|process| !process.is_empty()) {
            Self::Held(reason.into_owned())
        } else {
            Self::Unknown(reason.into_owned())
        }
    }

    /// Why it is not safe to move, if it is not.
    #[must_use]
    pub fn veto(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Held(reason) | Self::Unknown(reason) => Some(reason.clone()),
        }
    }
}

fn days(seconds: i64) -> f64 {
    // Report precision only; the decisions compare whole seconds.
    #[allow(clippy::cast_precision_loss)]
    let days = seconds as f64 / 86_400.0;
    (days * 10.0).round() / 10.0
}

/// Inputs to one unit's verdict besides its aggregates.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// The whole tree's walk was cut short.
    pub truncated: bool,
    /// The unit's mount maintains atime.
    pub atime_maintained: bool,
    /// Why a live process makes it unsafe, if one does.
    pub held: Option<String>,
    /// Seconds of continuous quiet in the ledger.
    pub observed_quiet: Option<i64>,
    /// The exclusion pattern matching a component, if any.
    pub excluded: Option<String>,
    /// The marker allows relocation.
    pub relocatable: bool,
}

/// Decide one unit.
#[must_use]
pub fn classify(stats: &UnitStats, evidence: &Evidence, now: i64, window: i64) -> Verdict {
    if let Some(pattern) = &evidence.excluded {
        return Verdict::Excluded {
            pattern: pattern.clone(),
        };
    }
    if !evidence.relocatable {
        return Verdict::NotRelocatable;
    }
    if evidence.truncated {
        return Verdict::Truncated;
    }
    if stats.unreadable {
        return Verdict::Unreadable;
    }
    if stats.crosses_mount {
        return Verdict::CrossesMount;
    }
    if let Some(reason) = &evidence.held {
        return Verdict::Held {
            reason: reason.clone(),
        };
    }
    let change_idle = now.saturating_sub(stats.newest_change);
    if change_idle < window {
        return Verdict::Changed {
            idle_days: days(change_idle),
        };
    }
    if evidence.atime_maintained {
        // No regular file means no read to look for; the change age stands.
        let access_idle = stats
            .newest_access
            .map_or(change_idle, |access| now.saturating_sub(access));
        if access_idle < window {
            return Verdict::Read {
                idle_days: days(access_idle),
            };
        }
        return Verdict::Eligible;
    }
    match evidence.observed_quiet {
        Some(observed) if observed >= window => Verdict::Eligible,
        observed => Verdict::Observing {
            observed_days: days(observed.unwrap_or(0)),
        },
    }
}

/// Survey every marked tree under the configured roots, update the ledger's
/// quiet streaks, and choose what to relocate.
pub fn build_plan(
    config: &RelocationConfig,
    platform: &dyn Platform,
    ledger: &mut Ledger,
    now: i64,
) -> Plan {
    let window = config.min_idle_secs();
    let gap = config.max_gap_secs();
    let trees: Vec<MarkedTree> = config
        .roots
        .iter()
        .flat_map(|root| find_marked_trees(root, config))
        .collect();
    let mut plan = Plan {
        marked_trees: trees.len(),
        candidates: Vec::new(),
        entries: 0,
        truncated: false,
    };
    let mut surveys: Vec<(MarkedTree, TreeSurvey)> = Vec::new();
    for tree in trees {
        let budget = config.max_entries.saturating_sub(plan.entries);
        if budget == 0 {
            plan.truncated = true;
            break;
        }
        let Ok(survey) = survey::survey_tree(&tree.path, config.unit_depth, budget) else {
            continue;
        };
        plan.entries += survey.entries;
        plan.truncated |= survey.truncated;
        surveys.push((tree, survey));
    }
    // One process sweep answers every tree.
    let roots: Vec<PathBuf> = surveys.iter().map(|(tree, _)| tree.path.clone()).collect();
    let references = sweep(platform, &roots);
    for (tree, survey) in &surveys {
        let atime_maintained = survey::atime_maintained(&tree.path).unwrap_or(false);
        let mut chosen: Vec<PathBuf> = Vec::new();
        for stats in &survey.units {
            if stats.bytes < config.min_bytes {
                continue;
            }
            let excluded = stats
                .path
                .strip_prefix(&tree.path)
                .ok()
                .into_iter()
                .flat_map(Path::components)
                .find_map(|component| config.excluded_by(&component.as_os_str().to_string_lossy()));
            let holders = Holders::of(&references, &stats.path);
            // An incomplete sweep is no evidence either way: it neither
            // extends nor resets the streak. A gap that outlasts max_gap
            // breaks the streak on its own.
            if !matches!(holders, Holders::Unknown(_)) {
                let quiet = !survey.truncated
                    && !stats.unreadable
                    && !stats.crosses_mount
                    && holders == Holders::None;
                ledger.observe(&stats.path, stats.newest_change, quiet, now, gap);
            }
            let held = holders.veto();
            let evidence = Evidence {
                truncated: survey.truncated,
                atime_maintained,
                held,
                observed_quiet: ledger.observed_quiet(&stats.path, now, gap),
                excluded,
                relocatable: tree.relocatable,
            };
            let verdict = classify(stats, &evidence, now, window);
            let selected = verdict == Verdict::Eligible
                && !chosen.iter().any(|parent| stats.path.starts_with(parent));
            if selected {
                chosen.push(stats.path.clone());
            }
            plan.candidates.push(Candidate {
                marked_tree: tree.path.clone(),
                stats: stats.clone(),
                atime_evidence: atime_maintained,
                observed_days: evidence.observed_quiet.map(days),
                verdict,
                selected,
            });
        }
    }
    ledger.prune(now, gap);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const NOW: i64 = 2_000_000_000;

    fn stats(change_days: i64, access_days: Option<i64>) -> UnitStats {
        UnitStats {
            path: PathBuf::from("/data/tmp/x"),
            depth: 0,
            bytes: 1 << 30,
            files: 10,
            entries: 12,
            newest_change: NOW - change_days * DAY,
            newest_change_below: NOW - change_days * DAY,
            newest_access: access_days.map(|days| NOW - days * DAY),
            crosses_mount: false,
            unreadable: false,
            uid: 1000,
            gid: 1000,
            mode: 0o755,
        }
    }

    fn evidence(atime: bool) -> Evidence {
        Evidence {
            atime_maintained: atime,
            relocatable: true,
            ..Evidence::default()
        }
    }

    #[test]
    fn atime_mounts_need_both_change_and_access_idle() {
        let window = 14 * DAY;
        assert_eq!(
            classify(&stats(20, Some(15)), &evidence(true), NOW, window),
            Verdict::Eligible
        );
        assert!(matches!(
            classify(&stats(20, Some(3)), &evidence(true), NOW, window),
            Verdict::Read { .. }
        ));
        assert!(matches!(
            classify(&stats(5, Some(30)), &evidence(true), NOW, window),
            Verdict::Changed { .. }
        ));
        // No regular files: the change age decides.
        assert_eq!(
            classify(&stats(20, None), &evidence(true), NOW, window),
            Verdict::Eligible
        );
    }

    #[test]
    fn noatime_mounts_need_an_observed_streak() {
        let window = 14 * DAY;
        let mut without = evidence(false);
        assert!(matches!(
            classify(&stats(60, Some(60)), &without, NOW, window),
            Verdict::Observing { .. }
        ));
        without.observed_quiet = Some(13 * DAY);
        assert!(matches!(
            classify(&stats(60, Some(60)), &without, NOW, window),
            Verdict::Observing { .. }
        ));
        without.observed_quiet = Some(14 * DAY);
        assert_eq!(
            classify(&stats(60, Some(60)), &without, NOW, window),
            Verdict::Eligible
        );
    }

    #[test]
    fn vetoes_win_over_dormancy() {
        let window = 14 * DAY;
        let dormant = stats(60, Some(60));
        let mut held = evidence(true);
        held.held = Some("pid 7 (cargo) has 1 open file".into());
        assert!(matches!(
            classify(&dormant, &held, NOW, window),
            Verdict::Held { .. }
        ));
        let mut pinned = evidence(true);
        pinned.relocatable = false;
        assert_eq!(
            classify(&dormant, &pinned, NOW, window),
            Verdict::NotRelocatable
        );
        let mut excluded = evidence(true);
        excluded.excluded = Some("rch*".into());
        assert!(matches!(
            classify(&dormant, &excluded, NOW, window),
            Verdict::Excluded { .. }
        ));
        let mut truncated = evidence(true);
        truncated.truncated = true;
        assert_eq!(
            classify(&dormant, &truncated, NOW, window),
            Verdict::Truncated
        );
        let mut crossing = dormant;
        crossing.crosses_mount = true;
        assert_eq!(
            classify(&crossing, &evidence(true), NOW, window),
            Verdict::CrossesMount
        );
    }

    #[test]
    fn marker_discovery_respects_exclusions_and_opt_out() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in [
            "a/marked",
            "rch-cargo-cache-x/inner",
            "pinned",
            "deep/1/2/3/4/5",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(
            root.join("a/marked").join(MARKER_FILENAME),
            "added_by = \"agent\"\n",
        )
        .unwrap();
        fs::write(
            root.join("rch-cargo-cache-x/inner").join(MARKER_FILENAME),
            "",
        )
        .unwrap();
        fs::write(
            root.join("pinned").join(MARKER_FILENAME),
            "relocatable = false\n",
        )
        .unwrap();
        fs::write(root.join("deep/1/2/3/4/5").join(MARKER_FILENAME), "").unwrap();
        let config = RelocationConfig::default();
        let trees = find_marked_trees(root, &config);
        assert_eq!(
            trees,
            vec![
                MarkedTree {
                    path: root.join("a/marked"),
                    relocatable: true
                },
                MarkedTree {
                    path: root.join("pinned"),
                    relocatable: false
                },
            ]
        );
    }
}
