//! Find marked trees under the scratch roots, survey them, and decide which
//! units are dormant.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::config::RelocationConfig;
use super::ledger::Ledger;
use super::survey::{self, PolicyVeto, TreeSurvey, UnitStats};
use crate::platform::pal::Platform;
use crate::scanner::walker::{ActiveReferenceIndex, collect_active_reference_index};

/// A directory holding a `.sbh-protect` marker under a scratch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MarkedTree {
    /// The marked directory.
    pub path: PathBuf,
    /// False when the marker opts out or its permission cannot be established.
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

/// Read a marker's `relocatable` key without following links or blocking.
///
/// Empty and valid metadata markers remain relocatable;
/// malformed, unreadable, or unsafe markers never grant permission.
#[must_use]
pub fn marker_relocatable(dir: &Path) -> bool {
    survey::open_directory(dir)
        .and_then(|directory| survey::marker_policy(&directory))
        .is_ok_and(|policy| policy != Some(false))
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
        let marker =
            survey::open_directory(&dir).and_then(|directory| survey::marker_policy(&directory));
        if !matches!(marker, Ok(None)) {
            found.push(MarkedTree {
                relocatable: matches!(marker, Ok(Some(true))),
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

fn uncertain_policy(path: &Path, reason: impl std::fmt::Display) -> PolicyVeto {
    PolicyVeto {
        path: path.to_path_buf(),
        reason: format!("cannot establish relocation permission: {reason}"),
        excluded_pattern: None,
    }
}

/// Check the full configured scope, including markers above the first marked
/// tree. With overlapping roots the outermost one wins: naming a deeper root
/// cannot bypass an opt-out or excluded component below the outer root.
fn ancestor_policy(
    config: &RelocationConfig,
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<(), PolicyVeto> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(uncertain_policy(
            path,
            "candidate path is not an absolute, confined path",
        ));
    }
    let root = config
        .roots
        .iter()
        .filter(|root| path.starts_with(root))
        .min_by_key(|root| root.components().count())
        .ok_or_else(|| uncertain_policy(path, "candidate is outside configured scratch roots"))?;
    if root.components().any(|part| part == Component::ParentDir) {
        return Err(uncertain_policy(
            root,
            "scratch root contains a parent component",
        ));
    }
    if let Some(veto) = survey::excluded_veto(config, root) {
        return Err(veto);
    }
    let mut directory = match survey::open_directory(root) {
        Ok(directory) => directory,
        // A configured root may itself be the marked relocation unit. Once
        // renamed, its marker is checked at tree_path by the fresh survey;
        // a root recreated meanwhile is inspected normally and may opt out.
        Err(error)
            if allow_missing_leaf
                && root == path
                && error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        Err(error) => return Err(uncertain_policy(root, error)),
    };
    let mut current = root.clone();
    let relative = path
        .strip_prefix(root)
        .map_err(|error| uncertain_policy(path, error))?;
    let mut components = relative.components();
    loop {
        if let Some(veto) = survey::excluded_veto(config, &current)
            .or_else(|| survey::marker_veto(&directory, &current))
        {
            return Err(veto);
        }
        let Some(Component::Normal(name)) = components.next() else {
            return Ok(());
        };
        current.push(name);
        if let Some(veto) = survey::excluded_veto(config, &current) {
            return Err(veto);
        }
        // Ancestor policy is read-only. An explicitly configured scratch
        // root may be a mount below another configured root; inspect its
        // ancestors without rejecting that valid scope. The subtree survey
        // separately refuses every mount boundary inside the moved unit.
        let opened = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(std::io::Error::from);
        directory = match opened {
            Ok(child) => child,
            Err(error)
                if allow_missing_leaf
                    && current == path
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => return Err(uncertain_policy(&current, error)),
        };
    }
}

/// Renew relocation policy at an execution boundary.
///
/// `original_path` is the operator-visible location; `tree_path` is that directory before copy, or
/// its renamed sibling before removal. Ancestor opt-outs remain effective
/// after rename, while descendant policy is read from the actual source.
///
/// The existing entry budget bounds a fresh policy-aware survey. Incomplete
/// evidence, unsafe markers, mount crossings and exclusions all refuse the
/// operation. The complete survey is returned so the executor can also renew
/// its content comparison without a second traversal. Process safety still
/// requires a fresh holder check after this walk.
pub fn check_relocation_policy(
    config: &RelocationConfig,
    original_path: &Path,
    tree_path: &Path,
) -> Result<TreeSurvey, String> {
    if original_path != tree_path && original_path.parent() != tree_path.parent() {
        return Err("renamed relocation source is not a sibling of the original path".into());
    }
    let renamed = original_path != tree_path;
    ancestor_policy(config, original_path, renamed).map_err(|veto| veto.to_string())?;
    let survey = survey::survey_tree_with_policy(tree_path, 0, config.max_entries, config)
        .map_err(|error| format!("cannot inspect relocation policy: {error}"))?;
    let unit = &survey.units[0];
    if survey.truncated || unit.unreadable || unit.crosses_mount {
        return Err("relocation policy survey is incomplete or crosses a mount".into());
    }
    if let Some(veto) = &unit.relocation_veto {
        return Err(veto.to_string());
    }
    let source = survey::open_directory(tree_path)
        .map_err(|error| format!("cannot renew source policy: {error}"))?;
    if let Some(veto) = survey::marker_veto(&source, tree_path) {
        return Err(veto.to_string());
    }
    // A large subtree walk must not hide an owner opt-out made on its
    // ancestors while that walk was running.
    ancestor_policy(config, original_path, renamed).map_err(|veto| veto.to_string())?;
    Ok(survey)
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
    if let Some(veto) = &stats.relocation_veto {
        return veto
            .excluded_pattern
            .as_ref()
            .map_or(Verdict::NotRelocatable, |pattern| Verdict::Excluded {
                pattern: pattern.clone(),
            });
    }
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
        let Ok(mut survey) =
            survey::survey_tree_with_policy(&tree.path, config.unit_depth, budget, config)
        else {
            continue;
        };
        if let Err(veto) = ancestor_policy(config, &tree.path, false) {
            for unit in &mut survey.units {
                unit.relocation_veto.get_or_insert_with(|| veto.clone());
            }
        }
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
                    && stats.relocation_veto.is_none()
                    && tree.relocatable
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
    use crate::platform::pal::MockPlatform;
    use crate::relocate::ledger::Observation;
    use crate::scanner::protection::MARKER_FILENAME;

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
            relocation_veto: None,
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

    fn test_config(root: &Path) -> RelocationConfig {
        RelocationConfig {
            roots: vec![root.to_path_buf()],
            min_bytes: 0,
            unit_depth: 1,
            max_entries: 1_000,
            ..RelocationConfig::default()
        }
    }

    /// Supply a real continuous observation history so the same fixture
    /// works on both atime and noatime test filesystems.
    fn dormant_plan(config: &RelocationConfig, marked: &Path) -> Plan {
        let now = chrono::Utc::now().timestamp() + 30 * DAY;
        let survey = survey::survey_tree(marked, config.unit_depth, config.max_entries).unwrap();
        let mut ledger = Ledger::default();
        for unit in survey.units {
            ledger.observations.insert(
                unit.path,
                Observation {
                    quiet_since: now - 20 * DAY,
                    last_seen: now,
                    newest_change: unit.newest_change,
                },
            );
        }
        build_plan(config, &MockPlatform::healthy(), &mut ledger, now)
    }

    #[test]
    fn nested_opt_out_and_cache_keep_enclosing_units_but_allow_safe_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let marked = tmp.path().join("session");
        for directory in ["pinned/deep/inside", ".cargo", "safe"] {
            fs::create_dir_all(marked.join(directory)).unwrap();
            fs::write(marked.join(directory).join("data"), b"preserve").unwrap();
        }
        fs::write(marked.join(MARKER_FILENAME), "added_by = \"agent\"\n").unwrap();
        let pinned = marked.join("pinned/deep/inside").join(MARKER_FILENAME);
        fs::write(&pinned, "relocatable = false\n").unwrap();
        let plan = dormant_plan(&test_config(tmp.path()), &marked);
        let selected: Vec<_> = plan
            .selected()
            .iter()
            .map(|unit| unit.stats.path.clone())
            .collect();
        assert_eq!(selected, vec![marked.join("safe")]);
        let parent = plan
            .candidates
            .iter()
            .find(|unit| unit.stats.path == marked)
            .unwrap();
        assert!(parent.stats.relocation_veto.is_some());
        let pinned_unit = plan
            .candidates
            .iter()
            .find(|unit| unit.stats.path == marked.join("pinned"))
            .unwrap();
        assert_eq!(pinned_unit.verdict, Verdict::NotRelocatable);
        assert_eq!(
            pinned_unit.stats.relocation_veto.as_ref().unwrap().path,
            pinned
        );
        let cache = plan
            .candidates
            .iter()
            .find(|unit| unit.stats.path == marked.join(".cargo"))
            .unwrap();
        assert_eq!(
            cache.verdict,
            Verdict::Excluded {
                pattern: ".cargo".into()
            }
        );
    }

    #[test]
    fn malformed_outer_marker_vetoes_every_child_and_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let marked = tmp.path().join("session");
        fs::create_dir_all(marked.join("child")).unwrap();
        fs::write(marked.join("child/data"), b"keep").unwrap();
        fs::write(marked.join(MARKER_FILENAME), "relocatable = \"false\"\n").unwrap();
        let plan = dormant_plan(&test_config(tmp.path()), &marked);
        assert_eq!(plan.marked_trees, 1);
        assert!(plan.selected().is_empty());
        assert_eq!(plan.candidates.len(), 2);
        assert!(
            plan.candidates
                .iter()
                .all(|unit| unit.verdict == Verdict::NotRelocatable)
        );
    }

    #[test]
    fn fresh_policy_honors_ancestor_opt_out_across_overlapping_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let marked = tmp.path().join("outer/session");
        let child = marked.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(marked.join(MARKER_FILENAME), "").unwrap();
        fs::write(child.join("data"), b"keep").unwrap();
        let mut config = test_config(tmp.path());
        config.roots.push(marked.clone());
        assert!(check_relocation_policy(&config, &child, &child).is_ok());
        // The owner opts out above the first marked tree after planning.
        let ancestor_marker = tmp.path().join(MARKER_FILENAME);
        fs::write(&ancestor_marker, "relocatable = false\n").unwrap();
        let refusal = check_relocation_policy(&config, &child, &child).unwrap_err();
        assert!(refusal.contains(&ancestor_marker.display().to_string()));
        assert!(refusal.contains("relocatable = false"));
        assert!(dormant_plan(&config, &marked).selected().is_empty());
    }

    #[test]
    fn fresh_policy_reads_renamed_source_and_original_ancestors() {
        let tmp = tempfile::tempdir().unwrap();
        let marked = tmp.path().join("session");
        let child = marked.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(marked.join(MARKER_FILENAME), "").unwrap();
        fs::write(child.join("data"), b"keep").unwrap();
        let config = test_config(tmp.path());
        let aside = marked.join("child.sbh-relocating");
        fs::rename(&child, &aside).unwrap();
        assert!(check_relocation_policy(&config, &child, &aside).is_ok());
        fs::write(marked.join(MARKER_FILENAME), "relocatable = false\n").unwrap();
        assert!(check_relocation_policy(&config, &child, &aside).is_err());
        fs::write(marked.join(MARKER_FILENAME), "").unwrap();
        fs::write(aside.join(MARKER_FILENAME), "relocatable = false\n").unwrap();
        assert!(check_relocation_policy(&config, &child, &aside).is_err());
    }

    #[test]
    fn configured_root_can_be_renewed_after_rename_without_ignoring_a_new_opt_out() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("scratch");
        fs::create_dir(&root).unwrap();
        fs::write(root.join(MARKER_FILENAME), "").unwrap();
        fs::write(root.join("data"), b"keep").unwrap();
        let config = test_config(&root);
        let aside = tmp.path().join("scratch.sbh-relocating");
        fs::rename(&root, &aside).unwrap();
        assert!(check_relocation_policy(&config, &root, &aside).is_ok());
        fs::create_dir(&root).unwrap();
        fs::write(root.join(MARKER_FILENAME), "relocatable = false\n").unwrap();
        assert!(check_relocation_policy(&config, &root, &aside).is_err());
    }

    #[test]
    fn exclusions_are_scoped_to_scratch_root_and_include_descendants() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rch-outside-scope/scratch");
        let marked = root.join("session");
        fs::create_dir_all(marked.join("safe")).unwrap();
        fs::write(marked.join(MARKER_FILENAME), "").unwrap();
        let mut config = test_config(&root);
        assert!(check_relocation_policy(&config, &marked, &marked).is_ok());
        config.exclude.push("keep-*".into());
        fs::create_dir_all(marked.join("deep/inside/keep-data")).unwrap();
        assert!(check_relocation_policy(&config, &marked, &marked).is_err());
        let safe = marked.join("safe");
        assert!(check_relocation_policy(&config, &safe, &safe).is_ok());
        let mut outside = config.clone();
        outside.roots = vec![tmp.path().join("unrelated")];
        assert!(check_relocation_policy(&outside, &safe, &safe).is_err());
    }

    #[test]
    fn fresh_policy_refuses_incomplete_walks() {
        let tmp = tempfile::tempdir().unwrap();
        let marked = tmp.path().join("session");
        fs::create_dir(&marked).unwrap();
        fs::write(marked.join(MARKER_FILENAME), "").unwrap();
        fs::write(marked.join("data"), b"keep").unwrap();
        let mut config = test_config(tmp.path());
        config.max_entries = 1;
        assert!(check_relocation_policy(&config, &marked, &marked).is_err());
    }
}
