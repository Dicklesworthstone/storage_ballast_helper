//! Final traversal receipts used to admit recursive cleanup scopes.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::errors::Result;
use crate::platform::pal::{Platform, detect_platform};
use crate::scanner::planner::{SafetyObservation, hard_veto, rejected_scopes};
use crate::scanner::protection::ProtectionRegistry;
use crate::scanner::scoring::CandidacyScore;
use crate::scanner::walker::{
    DirectoryWalker, FsIdentity, WalkEntry, WalkerConfig, identity_for_path,
};

/// A no-follow walk through disjoint canonical roots on one mount per device
/// has unique directory spellings. Elsewhere unfinished branches might hide
/// aliases of candidates on the same filesystem.
#[derive(Default)]
pub(crate) struct RootCoverage {
    pub(crate) isolated_roots: Vec<PathBuf>,
    pub(crate) root_devices: HashMap<PathBuf, u64>,
}

impl RootCoverage {
    pub(crate) fn new(roots: &[PathBuf], follow_links: bool, platform: &dyn Platform) -> Self {
        let mut result = Self::default();
        if follow_links {
            return result;
        }
        let Ok(mounts) = platform.mount_points() else {
            return result;
        };
        let mut bindings = Vec::new();
        for root in roots {
            let (Ok(real), Ok(id)) = (
                std::fs::canonicalize(root),
                identity_for_path(root, true),
            ) else {
                // An unresolved scan root might be another route to any device.
                return result;
            };
            result.root_devices.insert(root.clone(), id.device_id);
            bindings.push((root, real, id));
        }
        // Bind mounts can expose the same directory through an unrelated root.
        // Mark both the mounted and enclosing devices ambiguous; independent
        // volumes retain their early dispatch and partial coverage receipts.
        let mut ambiguous = HashSet::new();
        let mut owners = HashMap::new();
        for (_, real, id) in &bindings {
            if let Some(mount) = mounts
                .iter()
                .filter(|mount| real.starts_with(&mount.path))
                .max_by_key(|mount| mount.path.components().count())
            {
                if (cfg!(target_os = "macos") && !mount.fs_type.eq_ignore_ascii_case("apfs"))
                    || owners
                        .insert(id.device_id, mount.path.as_path())
                        .is_some_and(|previous| previous != mount.path)
                {
                    ambiguous.insert(id.device_id);
                }
            } else {
                ambiguous.insert(id.device_id);
            }
            for mount in &mounts {
                if mount.path != *real && mount.path.starts_with(real) {
                    ambiguous.insert(id.device_id);
                    let Ok(nested) = identity_for_path(&mount.path, true)
                    else {
                        return result;
                    };
                    ambiguous.insert(nested.device_id);
                }
            }
        }
        for (root, real, id) in &bindings {
            // Two APFS case or Unicode spellings can coincide without sharing a
            // lexical prefix. Compare the physical identities of the ancestors.
            let mut ancestry = HashSet::new();
            for ancestor in real.ancestors().skip(1) {
                let Ok(parent) = identity_for_path(ancestor, true) else {
                    ambiguous.insert(id.device_id);
                    break;
                };
                ancestry.insert(parent);
            }
            if bindings
                .iter()
                .any(|(other, _, oid)| other != root && (oid == id || ancestry.contains(oid)))
            {
                ambiguous.insert(id.device_id);
            }
        }
        result.isolated_roots = bindings
            .into_iter()
            .filter(|(_, _, id)| !ambiguous.contains(&id.device_id))
            .map(|(root, _, _)| root.clone())
            .collect();
        result
    }

    pub(crate) fn covered<'a>(
        &'a self,
        unfinished: &'a [PathBuf],
        popped: Option<&'a Path>,
    ) -> impl Fn(&CandidacyScore) -> bool + 'a {
        // Index once: a full scan may rank hundreds of thousands of rows
        // alongside thousands of independent depth or protection boundaries.
        let gaps: BTreeSet<&Path> = unfinished
            .iter()
            .map(PathBuf::as_path)
            .chain(popped)
            .collect();
        let isolated: HashSet<&Path> = self.isolated_roots.iter().map(PathBuf::as_path).collect();
        let mut every_gap_mapped = true;
        let mut gap_devices = HashSet::new();
        for gap in &gaps {
            let mut devices = gap
                .ancestors()
                .filter(|root| isolated.contains(root))
                .filter_map(|root| self.root_devices.get(root));
            let Some(&device) = devices.next() else {
                every_gap_mapped = false;
                break;
            };
            // Cross-device proof needs a different isolated device for each
            // gap. A gap mapped to multiple devices can satisfy any known ID.
            if devices.all(|&other| other == device) {
                gap_devices.insert(device);
            }
        }

        move |row| {
            if gaps.is_empty() {
                return true;
            }
            let path = row.path.as_path();
            let overlaps = path.ancestors().any(|ancestor| gaps.contains(ancestor))
                || gaps
                    .range(path..)
                    .next()
                    .is_some_and(|gap| gap.starts_with(path));
            !overlaps
                && (path.ancestors().any(|parent| isolated.contains(parent))
                    || (every_gap_mapped
                        && row
                            .identity
                            .is_some_and(|id| !gap_devices.contains(&id.device_id))))
        }
    }
}

/// The disposition of an observation from a manual cleanup or its preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkRejection {
    /// The scope has complete traversal evidence and passed the supplied vetoes.
    Admitted,
    /// A hard veto or a category suspension covers this scope or an observed alias.
    Veto,
    /// Unseen or deliberately omitted ground prevents proving the scope complete.
    Uncovered,
}

/// A completed CLI walk, including evidence that a subtree could not be
/// inspected. Collecting entries alone discards that evidence at end-of-stream.
pub struct CleanupWalk {
    /// All observations, including rows below any eventual scoring threshold.
    pub entries: Vec<WalkEntry>,
    /// The walker retains the protection registry for reporting discovered markers.
    pub walker: DirectoryWalker,
    gaps: Option<Vec<PathBuf>>,
    roots: Vec<(PathBuf, Option<FsIdentity>)>,
    coverage: RootCoverage,
}

impl CleanupWalk {
    /// Walk the configured roots to EOF and capture both omitted and unfinished paths.
    pub fn collect(config: WalkerConfig, protection: ProtectionRegistry) -> Result<Self> {
        let coverage = RootCoverage::new(
            &config.root_paths,
            config.follow_symlinks,
            detect_platform()?.as_ref(),
        );
        // Roots are not emitted as entries, but their identities connect aliases.
        let roots = config
            .root_paths
            .iter()
            .map(|path| (path.clone(), identity_for_path(path, true).ok()))
            .collect();
        let walker = DirectoryWalker::new(config, protection);
        let mut stream = walker.stream()?;
        let omissions = stream.omitted_scopes();
        let entries = stream.by_ref().collect();
        let gaps = stream
            .unfinished_after_cancel(Duration::ZERO)
            .and_then(|mut gaps| {
                gaps.extend(omissions.lock().take()?);
                Some(gaps)
            });
        Ok(Self {
            entries,
            walker,
            gaps,
            roots,
            coverage,
        })
    }

    /// Supply all scored observations before filtering, including hard vetoes
    /// below the display threshold. Unscored directories still connect aliases.
    pub fn rejections<'a>(
        &'a self,
        scores: impl IntoIterator<Item = &'a CandidacyScore, IntoIter: Clone>,
    ) -> Vec<WalkRejection> {
        let scores = scores.into_iter();
        let vetoes = if scores.clone().any(hard_veto) {
            let roots = self.roots.iter().map(|(path, identity)| SafetyObservation {
                path,
                identity: *identity,
                vetoed: false,
            });
            let entries = self.entries.iter().map(|entry| SafetyObservation {
                path: &entry.path,
                identity: Some(entry.metadata.identity()),
                vetoed: false,
            });
            rejected_scopes(
                scores
                    .clone()
                    .map(SafetyObservation::from)
                    .chain(roots)
                    .chain(entries),
            )
        } else {
            vec![false; scores.clone().count()]
        };
        let covered = self
            .gaps
            .as_deref()
            .map(|gaps| self.coverage.covered(gaps, None));
        scores
            .zip(vetoes)
            .map(|(score, vetoed)| {
                if vetoed {
                    WalkRejection::Veto
                } else if covered.as_ref().is_some_and(|check| check(score)) {
                    WalkRejection::Admitted
                } else {
                    WalkRejection::Uncovered
                }
            })
            .collect()
    }

    /// Keep covered, non-vetoed observations in their input order.
    pub fn admit(&self, mut scores: Vec<CandidacyScore>) -> Vec<CandidacyScore> {
        let mut reasons = self.rejections(&scores).into_iter();
        scores.retain(|_| reasons.next() == Some(WalkRejection::Admitted));
        scores
    }
}
