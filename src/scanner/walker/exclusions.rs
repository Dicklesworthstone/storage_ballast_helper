//! Per-walk exclusion scopes, including configured root aliases.
//!
//! Resolve policy and root spellings once, before workers start. Ordinary
//! no-follow traversal then needs only component-aware hash lookups, not a
//! canonicalize syscall for every directory in a large artifact tree.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::WalkerConfig;
use crate::core::errors::{Result, SbhError};
use crate::scanner::protection::exclusion_path_spellings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExclusionRelation {
    Clear,
    Excluded,
    ContainsExcluded,
}

#[derive(Default)]
pub(super) struct WalkExclusions {
    recursive: HashSet<PathBuf>,
    exact: HashSet<PathBuf>,
    ancestors: HashSet<PathBuf>,
    unresolved_roots: HashSet<PathBuf>,
}

impl WalkExclusions {
    pub(super) fn new(config: &WalkerConfig) -> Result<Self> {
        let mut result = Self::default();
        if config.excluded_paths.is_empty() {
            return Ok(result);
        }
        let resolve = |path: &Path| {
            exclusion_path_spellings(path).map_err(|source| SbhError::Io {
                path: path.to_path_buf(),
                source,
            })
        };
        let mut roots = Vec::new();
        for root in &config.root_paths {
            match resolve(root) {
                Ok(spellings) => roots.push((root, spellings)),
                Err(_) => {
                    // Unknown scope prevents admitting this root, including
                    // if its alias becomes readable after preparation. Other
                    // configured roots still have independent, valid scopes.
                    result.unresolved_roots.insert(root.clone());
                }
            }
        }
        for excluded in &config.excluded_paths {
            // Unlike an unavailable root, an unknown exclusion can overlap
            // any healthy root. Its scope must be known before any traversal.
            let spellings = resolve(excluded)?;
            // `/` prevents a whole-filesystem scan, not every scan. An alias
            // resolving to `/` has the same exact-only meaning.
            let recursive = spellings[1].parent().is_some();
            result.insert(excluded.clone(), recursive);
            for spelling in &spellings {
                result.insert(spelling.clone(), recursive);
                for (root, root_spellings) in &roots {
                    for root_spelling in root_spellings {
                        if spelling == root_spelling
                            || (recursive && root_spelling.starts_with(spelling))
                        {
                            result.insert((*root).clone(), recursive);
                        } else if let Ok(suffix) = spelling.strip_prefix(root_spelling) {
                            // Workers retain the root's original spelling,
                            // including relative paths and configured aliases.
                            result.insert(root.join(suffix), recursive);
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub(super) fn root_is_unresolved(&self, root: &Path) -> bool {
        self.unresolved_roots.contains(root)
    }

    fn insert(&mut self, path: PathBuf, recursive: bool) {
        if recursive {
            for ancestor in path.ancestors().skip(1) {
                self.ancestors.insert(ancestor.to_path_buf());
            }
            self.recursive.insert(path);
        } else {
            self.exact.insert(path);
        }
    }

    fn spelling_relation(&self, path: &Path) -> ExclusionRelation {
        if self.exact.contains(path)
            || path
                .ancestors()
                .any(|parent| self.recursive.contains(parent))
        {
            ExclusionRelation::Excluded
        } else if self.ancestors.contains(path) {
            ExclusionRelation::ContainsExcluded
        } else {
            ExclusionRelation::Clear
        }
    }

    pub(super) fn relation(&self, path: &Path, follow_symlinks: bool) -> ExclusionRelation {
        let direct = self.spelling_relation(path);
        if !follow_symlinks
            || direct == ExclusionRelation::Excluded
            || (self.recursive.is_empty() && self.exact.is_empty())
        {
            return direct;
        }
        // Following child aliases is opt-in and needs their actual location.
        // A failed resolution is unknown scope and cannot authorize traversal.
        let Ok(resolved) = fs::canonicalize(path) else {
            return ExclusionRelation::Excluded;
        };
        match self.spelling_relation(&resolved) {
            ExclusionRelation::Clear => direct,
            relation => relation,
        }
    }
}
