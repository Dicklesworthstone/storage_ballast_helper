//! Which running browser may own a macOS code-sign clone (bd-39da).
//!
//! Each launch of a Chromium browser APFS-clones its app bundle to
//! `/var/folders/<xx>/<hash>/X/<bundle-id>.code_sign_clone/code_sign_clone.XXXXXX/<App>.app.bundle`,
//! with the main executable a hard link to the one it runs, so its code
//! signature stays valid after a staged update replaces the installed app
//! (Chromium `code_sign_clone_manager.h`). Open-file, executable and mapping
//! evidence cannot tell which clone is live: Opera and Brave hold nothing in
//! theirs (mac-studio, 2026-10-16), and every clone made from one binary
//! shares its executable inode, so the kernel names whichever link it last
//! resolved (mac-mini-max: eight clones, one inode, the reported path moving
//! between them across scans). A clone is born seconds after its browser
//! starts, so a running instance of the same app that started shortly before
//! a clone's birth may own it; the newest clone of a running app is kept too.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::platform::types::ProcessInfo;
use crate::scanner::patterns::is_browser_code_sign_clone;

/// How long after its browser starts a clone may be born (observed: 3-4 s).
const BIRTH_WINDOW: Duration = Duration::from_mins(10);
/// Timestamp granularity: a start recorded just after the clone's birth.
const START_SLACK: Duration = Duration::from_secs(2);
/// More clones than this leave the listing incomplete.
const MAX_CLONES: usize = 65_536;

/// A running process of a macOS app bundle's main executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AppInstance {
    pub(super) app: String,
    pub(super) pid: i32,
    pub(super) name: String,
    pub(super) started: Option<SystemTime>,
}

impl AppInstance {
    pub(super) fn of_process(process: &ProcessInfo) -> Option<Self> {
        Self::of(
            process.pid,
            &process.name,
            process.executable.as_deref()?,
            process.start_time_unix_ms,
        )
    }

    /// The app `executable` belongs to when it is a bundle's main executable,
    /// `<App>.app/Contents/MacOS/<exe>` (or a clone's `<App>.app.bundle`).
    fn of(pid: i32, name: &str, executable: &Path, started_unix_ms: Option<i64>) -> Option<Self> {
        let macos = executable.parent()?;
        let contents = macos.parent()?;
        if macos.file_name()? != "MacOS" || contents.file_name()? != "Contents" {
            return None;
        }
        let app = app_name(contents.parent()?.file_name()?.to_str()?)?;
        let started = started_unix_ms
            .and_then(|ms| u64::try_from(ms).ok())
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms));
        Some(Self {
            app: app.to_string(),
            pid,
            name: name.to_string(),
            started,
        })
    }
}

/// One clone on disk and the apps it copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodeSignClone {
    pub(super) path: PathBuf,
    pub(super) apps: Vec<String>,
    pub(super) born: Option<SystemTime>,
    /// No clone of the same browser was born later.
    pub(super) newest: bool,
}

impl CodeSignClone {
    /// The running instances that may own this clone: the same app (any app
    /// when the clone's content is unreadable), started at most
    /// [`BIRTH_WINDOW`] before the clone was born, or any time when it is
    /// the newest. An unknown time counts as a possible owner.
    pub(super) fn owners<'a>(
        &'a self,
        instances: &'a [AppInstance],
    ) -> impl Iterator<Item = &'a AppInstance> + 'a {
        instances.iter().filter(move |instance| {
            (self.apps.is_empty() || self.apps.contains(&instance.app))
                && (self.newest
                    || match (instance.started, self.born) {
                        (Some(started), Some(born)) => {
                            started <= born + START_SLACK
                                && born
                                    .duration_since(started)
                                    .map_or(true, |gap| gap <= BIRTH_WINDOW)
                        }
                        _ => true,
                    })
        })
    }
}

/// Mark every clone under `roots` that a running instance of its app may own.
pub(super) fn add_owners(
    index: &mut super::ActiveReferenceIndex,
    roots: &[PathBuf],
    instances: &[AppInstance],
) {
    if instances.is_empty() {
        return;
    }
    let (clones, complete) = clones_under(Path::new("/private/var/folders"));
    if !complete {
        index.complete = false;
    }
    for clone in &clones {
        for owner in clone.owners(instances) {
            index.add_reference(roots, &clone.path, |summary| {
                summary.add_app_instance(owner.pid, Some(owner.name.clone()));
            });
        }
    }
}

/// Every clone in the per-user clone areas below `folders`
/// (`/private/var/folders`), and whether the listing is complete.
fn clones_under(folders: &Path) -> (Vec<CodeSignClone>, bool) {
    let mut clones = Vec::new();
    for area in subdirs(folders)
        .iter()
        .flat_map(|outer| subdirs(outer))
        .map(|user| user.join("X"))
    {
        for container in subdirs(&area) {
            if !container
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".code_sign_clone"))
            {
                continue;
            }
            let first = clones.len();
            for path in subdirs(&container) {
                if !is_browser_code_sign_clone(&path) {
                    continue;
                }
                if clones.len() == MAX_CLONES {
                    return (clones, false);
                }
                clones.push(read_clone(path));
            }
            mark_newest(&mut clones[first..]);
        }
    }
    (clones, true)
}

fn read_clone(path: PathBuf) -> CodeSignClone {
    let born = fs::symlink_metadata(&path)
        .and_then(|meta| meta.created())
        .ok();
    let apps = fs::read_dir(&path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(app_name)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    CodeSignClone {
        path,
        apps,
        born,
        newest: false,
    }
}

/// One browser's clones: the latest born is the newest, and so is any whose
/// birth time is unknown.
fn mark_newest(clones: &mut [CodeSignClone]) {
    let latest = clones.iter().filter_map(|clone| clone.born).max();
    for clone in clones {
        clone.newest = clone.born.is_none() || clone.born == latest;
    }
}

/// `Opera` for `Opera.app` or a clone's `Opera.app.bundle`.
fn app_name(bundle: &str) -> Option<&str> {
    bundle
        .strip_suffix(".app.bundle")
        .or_else(|| bundle.strip_suffix(".app"))
        .filter(|name| !name.is_empty())
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    dirs
}

#[cfg(test)]
mod tests {
    use super::{AppInstance, CodeSignClone, START_SLACK, app_name, mark_newest};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn app_instances_are_bundle_main_executables() {
        let opera = AppInstance::of(
            598,
            "Opera",
            Path::new("/Applications/Opera.app/Contents/MacOS/Opera"),
            Some(1_000),
        )
        .unwrap();
        assert_eq!(opera.app, "Opera");
        assert_eq!(opera.started, Some(UNIX_EPOCH + Duration::from_secs(1)));
        // Chrome runs from its clone.
        let chrome = AppInstance::of(
            602,
            "Google Chrome",
            Path::new("/private/var/folders/vt/n2xy/X/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk/Google Chrome.app.bundle/Contents/MacOS/Google Chrome"),
            None,
        )
        .unwrap();
        assert_eq!(chrome.app, "Google Chrome");
        for not_main in [
            "/usr/bin/true",
            "/Applications/Opera.app/Contents/Frameworks/Opera Framework.framework/Versions/1/Helpers/chrome_crashpad_handler",
            "/Applications/Opera.app/Contents/Resources/Opera",
            "/Contents/MacOS/x",
        ] {
            assert_eq!(
                AppInstance::of(1, "x", Path::new(not_main), None),
                None,
                "{not_main}"
            );
        }
        assert_eq!(app_name(".app"), None);
        assert_eq!(app_name("Brave Browser.app.bundle"), Some("Brave Browser"));
    }

    #[test]
    fn a_clone_is_owned_by_its_apps_instances_started_just_before_it() {
        let at = |secs: u64| Some(UNIX_EPOCH + Duration::from_secs(secs));
        let instance = |app: &str, pid: i32, started| AppInstance {
            app: app.to_string(),
            pid,
            name: app.to_string(),
            started,
        };
        let clone = CodeSignClone {
            path: PathBuf::from(
                "/private/var/folders/vt/n2xy/X/com.operasoftware.Opera.code_sign_clone/code_sign_clone.QSFYpT",
            ),
            apps: vec!["Opera".to_string()],
            born: at(100_004),
            newest: false,
        };
        let instances = [
            // Opera started 4 s before the clone: its creator.
            instance("Opera", 1, at(100_000)),
            // Same app, started a day earlier: another launch's clone.
            instance("Opera", 2, at(13_600)),
            // Started after the clone was born: it made its own.
            instance("Opera", 3, at(100_004 + START_SLACK.as_secs() + 1)),
            // Another app at the same moment.
            instance("Brave Browser", 4, at(100_000)),
            // No start time: may be the creator.
            instance("Opera", 5, None),
        ];
        let owners: Vec<i32> = clone.owners(&instances).map(|owner| owner.pid).collect();
        assert_eq!(owners, [1, 5]);
        // Without a birth time every instance of the app may own it, and so
        // may any running instance own the app's newest clone: a running
        // browser can move to a clone born long after it started.
        for owned_by_all in [
            CodeSignClone {
                born: None,
                ..clone.clone()
            },
            CodeSignClone {
                newest: true,
                ..clone.clone()
            },
        ] {
            let owners: Vec<i32> = owned_by_all
                .owners(&instances)
                .map(|owner| owner.pid)
                .collect();
            assert_eq!(owners, [1, 2, 3, 5]);
        }
        // Unreadable content: any running app may own it.
        let unreadable = CodeSignClone {
            apps: Vec::new(),
            ..clone
        };
        let owners: Vec<i32> = unreadable
            .owners(&instances)
            .map(|owner| owner.pid)
            .collect();
        assert_eq!(owners, [1, 4, 5]);
    }

    #[test]
    fn the_latest_born_and_undated_clones_are_the_newest() {
        let at = |secs: u64| Some(UNIX_EPOCH + Duration::from_secs(secs));
        let clone = |born| CodeSignClone {
            path: PathBuf::new(),
            apps: Vec::new(),
            born,
            newest: false,
        };
        let mut clones = [clone(at(3)), clone(at(9)), clone(None), clone(at(1))];
        mark_newest(&mut clones);
        let newest: Vec<bool> = clones.iter().map(|clone| clone.newest).collect();
        assert_eq!(newest, [false, true, true, false]);
        mark_newest(&mut []);
    }
}
