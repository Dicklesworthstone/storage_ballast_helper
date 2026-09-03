//! Static macOS cleanup heuristic catalog.

#![allow(missing_docs)]

use crate::platform::cleanup_catalog;
pub use crate::platform::cleanup_catalog::{
    AgeThreshold, CheckRequirement, CleanupConfidence, CleanupRule, ReclaimCommand,
};

pub const XCODE_DERIVED_DATA: CleanupRule = cleanup_rule(
    "xcode-derived-data",
    "~/Library/Developer/Xcode/DerivedData/*",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Definite,
);

pub const CORE_SIMULATOR_CACHES: CleanupRule = cleanup_rule(
    "core-simulator-caches",
    "~/Library/Developer/CoreSimulator/Caches/*",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Definite,
);

pub const ELECTRON_CACHE: CleanupRule = cleanup_rule(
    "electron-cache",
    "~/Library/Application Support/*/Cache/*",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_CACHE_ROOT: CleanupRule = cleanup_rule(
    "electron-cache-root",
    "~/Library/Application Support/*/Cache",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_SERVICE_WORKER_CACHE: CleanupRule = cleanup_rule(
    "electron-service-worker-cache",
    "~/Library/Application Support/*/Service Worker/CacheStorage/*",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_SERVICE_WORKER_CACHE_ROOT: CleanupRule = cleanup_rule(
    "electron-service-worker-cache-root",
    "~/Library/Application Support/*/Service Worker/CacheStorage",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_CODE_CACHE: CleanupRule = cleanup_rule(
    "electron-code-cache",
    "~/Library/Application Support/*/Code Cache/*",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_CODE_CACHE_ROOT: CleanupRule = cleanup_rule(
    "electron-code-cache-root",
    "~/Library/Application Support/*/Code Cache",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_GPU_CACHE: CleanupRule = cleanup_rule(
    "electron-gpu-cache",
    "~/Library/Application Support/*/GPUCache/*",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_GPU_CACHE_ROOT: CleanupRule = cleanup_rule(
    "electron-gpu-cache-root",
    "~/Library/Application Support/*/GPUCache",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_INDEXED_DB: CleanupRule = cleanup_rule(
    "electron-indexed-db",
    "~/Library/Application Support/*/IndexedDB/*",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_INDEXED_DB_ROOT: CleanupRule = cleanup_rule(
    "electron-indexed-db-root",
    "~/Library/Application Support/*/IndexedDB",
    AgeThreshold::from_hours(1),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_VM_BUNDLES: CleanupRule = cleanup_rule(
    "electron-vm-bundles",
    "~/Library/Application Support/*/vm_bundles/*",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const ELECTRON_VM_BUNDLES_ROOT: CleanupRule = cleanup_rule(
    "electron-vm-bundles-root",
    "~/Library/Application Support/*/vm_bundles",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const TMP_DASH_TARGET: CleanupRule = cleanup_rule(
    "tmp-dash-target",
    "/private/tmp/*-target",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const TMP_UNDERSCORE_TARGET: CleanupRule = cleanup_rule(
    "tmp-underscore-target",
    "/private/tmp/*_target",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const TMP_TARGET_UNDERSCORE_PREFIX: CleanupRule = cleanup_rule(
    "tmp-target-underscore-prefix",
    "/private/tmp/target_*",
    AgeThreshold::from_hours(24),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const USER_NAMED_TRASH_EXACT: CleanupRule = cleanup_rule(
    "user-named-trash-exact",
    "/private/tmp/trash",
    AgeThreshold::NONE,
    CheckRequirement::Required,
    ReclaimCommand::PromptBeforeRemove,
    CleanupConfidence::Unclear,
);

pub const USER_NAMED_TRASHED_EXACT: CleanupRule = cleanup_rule(
    "user-named-trashed-exact",
    "/private/tmp/trashed",
    AgeThreshold::NONE,
    CheckRequirement::Required,
    ReclaimCommand::PromptBeforeRemove,
    CleanupConfidence::Unclear,
);

pub const USER_NAMED_TRASH: CleanupRule = cleanup_rule(
    "user-named-trash",
    "/private/tmp/*-trash-*",
    AgeThreshold::NONE,
    CheckRequirement::Required,
    ReclaimCommand::PromptBeforeRemove,
    CleanupConfidence::Unclear,
);

pub const RELEASE_WORK_BUILDROOT: CleanupRule = cleanup_rule(
    "release-work-buildroot",
    "~/release-work/*[-_]buildroot",
    AgeThreshold::from_days(7),
    CheckRequirement::Required,
    ReclaimCommand::RemoveTree,
    CleanupConfidence::Likely,
);

pub const USER_LOGS: CleanupRule = cleanup_rule(
    "user-logs",
    "~/Library/Logs/*",
    AgeThreshold::from_days(7),
    CheckRequirement::Required,
    ReclaimCommand::RemoveMatchingFiles,
    CleanupConfidence::Likely,
);

pub const IPSW_SOFTWARE_UPDATES: CleanupRule = cleanup_rule(
    "ipsw-software-updates",
    "~/Library/iTunes/iPhone Software Updates/*.ipsw",
    AgeThreshold::from_days(30),
    CheckRequirement::NotRequired,
    ReclaimCommand::RemoveMatchingFiles,
    CleanupConfidence::Definite,
);

pub const HOME_TRASH_REPORT: CleanupRule = cleanup_rule(
    "home-trash-report",
    "~/.Trash/*",
    AgeThreshold::NONE,
    CheckRequirement::NotRequired,
    ReclaimCommand::ReportOnly,
    CleanupConfidence::ReportOnly,
);

pub const ICLOUD_TRASH_REPORT: CleanupRule = cleanup_rule(
    "icloud-trash-report",
    "~/Library/Mobile Documents/com~apple~CloudDocs/.Trash/*",
    AgeThreshold::NONE,
    CheckRequirement::NotRequired,
    ReclaimCommand::ReportOnly,
    CleanupConfidence::ReportOnly,
);

pub const TIME_MACHINE_LOCAL_SNAPSHOTS: CleanupRule = cleanup_rule(
    "time-machine-local-snapshots",
    "/",
    AgeThreshold::NONE,
    CheckRequirement::NotRequired,
    ReclaimCommand::ThinLocalSnapshots,
    CleanupConfidence::Likely,
);

pub const SPOTLIGHT_INDEX_REPORT: CleanupRule = cleanup_rule(
    "spotlight-index-report",
    "/.Spotlight-V100",
    AgeThreshold::NONE,
    CheckRequirement::NotRequired,
    ReclaimCommand::ReportOnly,
    CleanupConfidence::ReportOnly,
);

pub const PHOTOS_LIBRARY_SACRED: CleanupRule = sacred_rule(
    "photos-library-sacred",
    "~/Pictures/Photos Library.photoslibrary",
);

pub const MAIL_LIBRARY_SACRED: CleanupRule = sacred_rule("mail-library-sacred", "~/Library/Mail/*");

pub const MESSAGES_LIBRARY_SACRED: CleanupRule =
    sacred_rule("messages-library-sacred", "~/Library/Messages/*");

pub const FINAL_CUT_LIBRARY_SACRED: CleanupRule =
    sacred_rule("final-cut-library-sacred", "~/Movies/*.fcpbundle");

pub const USER_LIBRARY_CACHES_APP: CleanupRule = cleanup_rule(
    "user-library-caches-app",
    "~/Library/Caches/*",
    AgeThreshold::from_days(7),
    CheckRequirement::Required,
    ReclaimCommand::PromptBeforeRemove,
    CleanupConfidence::Unclear,
);

pub const MAC_CLEANUP_RULES: &[CleanupRule] = &[
    XCODE_DERIVED_DATA,
    CORE_SIMULATOR_CACHES,
    ELECTRON_CACHE,
    ELECTRON_CACHE_ROOT,
    ELECTRON_SERVICE_WORKER_CACHE,
    ELECTRON_SERVICE_WORKER_CACHE_ROOT,
    ELECTRON_CODE_CACHE,
    ELECTRON_CODE_CACHE_ROOT,
    ELECTRON_GPU_CACHE,
    ELECTRON_GPU_CACHE_ROOT,
    ELECTRON_INDEXED_DB,
    ELECTRON_INDEXED_DB_ROOT,
    ELECTRON_VM_BUNDLES,
    ELECTRON_VM_BUNDLES_ROOT,
    TMP_DASH_TARGET,
    TMP_UNDERSCORE_TARGET,
    TMP_TARGET_UNDERSCORE_PREFIX,
    USER_NAMED_TRASH_EXACT,
    USER_NAMED_TRASHED_EXACT,
    USER_NAMED_TRASH,
    RELEASE_WORK_BUILDROOT,
    USER_LOGS,
    USER_LIBRARY_CACHES_APP,
    IPSW_SOFTWARE_UPDATES,
    HOME_TRASH_REPORT,
    ICLOUD_TRASH_REPORT,
    TIME_MACHINE_LOCAL_SNAPSHOTS,
    SPOTLIGHT_INDEX_REPORT,
    PHOTOS_LIBRARY_SACRED,
    MAIL_LIBRARY_SACRED,
    MESSAGES_LIBRARY_SACRED,
    FINAL_CUT_LIBRARY_SACRED,
];

#[must_use]
pub fn cleanup_rules() -> &'static [CleanupRule] {
    MAC_CLEANUP_RULES
}

#[must_use]
pub fn find_rule(name: &str) -> Option<&'static CleanupRule> {
    cleanup_catalog::find_rule(MAC_CLEANUP_RULES, name)
}

#[must_use]
pub fn match_rule(path: &std::path::Path) -> Option<&'static CleanupRule> {
    cleanup_catalog::match_rule(path, MAC_CLEANUP_RULES)
}

#[must_use]
pub fn match_path_scanner_rule(path: &std::path::Path) -> Option<&'static CleanupRule> {
    cleanup_catalog::match_path_scanner_rule(path, MAC_CLEANUP_RULES)
}

const fn cleanup_rule(
    name: &'static str,
    path_glob: &'static str,
    age_threshold: AgeThreshold,
    fd_check: CheckRequirement,
    reclaim_command: ReclaimCommand,
    confidence: CleanupConfidence,
) -> CleanupRule {
    CleanupRule {
        name,
        path_glob,
        age_threshold,
        fd_check,
        parent_check: CheckRequirement::Required,
        sacred_overlaps_check: CheckRequirement::Required,
        reclaim_command,
        confidence,
    }
}

const fn sacred_rule(name: &'static str, path_glob: &'static str) -> CleanupRule {
    CleanupRule {
        name,
        path_glob,
        age_threshold: AgeThreshold::NONE,
        fd_check: CheckRequirement::NotRequired,
        parent_check: CheckRequirement::NotRequired,
        sacred_overlaps_check: CheckRequirement::Required,
        reclaim_command: ReclaimCommand::Refuse,
        confidence: CleanupConfidence::Sacred,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;
    use std::time::Duration;

    use super::{
        AgeThreshold, CORE_SIMULATOR_CACHES, CheckRequirement, CleanupConfidence, CleanupRule,
        ELECTRON_CACHE, ELECTRON_CODE_CACHE, ELECTRON_GPU_CACHE, ELECTRON_INDEXED_DB,
        ELECTRON_SERVICE_WORKER_CACHE, ELECTRON_VM_BUNDLES, FINAL_CUT_LIBRARY_SACRED,
        HOME_TRASH_REPORT, ICLOUD_TRASH_REPORT, IPSW_SOFTWARE_UPDATES, MAC_CLEANUP_RULES,
        MAIL_LIBRARY_SACRED, MESSAGES_LIBRARY_SACRED, PHOTOS_LIBRARY_SACRED,
        RELEASE_WORK_BUILDROOT, ReclaimCommand, SPOTLIGHT_INDEX_REPORT,
        TIME_MACHINE_LOCAL_SNAPSHOTS, TMP_DASH_TARGET, TMP_TARGET_UNDERSCORE_PREFIX,
        TMP_UNDERSCORE_TARGET, USER_LIBRARY_CACHES_APP, USER_LOGS, USER_NAMED_TRASH,
        USER_NAMED_TRASH_EXACT, USER_NAMED_TRASHED_EXACT, XCODE_DERIVED_DATA, cleanup_rules,
        find_rule, match_path_scanner_rule, match_rule,
    };

    #[test]
    fn catalog_names_are_unique() {
        let mut names = HashSet::new();
        for rule in MAC_CLEANUP_RULES {
            assert!(
                names.insert(rule.name),
                "duplicate rule name: {}",
                rule.name
            );
        }
    }

    #[test]
    fn exported_catalog_is_the_static_catalog() {
        assert_eq!(cleanup_rules(), MAC_CLEANUP_RULES);
        assert_eq!(find_rule("xcode-derived-data"), Some(&XCODE_DERIVED_DATA));
        assert!(find_rule("missing").is_none());
    }

    #[test]
    fn destructive_rules_require_parent_and_sacred_checks() {
        for rule in MAC_CLEANUP_RULES
            .iter()
            .filter(|rule| rule.is_destructive())
            .filter(|rule| rule.confidence != CleanupConfidence::Sacred)
        {
            assert_eq!(
                rule.parent_check,
                CheckRequirement::Required,
                "{} must verify parent safety",
                rule.name
            );
            assert_eq!(
                rule.sacred_overlaps_check,
                CheckRequirement::Required,
                "{} must check sacred overlaps",
                rule.name
            );
        }
    }

    #[test]
    fn report_only_rules_never_delete() {
        for rule in [
            HOME_TRASH_REPORT,
            ICLOUD_TRASH_REPORT,
            SPOTLIGHT_INDEX_REPORT,
        ] {
            assert_eq!(rule.reclaim_command, ReclaimCommand::ReportOnly);
            assert_eq!(rule.confidence, CleanupConfidence::ReportOnly);
            assert!(!rule.is_destructive());
        }
    }

    #[test]
    fn sacred_rules_refuse_reclaim() {
        for rule in [
            PHOTOS_LIBRARY_SACRED,
            MAIL_LIBRARY_SACRED,
            MESSAGES_LIBRARY_SACRED,
            FINAL_CUT_LIBRARY_SACRED,
        ] {
            assert_eq!(rule.reclaim_command, ReclaimCommand::Refuse);
            assert_eq!(rule.confidence, CleanupConfidence::Sacred);
            assert!(!rule.is_destructive());
        }
    }

    #[test]
    fn xcode_derived_data_rule_is_definite() {
        assert_rule(
            XCODE_DERIVED_DATA,
            "xcode-derived-data",
            "~/Library/Developer/Xcode/DerivedData/*",
            CleanupConfidence::Definite,
            ReclaimCommand::RemoveTree,
            AgeThreshold::from_hours(24),
        );
    }

    #[test]
    fn core_simulator_cache_rule_is_definite() {
        assert_rule(
            CORE_SIMULATOR_CACHES,
            "core-simulator-caches",
            "~/Library/Developer/CoreSimulator/Caches/*",
            CleanupConfidence::Definite,
            ReclaimCommand::RemoveTree,
            AgeThreshold::from_hours(24),
        );
    }

    #[test]
    fn core_simulator_devices_are_not_cleanup_candidates() {
        for path in [
            Path::new("/Users/operator/Library/Developer/CoreSimulator/Devices"),
            Path::new(
                "/Users/operator/Library/Developer/CoreSimulator/Devices/ABCDEF/data/Library/Caches",
            ),
        ] {
            assert!(
                match_rule(path).is_none(),
                "CoreSimulator device state must not match a cleanup rule: {}",
                path.display()
            );
            assert!(
                match_path_scanner_rule(path).is_none(),
                "CoreSimulator device state must not become a path-scanner candidate: {}",
                path.display()
            );
        }
    }

    #[test]
    fn electron_cache_rules_cover_common_cache_shapes() {
        let rules = [
            (
                ELECTRON_CACHE,
                "~/Library/Application Support/*/Cache/*",
                "electron-cache",
            ),
            (
                ELECTRON_SERVICE_WORKER_CACHE,
                "~/Library/Application Support/*/Service Worker/CacheStorage/*",
                "electron-service-worker-cache",
            ),
            (
                ELECTRON_CODE_CACHE,
                "~/Library/Application Support/*/Code Cache/*",
                "electron-code-cache",
            ),
            (
                ELECTRON_GPU_CACHE,
                "~/Library/Application Support/*/GPUCache/*",
                "electron-gpu-cache",
            ),
            (
                ELECTRON_INDEXED_DB,
                "~/Library/Application Support/*/IndexedDB/*",
                "electron-indexed-db",
            ),
            (
                ELECTRON_VM_BUNDLES,
                "~/Library/Application Support/*/vm_bundles/*",
                "electron-vm-bundles",
            ),
        ];

        for (rule, path_glob, name) in rules {
            assert_rule(
                rule,
                name,
                path_glob,
                CleanupConfidence::Likely,
                ReclaimCommand::RemoveTree,
                if rule == ELECTRON_VM_BUNDLES {
                    AgeThreshold::from_hours(24)
                } else {
                    AgeThreshold::from_hours(1)
                },
            );
            assert_eq!(rule.fd_check, CheckRequirement::Required);
        }
    }

    #[test]
    fn temporary_cargo_target_rules_require_fd_checks() {
        let rules = [
            (TMP_DASH_TARGET, "/private/tmp/*-target"),
            (TMP_UNDERSCORE_TARGET, "/private/tmp/*_target"),
            (TMP_TARGET_UNDERSCORE_PREFIX, "/private/tmp/target_*"),
        ];

        for (rule, path_glob) in rules {
            assert_eq!(rule.path_glob, path_glob);
            assert_eq!(rule.fd_check, CheckRequirement::Required);
            assert_eq!(rule.confidence, CleanupConfidence::Likely);
            assert_eq!(rule.reclaim_command, ReclaimCommand::RemoveTree);
            assert_eq!(rule.age_threshold, AgeThreshold::from_hours(24));
        }
    }

    #[test]
    fn user_named_trash_rule_prompts_and_checks_fds() {
        for (rule, name, path_glob) in [
            (
                USER_NAMED_TRASH_EXACT,
                "user-named-trash-exact",
                "/private/tmp/trash",
            ),
            (
                USER_NAMED_TRASHED_EXACT,
                "user-named-trashed-exact",
                "/private/tmp/trashed",
            ),
            (
                USER_NAMED_TRASH,
                "user-named-trash",
                "/private/tmp/*-trash-*",
            ),
        ] {
            assert_rule(
                rule,
                name,
                path_glob,
                CleanupConfidence::Unclear,
                ReclaimCommand::PromptBeforeRemove,
                AgeThreshold::NONE,
            );
            assert_eq!(rule.fd_check, CheckRequirement::Required);
        }
    }

    #[test]
    fn release_work_buildroot_rule_is_likely_after_seven_days() {
        assert_rule(
            RELEASE_WORK_BUILDROOT,
            "release-work-buildroot",
            "~/release-work/*[-_]buildroot",
            CleanupConfidence::Likely,
            ReclaimCommand::RemoveTree,
            AgeThreshold::from_days(7),
        );
    }

    #[test]
    fn user_logs_rule_preserves_recent_logs() {
        assert_rule(
            USER_LOGS,
            "user-logs",
            "~/Library/Logs/*",
            CleanupConfidence::Likely,
            ReclaimCommand::RemoveMatchingFiles,
            AgeThreshold::from_days(7),
        );
    }

    #[test]
    fn ipsw_rule_keeps_recent_firmware_files() {
        assert_rule(
            IPSW_SOFTWARE_UPDATES,
            "ipsw-software-updates",
            "~/Library/iTunes/iPhone Software Updates/*.ipsw",
            CleanupConfidence::Definite,
            ReclaimCommand::RemoveMatchingFiles,
            AgeThreshold::from_days(30),
        );
    }

    #[test]
    fn ipsw_rule_only_matches_software_update_firmware_files() {
        let firmware =
            Path::new("/Users/operator/Library/iTunes/iPhone Software Updates/iPhone_17.ipsw");
        assert_eq!(match_rule(firmware), Some(&IPSW_SOFTWARE_UPDATES));
        assert_eq!(
            match_path_scanner_rule(firmware),
            Some(&IPSW_SOFTWARE_UPDATES)
        );

        for path in [
            Path::new("/Users/operator/Downloads/iPhone_17.ipsw"),
            Path::new("/Users/operator/Library/iTunes/iPhone Software Updates/readme.txt"),
        ] {
            assert!(
                match_rule(path).is_none(),
                "non-update IPSW-adjacent path must not match: {}",
                path.display()
            );
            assert!(
                match_path_scanner_rule(path).is_none(),
                "non-update IPSW-adjacent path must not be scanned: {}",
                path.display()
            );
        }
    }

    #[test]
    fn time_machine_rule_uses_tmutil_not_path_deletion() {
        assert_rule(
            TIME_MACHINE_LOCAL_SNAPSHOTS,
            "time-machine-local-snapshots",
            "/",
            CleanupConfidence::Likely,
            ReclaimCommand::ThinLocalSnapshots,
            AgeThreshold::NONE,
        );
        assert_eq!(
            TIME_MACHINE_LOCAL_SNAPSHOTS.fd_check,
            CheckRequirement::NotRequired
        );
    }

    #[test]
    fn age_threshold_helpers_use_expected_durations() {
        assert_eq!(AgeThreshold::NONE.minimum_age, Duration::ZERO);
        assert_eq!(
            AgeThreshold::from_hours(2).minimum_age,
            Duration::from_hours(2)
        );
        assert_eq!(
            AgeThreshold::from_days(2).minimum_age,
            Duration::from_hours(48)
        );
    }

    fn assert_rule(
        rule: CleanupRule,
        name: &str,
        path_glob: &str,
        confidence: CleanupConfidence,
        reclaim_command: ReclaimCommand,
        age_threshold: AgeThreshold,
    ) {
        assert_eq!(rule.name, name);
        assert_eq!(rule.path_glob, path_glob);
        assert_eq!(rule.confidence, confidence);
        assert_eq!(rule.reclaim_command, reclaim_command);
        assert_eq!(rule.age_threshold, age_threshold);
        assert_eq!(rule.sacred_overlaps_check, CheckRequirement::Required);
    }

    #[test]
    fn user_library_caches_app_rule_matches_app_cache_directory() {
        assert_rule(
            USER_LIBRARY_CACHES_APP,
            "user-library-caches-app",
            "~/Library/Caches/*",
            CleanupConfidence::Unclear,
            ReclaimCommand::PromptBeforeRemove,
            AgeThreshold::from_days(7),
        );
        let app_cache = Path::new("/Users/developer/Library/Caches/com.apple.dt.Xcode");
        let matched = match_rule(app_cache).expect("must match user-library-caches-app");
        assert_eq!(matched.name, "user-library-caches-app");
        assert_eq!(matched.confidence, CleanupConfidence::Unclear);
        assert_eq!(matched.reclaim_command, ReclaimCommand::PromptBeforeRemove);
    }
}
