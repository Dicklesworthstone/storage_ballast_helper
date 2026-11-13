//! Public state-file contract across reserve metrics and both cockpit renderers.
#![cfg(feature = "tui")]
#![allow(clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use storage_ballast_helper::ballast::coordinator::{
    BallastRefillBlocker, BallastReserveSnapshot, BallastReserveState,
};
use storage_ballast_helper::daemon::metrics;
use storage_ballast_helper::daemon::self_monitor::{
    BallastPoolState, BallastState, DaemonState, DiscoveryState, MountPressure, PressureState,
};
use storage_ballast_helper::platform::pal::MockPlatform;
use storage_ballast_helper::tui::adapters::{DashboardStateAdapter, StateAdapter};
use storage_ballast_helper::tui::model::{DashboardModel, DashboardMsg, Screen};
use storage_ballast_helper::tui::{render, update};

const GIB: u64 = 1 << 30;

fn observed_pool(mount: &str, available: usize, now: DateTime<Utc>) -> BallastPoolState {
    let bytes = u64::try_from(available).unwrap() * GIB;
    BallastPoolState {
        mount: mount.into(),
        ballast_dir: format!("{mount}/ballast"),
        // Actuator bookkeeping deliberately remains full after a release.
        available: 4,
        total: 4,
        releasable_bytes: 4 * GIB,
        reserve: Some(BallastReserveSnapshot {
            observed_at: now.to_rfc3339(),
            mount_point: PathBuf::from(mount),
            ballast_dir: PathBuf::from(format!("{mount}/ballast")),
            files_available: available,
            files_total: 4,
            releasable_bytes: bytes,
            configured_bytes: 4 * GIB,
            state: BallastReserveState::classify(4 * GIB, bytes, true),
            inventory_authoritative: true,
            unreadable_count: 0,
            headroom: None,
            headroom_error: None,
            refill_blockers: if available < 4 {
                vec![
                    BallastRefillBlocker::PressurePolicy,
                    BallastRefillBlocker::SafetyFloor,
                ]
            } else {
                Vec::new()
            },
            refill_in_progress: false,
        }),
        ..Default::default()
    }
}

fn state(available: usize) -> DaemonState {
    // The public live reader owns its clock. Broad margins avoid sleeps and
    // timing races; injected-clock unit tests cover the exact 90-second edge.
    let now = Utc::now() - chrono::Duration::seconds(1);
    DaemonState {
        pid: std::process::id(),
        run_id: "reserve-reader-contract".into(),
        started_at: (now - chrono::Duration::hours(12)).to_rfc3339(),
        last_updated: now.to_rfc3339(),
        ballast: BallastState {
            available: 8,
            total: 8,
            released: 0,
        },
        ballast_pools: vec![
            observed_pool("/data", available, now),
            observed_pool("/safe", 4, now),
        ],
        pressure: PressureState {
            overall: "yellow".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 15.0,
                level: "yellow".into(),
                rate_bps: None,
            }],
        },
        ..Default::default()
    }
}

fn adapter() -> DashboardStateAdapter {
    DashboardStateAdapter::new(
        Arc::new(MockPlatform::default()),
        Duration::from_secs(90),
        Duration::ZERO,
    )
}

fn model(path: &Path) -> DashboardModel {
    let mut model = DashboardModel::new(path.into(), vec![], Duration::from_secs(1), (180, 60));
    model.screen = Screen::Ballast;
    model.ballast_detail = true;
    model
}

fn publish_and_read(
    path: &Path,
    state: &DaemonState,
    adapter: &DashboardStateAdapter,
    model: &mut DashboardModel,
) -> String {
    std::fs::write(path, serde_json::to_vec(state).unwrap()).unwrap();
    filetime::set_file_mtime(
        path,
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(1)),
    )
    .unwrap();
    // Metrics and the cockpit consume the same serialized document, including
    // the distinction between a missing observation and a confirmed zero.
    let document: DaemonState = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let exposition = metrics::render(&document, "contract-test");
    metrics::validate_exposition(&exposition).unwrap();
    update::update(
        model,
        DashboardMsg::DataUpdate(adapter.read_state(path).map(Box::new)),
    );
    exposition
}

fn rendered(model: &DashboardModel) -> [String; 2] {
    let mut pool = ftui::GraphemePool::new();
    let mut frame = ftui::Frame::new(model.terminal_size.0, model.terminal_size.1, &mut pool);
    render::render_frame(model, &mut frame);
    let mut text = String::new();
    for y in 0..model.terminal_size.1 {
        for x in 0..model.terminal_size.0 {
            text.push(
                frame
                    .buffer
                    .get(x, y)
                    .and_then(|cell| cell.content.as_char())
                    .unwrap_or(' '),
            );
        }
        text.push('\n');
    }
    [render::render_to_string(model), text]
}

fn sample<'a>(text: &'a str, name: &str, labels: &[(&str, &str)]) -> Option<&'a str> {
    text.lines()
        .find(|line| {
            line.strip_prefix(name)
                .is_some_and(|tail| tail.starts_with('{') || tail.starts_with(' '))
                && labels
                    .iter()
                    .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        })
        .and_then(|line| line.rsplit_once(' ').map(|(_, value)| value))
}

fn both_contain(model: &DashboardModel, expected: &str) {
    for text in rendered(model) {
        assert!(
            text.contains(expected),
            "missing {expected:?} in rendered cockpit:\n{text}"
        );
    }
}

#[test]
fn observed_release_and_recovery_reach_metrics_and_the_cockpit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let adapter = adapter();
    let mut model = model(&path);
    for (available, condition, badge) in [
        (0, "exhausted", "EXHAUSTED"),
        (1, "critical", "CRITICAL"),
        (2, "depleted", "LOW"),
        (4, "healthy", "OK"),
    ] {
        model.screen = Screen::Ballast;
        let export = publish_and_read(&path, &state(available), &adapter, &mut model);
        assert!(!model.degraded);
        both_contain(&model, badge);
        both_contain(&model, &format!("{available}/4"));
        assert_eq!(
            sample(
                &export,
                "sbh_ballast_reserve_state",
                &[("mount", "/data"), ("state", condition)]
            ),
            Some("1")
        );
        assert_eq!(
            sample(&export, "sbh_ballast_present_bytes", &[("mount", "/data")]),
            Some(
                (u64::try_from(available).unwrap() * GIB)
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(
            sample(
                &export,
                "sbh_ballast_reserve_state",
                &[("mount", "/safe"), ("state", "healthy")]
            ),
            Some("1")
        );
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "available")]),
            Some((available + 4).to_string().as_str())
        );
        assert_eq!(
            sample(&export, "sbh_ballast_inventory_complete", &[]),
            Some("1")
        );
        assert_eq!(
            sample(
                &export,
                "sbh_ballast_refill_blocked",
                &[("mount", "/data"), ("reason", "safety_floor")]
            ),
            Some(if available < 4 { "1" } else { "0" })
        );
        if available < 4 {
            both_contain(&model, "safety floor");
            both_contain(&model, "pressure policy suppresses refill");
        }
        model.screen = Screen::Overview;
        both_contain(&model, badge);
        both_contain(&model, &format!("available={}/8", available + 4));
    }
}

#[test]
fn unknown_inventory_never_becomes_zero_or_cached_protection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let adapter = adapter();
    let mut model = model(&path);
    for case in [
        "missing",
        "pending",
        "invalid",
        "future",
        "stale",
        "unreadable",
        "legacy",
    ] {
        let mut state = state(4);
        match case {
            "missing" => state.ballast_pools[0].reserve = None,
            "legacy" => state.ballast_pools.clear(),
            _ => {
                let reserve = state.ballast_pools[0].reserve.as_mut().unwrap();
                match case {
                    "pending" => {
                        reserve.observed_at.clear();
                        reserve.inventory_authoritative = false;
                    }
                    "invalid" => reserve.observed_at = "not-a-timestamp".into(),
                    "future" => {
                        reserve.observed_at = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
                    }
                    "stale" => {
                        reserve.observed_at = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
                    }
                    "unreadable" => {
                        reserve.inventory_authoritative = false;
                        reserve.state = BallastReserveState::Unknown;
                        reserve.unreadable_count = 1;
                        reserve.refill_blockers = vec![BallastRefillBlocker::InventoryUnreadable];
                    }
                    _ => unreachable!(),
                }
            }
        }
        model.screen = Screen::Ballast;
        let export = publish_and_read(&path, &state, &adapter, &mut model);
        assert!(
            !model.degraded,
            "{case}: fresh daemon document remains readable"
        );
        both_contain(&model, "UNKNOWN");
        both_contain(
            &model,
            if case == "legacy" {
                "unknown/8"
            } else {
                "unknown/4"
            },
        );
        assert_eq!(
            sample(&export, "sbh_ballast_present_bytes", &[("mount", "/data")]),
            None,
            "{case}"
        );
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "available")]),
            None,
            "{case}"
        );
        assert_eq!(
            sample(&export, "sbh_ballast_inventory_complete", &[]),
            Some("0"),
            "{case}"
        );
        if case != "legacy" {
            assert_eq!(
                sample(
                    &export,
                    "sbh_ballast_reserve_state",
                    &[("mount", "/data"), ("state", "unknown")]
                ),
                Some("1"),
                "{case}"
            );
            assert_eq!(
                sample(&export, "sbh_ballast_present_bytes", &[("mount", "/safe")]),
                Some((4 * GIB).to_string().as_str()),
                "{case}"
            );
            // A confirmed exhausted sibling remains visible when another
            // pool is unreadable; uncertainty must not hide observed loss.
            let now = DateTime::parse_from_rfc3339(&state.last_updated)
                .unwrap()
                .with_timezone(&Utc);
            state.ballast_pools[1] = observed_pool("/safe", 0, now);
            publish_and_read(&path, &state, &adapter, &mut model);
            model.screen = Screen::Overview;
            both_contain(&model, "EXHAUSTED");
            both_contain(&model, "available=unknown/8");
        }
    }

    for (pending, reload_pending) in [(true, false), (false, true)] {
        let mut document = state(0);
        document.discovery = Some(DiscoveryState {
            pending,
            reload_pending,
            ..Default::default()
        });
        document.ballast = BallastState::default();
        document.ballast_pools.clear();
        model.screen = Screen::Overview;
        let export = publish_and_read(&path, &document, &adapter, &mut model);
        assert!(!model.degraded, "discovery must not hide a live daemon");
        both_contain(&model, "UNKNOWN");
        both_contain(&model, "available=unknown");
        for text in rendered(&model) {
            assert!(!text.contains("unknown/0"), "{text}");
            assert!(!text.contains("UNCONFIGURED"), "{text}");
        }
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "total")]),
            None
        );
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "available")]),
            None
        );

        // Previously verified pools remain individually useful while a new
        // discovery plan is pending, but they cannot establish fleet totals.
        let observed_at = DateTime::parse_from_rfc3339(&document.last_updated)
            .unwrap()
            .with_timezone(&Utc);
        document.ballast_pools = vec![
            observed_pool("/data", 0, observed_at),
            observed_pool("/safe", 4, observed_at),
        ];
        document.ballast.total = 8;
        let export = publish_and_read(&path, &document, &adapter, &mut model);
        both_contain(&model, "EXHAUSTED");
        both_contain(&model, "available=unknown");
        assert_eq!(
            sample(&export, "sbh_ballast_present_bytes", &[("mount", "/data")]),
            Some("0")
        );
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "available")]),
            None
        );

        document.discovery = Some(DiscoveryState::default());
        let export = publish_and_read(&path, &document, &adapter, &mut model);
        both_contain(&model, "available=4/8");
        assert_eq!(
            sample(&export, "sbh_ballast_files", &[("state", "available")]),
            Some("4")
        );
    }
}

#[test]
fn stopped_and_copied_old_state_cannot_keep_healthy_inventory_visible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let adapter = adapter();
    let mut model = model(&path);
    for stopped in [false, true] {
        let mut state = state(4);
        publish_and_read(&path, &state, &adapter, &mut model);
        assert!(!model.degraded);
        assert_eq!(model.ballast_volumes.len(), 2);
        if stopped {
            state.stopped_at = Some(state.last_updated.clone());
        } else {
            let old = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
            state.started_at = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();
            state.last_updated.clone_from(&old);
            for pool in &mut state.ballast_pools {
                pool.reserve.as_mut().unwrap().observed_at.clone_from(&old);
            }
        }
        // publish_and_read gives even the old document a fresh file mtime.
        let export = publish_and_read(&path, &state, &adapter, &mut model);
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());
        assert!(model.ballast_volumes.is_empty());
        model.screen = Screen::Overview;
        both_contain(&model, "UNKNOWN");
        for text in rendered(&model) {
            assert!(!text.contains("available=8/8"));
        }
        if stopped {
            assert_eq!(
                sample(&export, "sbh_ballast_files", &[("state", "available")]),
                None
            );
        } else {
            // A pure textfile render describes publication time. Scrapers
            // detect a copied old document by its exported publication age.
            let timestamp = DateTime::parse_from_rfc3339(&state.last_updated)
                .unwrap()
                .timestamp()
                .to_string();
            assert_eq!(
                sample(&export, "sbh_state_last_updated_timestamp_seconds", &[]),
                Some(timestamp.as_str())
            );
        }
    }
}
