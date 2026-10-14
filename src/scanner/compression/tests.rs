use super::*;
use std::time::UNIX_EPOCH;

#[test]
fn default_policy_is_bounded_and_cannot_be_weakened_below_safety_floors() {
    let policy = CompressionPolicy::default();
    assert!(policy.validate().is_ok());
    for invalid in [
        CompressionPolicy { min_age_secs: 3599, ..policy.clone() },
        CompressionPolicy { min_free_bytes: 0, ..policy.clone() },
        CompressionPolicy { max_files: 0, ..policy.clone() },
        CompressionPolicy { max_files: 4097, ..policy.clone() },
        CompressionPolicy { timeout_secs: 0, ..policy.clone() },
        CompressionPolicy { timeout_secs: 3601, ..policy.clone() },
        CompressionPolicy { max_bytes: 1, ..policy.clone() },
        CompressionPolicy { min_size_bytes: 0, ..policy },
    ] {
        assert!(invalid.validate().is_err(), "{invalid:?}");
    }
}

#[test]
fn cold_file_age_is_inclusive_and_future_timestamps_fail_closed() {
    let now = UNIX_EPOCH + Duration::from_secs(100_000);
    assert!(cold_enough(now - Duration::from_secs(3600), now, 3600));
    assert!(!cold_enough(now - Duration::from_secs(3599), now, 3600));
    assert!(!cold_enough(now + Duration::from_secs(1), now, 3600));
}

#[test]
fn compressed_suffix_exclusions_are_case_insensitive_but_jsonl_is_eligible() {
    for path in ["archive.ZST", "image.JPEG", "clip.mp4", "font.woff2", "bundle.tar.gz"] {
        assert!(already_compressed(Path::new(path)), "{path}");
    }
    for path in ["old-session.jsonl", "debug/my-binary", "object.o", "recording.wav"] {
        assert!(!already_compressed(Path::new(path)), "{path}");
    }
}

#[test]
fn policy_serialization_rejects_misspelled_limits() {
    let policy = CompressionPolicy::default();
    let mut value = serde_json::to_value(&policy).unwrap();
    value["min_ag_secs"] = serde_json::json!(3600);
    assert!(serde_json::from_value::<CompressionPolicy>(value).is_err());
}

#[test]
fn apply_requires_both_acknowledgements_before_any_file_access() {
    use crate::platform::pal::MockPlatform;
    for mode in [
        CompressionMode { apply: true, ..CompressionMode::default() },
        CompressionMode { apply: true, allow_zstd_feature: true, quiescent: false },
        CompressionMode { apply: true, allow_zstd_feature: false, quiescent: true },
    ] {
        let error = run(&["/nonexistent/no-file-opened".into()], &CompressionPolicy::default(),
            mode, &Config::default(), &MockPlatform::healthy()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("requires"));
    }
}

#[test]
fn unknown_verification_and_accounting_are_not_serialized_as_zero_savings() {
    let report = CompressionFileReport::new(Path::new("/tmp/file"));
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["mutation_attempted"], false);
    assert_eq!(json["content_verified"], false);
    assert!(json["physical_data_bytes_after"].is_null());
    assert!(json["reclaim"].is_null());
    assert!(json["sha256_after"].is_null());
}

#[test]
fn an_empty_input_pass_is_rejected_without_platform_calls() {
    use crate::platform::pal::MockPlatform;
    let error = run(&[], &CompressionPolicy::default(), CompressionMode::default(),
        &Config::default(), &MockPlatform::healthy()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_cannot_suppress_post_mutation_reports() {
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/cold-\xff.bin".to_vec()));
    let mut report = CompressionFileReport::new(&path);
    report.mutation_attempted = true;
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["mutation_attempted"], true);
    assert_eq!(json["path"], path.to_string_lossy().as_ref());
    assert_eq!(report.path, path);
}
