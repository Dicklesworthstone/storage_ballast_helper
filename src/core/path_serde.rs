//! Byte-preserving JSON path fields for persisted scanner state.
//!
//! UTF-8 paths retain Serde's ordinary string representation byte-for-byte,
//! including checkpoint hash inputs. Other Unix paths use a typed byte array,
//! never a replacement character or an ambiguous string escape convention.
//! This is a representation, not filesystem validation or deletion authority.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    if let Some(text) = path.to_str() {
        return serializer.serialize_str(text);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use serde::Serialize;

        #[derive(Serialize)]
        struct UnixPath<'a> {
            unix_bytes: &'a [u8],
        }

        UnixPath {
            unix_bytes: path.as_os_str().as_bytes(),
        }
        .serialize(serializer)
    }
    #[cfg(not(unix))]
    {
        Err(serde::ser::Error::custom(
            "path is not representable as UTF-8 on this platform",
        ))
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged, deny_unknown_fields)]
    enum StoredPath {
        Text(String),
        UnixBytes { unix_bytes: Vec<u8> },
    }

    match StoredPath::deserialize(deserializer)? {
        StoredPath::Text(text) => Ok(PathBuf::from(text)),
        StoredPath::UnixBytes { unix_bytes } => {
            #[cfg(unix)]
            {
                use std::ffi::OsString;
                use std::os::unix::ffi::OsStringExt;
                Ok(PathBuf::from(OsString::from_vec(unix_bytes)))
            }
            #[cfg(not(unix))]
            {
                let _ = unix_bytes;
                Err(serde::de::Error::custom(
                    "Unix path bytes cannot be interpreted on this platform",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
    #[serde(transparent)]
    struct EncodedPath(#[serde(with = "crate::core::path_serde")] PathBuf);

    #[test]
    fn utf8_paths_keep_the_existing_wire_and_hash_input() {
        for text in [
            "/cache/project/target",
            "/cache/日本語/target",
            "/cache/quotes\"and\nnewlines",
            r#"/cache/{"unix_bytes":[255]}"#,
            "/cache//project/./target/",
        ] {
            let path = PathBuf::from(text);
            let encoded = serde_json::to_vec(&EncodedPath(path.clone())).unwrap();
            assert_eq!(encoded, serde_json::to_vec(&path).unwrap());
            let restored: EncodedPath = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(restored.0.as_os_str(), path.as_os_str());
        }
    }

    #[test]
    fn malformed_native_byte_representations_are_rejected() {
        for encoded in [
            r#"{"unix_bytes":[256]}"#,
            r#"{"unix_bytes":[-1]}"#,
            r#"{"unix_bytes":[1.5]}"#,
            r#"{"unix_bytes":"/root"}"#,
            r#"{"unix_bytes":[255],"unexpected":true}"#,
            r#"{"other_bytes":[255]}"#,
            "null",
        ] {
            assert!(serde_json::from_str::<EncodedPath>(encoded).is_err());
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn foreign_unix_bytes_are_not_reinterpreted_as_native_names() {
        assert!(
            serde_json::from_str::<EncodedPath>(r#"{"unix_bytes":[47,114,255]}"#).is_err()
        );
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::ffi::OsString;
        use std::fs;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::time::{Duration, UNIX_EPOCH};

        use crate::scanner::index::{
            CandidateIndexRecord, CandidateSafetyState, IndexedEntryKind, IndexedIdentity,
            IndexedPruneDecision, ScannerCandidateIndex, ScannerIndexContext, ScannerIndexLoadStatus,
        };
        use crate::scanner::patterns::StructuralSignals;

        fn native(bytes: &[u8]) -> PathBuf {
            PathBuf::from(OsString::from_vec(bytes.to_vec()))
        }

        fn record(path: PathBuf, inode: u64) -> CandidateIndexRecord {
            CandidateIndexRecord {
                path,
                identity: IndexedIdentity {
                    device_id: 7,
                    inode,
                    kind: IndexedEntryKind::Directory,
                },
                parent_identity: None,
                parent_mtime_nanos: None,
                candidate_mtime_nanos: 200,
                candidate_ctime_nanos: Some(300),
                size_estimate_bytes: 1024,
                prune_decision: IndexedPruneDecision::CandidateOpaque,
                score: Some(0.9),
                safety_state: CandidateSafetyState::Safe,
                fail_count: 0,
                cooldown_until_nanos: None,
                event_generation: 0,
                structural_signals: StructuralSignals::default(),
            }
        }

        fn index() -> ScannerCandidateIndex {
            ScannerCandidateIndex::new(ScannerIndexContext {
                root_fingerprint: "byte-paths".to_string(),
                config_fingerprint: "config".to_string(),
            })
        }

        fn restart(index: &ScannerCandidateIndex, path: &Path) -> ScannerCandidateIndex {
            index.save_checkpoint(path).unwrap();
            let (loaded, status) =
                ScannerCandidateIndex::load_checkpoint(path, index.context().clone());
            assert_eq!(status, ScannerIndexLoadStatus::Loaded);
            assert_eq!(loaded.len(), index.len());
            loaded
        }

        #[test]
        fn native_names_never_alias_replacement_characters_or_encoding_like_text() {
            let paths = [
                native(b"/cache/project-\xff/target"),
                PathBuf::from("/cache/project-�/target"),
                PathBuf::from(r#"/cache/{"unix_bytes":[255]}/target"#),
            ];
            let encoded: Vec<_> = paths
                .iter()
                .map(|path| serde_json::to_vec(&EncodedPath(path.clone())).unwrap())
                .collect();
            assert_ne!(encoded[0], encoded[1]);
            assert_ne!(encoded[0], encoded[2]);
            for (bytes, expected) in encoded.iter().zip(&paths) {
                let restored: EncodedPath = serde_json::from_slice(bytes).unwrap();
                assert_eq!(restored.0.as_os_str().as_bytes(), expected.as_os_str().as_bytes());
            }
            assert!(serde_json::to_vec(&paths[0]).is_err());
        }

        proptest::proptest! {
            #[test]
            fn arbitrary_native_path_bytes_round_trip_without_normalizing(
                tail in proptest::collection::vec(1u8..=255, 0..128),
            ) {
                // Representation coverage, not a claim that every filesystem
                // admits every generated filename (APFS in particular does not).
                let mut bytes = b"/cache/".to_vec();
                bytes.extend(tail);
                let encoded = serde_json::to_vec(&EncodedPath(native(&bytes))).unwrap();
                let restored: EncodedPath = serde_json::from_slice(&encoded).unwrap();
                proptest::prop_assert_eq!(restored.0.as_os_str().as_bytes(), bytes.as_slice());
            }
        }

        #[test]
        fn one_native_candidate_does_not_poison_the_entire_index_checkpoint() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("index.json");
            let candidates = [
                record(PathBuf::from("/cache/plain/target"), 1),
                record(native(b"/cache/project-\xff/target"), 2),
                record(native(b"/cache/project-\xfe/target"), 3),
            ];
            let mut index = index();
            for candidate in &candidates {
                index.upsert(candidate.clone());
            }
            let loaded = restart(&index, &path);
            for candidate in &candidates {
                assert_eq!(loaded.get(candidate.identity), Some(candidate));
            }
            assert_eq!(
                loaded.ranked_records(UNIX_EPOCH, 3),
                index.ranked_records(UNIX_EPOCH, 3)
            );
            let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert!(value["records"][0]["path"].is_string());
            assert!(value["records"][1]["path"]["unix_bytes"].is_array());
        }

        #[test]
        fn native_candidate_failure_backoff_survives_restart_at_the_exact_boundary() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("index.json");
            let candidate = record(native(b"/cache/project-\xff/target"), 1);
            let mut index = index();
            index.upsert(candidate.clone());
            index.record_failure(
                candidate.identity,
                UNIX_EPOCH,
                Duration::from_secs(30),
                Duration::from_secs(120),
            );
            let loaded = restart(&index, &path);
            assert_eq!(loaded.get(candidate.identity), index.get(candidate.identity));
            assert!(loaded.ranked_records(UNIX_EPOCH + Duration::from_secs(29), 1).is_empty());
            let ready = loaded.ranked_records(UNIX_EPOCH + Duration::from_secs(30), 1);
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].path.as_os_str(), candidate.path.as_os_str());
            assert_eq!(ready[0].fail_count, 1);
            assert_eq!(ready[0].safety_state, CandidateSafetyState::Failed);
        }

        #[test]
        fn native_scope_invalidation_stays_revoked_across_checkpoint_restart() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("index.json");
            let candidate = record(native(b"/cache/project-\xff/target"), 1);
            let neighbor = record(native(b"/cache/project-\xff-other/target"), 2);
            let mut index = index();
            index.upsert(candidate.clone());
            index.upsert(neighbor.clone());
            let mut loaded = restart(&index, &path);
            assert_eq!(
                loaded.invalidate_paths([candidate.path.join("debug/deps/object.o").as_path()]),
                1
            );
            let loaded = restart(&loaded, &path);
            assert_eq!(loaded.get(candidate.identity).unwrap().score, None);
            assert_eq!(loaded.ranked_records(UNIX_EPOCH, 2), vec![neighbor]);
            assert_eq!(
                loaded.get(candidate.identity).unwrap().path.as_os_str(),
                candidate.path.as_os_str()
            );
        }

        #[test]
        fn native_path_identity_replacement_uses_the_rebuilt_lookup_after_restart() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("index.json");
            let old = record(native(b"/cache/project-\xff/target"), 1);
            let neighbor = record(native(b"/cache/project-\xfe/target"), 2);
            let mut index = index();
            index.upsert(old.clone());
            index.upsert(neighbor.clone());
            let mut loaded = restart(&index, &path);
            let mut replacement = record(old.path.clone(), 3);
            replacement.safety_state = CandidateSafetyState::Vetoed;
            loaded.upsert(replacement.clone());
            assert!(loaded.get(old.identity).is_none());
            let loaded = restart(&loaded, &path);
            assert_eq!(loaded.len(), 2);
            assert_eq!(loaded.get(replacement.identity), Some(&replacement));
            assert_eq!(loaded.ranked_records(UNIX_EPOCH, 2), vec![neighbor]);
        }

        #[test]
        fn corrupt_native_path_checkpoint_falls_back_instead_of_changing_the_name() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("index.json");
            let mut index = index();
            index.upsert(record(native(b"/cache/project-\xff/target"), 1));
            index.save_checkpoint(&path).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["records"][0]["path"]["unix_bytes"][0] = serde_json::json!(256);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let (loaded, status) =
                ScannerCandidateIndex::load_checkpoint(&path, index.context().clone());
            assert!(matches!(status, ScannerIndexLoadStatus::Corrupt(_)));
            assert!(loaded.is_empty());
        }
    }
}
