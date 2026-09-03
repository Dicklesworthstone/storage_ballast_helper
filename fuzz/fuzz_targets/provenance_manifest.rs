#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| storage_ballast_helper::fuzzing::provenance_manifest(data));
