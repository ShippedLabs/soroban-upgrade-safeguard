//! Integration tests for the persistent compatibility lineage ledger.

use soroban_upgrade_safeguard::lineage::{
    LineageRecord, LineageStore, LiveStatus, LiveVersionPolicy,
};
use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn wasm_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name);
    std::fs::read(path).expect("failed to read fixture WASM")
}

/// Serialize `wasm`'s extracted spec, suitable for a [`LineageRecord`]'s
/// `spec_json` field.
fn extracted_spec_json(source: &str, wasm: &[u8]) -> String {
    let metadata = soroban_upgrade_safeguard::parser::extract_metadata(wasm)
        .expect("failed to extract metadata from fixture WASM");
    let spec = soroban_upgrade_safeguard::spec::ContractSpec::from_entries(&metadata.spec);
    let extracted = soroban_upgrade_safeguard::spec_json::ExtractedSpec::new(source, &metadata, &spec);
    serde_json::to_string(&extracted).expect("failed to serialize extracted spec")
}

#[test]
fn test_lineage_store_persistence_json_and_toml() {
    let mut store = LineageStore::new(Some("test-contract".to_string()), Some("C123".to_string()));
    store.policy.max_live_versions = Some(5);

    let rec1 = LineageRecord {
        version_id: "v1.0.0".to_string(),
        order: 1,
        created_at: "2026-08-25T00:00:00Z".to_string(),
        status: LiveStatus::Live,
        wasm_hash: "hash_v1".to_string(),
        interface_hash: "iface_v1".to_string(),
        spec_json: None,
        storage_schema: None,
        metadata: BTreeMap::new(),
    };
    store.record_version(rec1).unwrap();

    let rec2 = LineageRecord {
        version_id: "v1.1.0".to_string(),
        order: 2,
        created_at: "2026-08-25T01:00:00Z".to_string(),
        status: LiveStatus::Live,
        wasm_hash: "hash_v2".to_string(),
        interface_hash: "iface_v2".to_string(),
        spec_json: None,
        storage_schema: None,
        metadata: BTreeMap::new(),
    };
    store.record_version(rec2).unwrap();

    // Test JSON save and load
    let json_path = std::env::temp_dir().join(format!(
        "test_lineage_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    store.save_to_path(&json_path).unwrap();

    let loaded_json = LineageStore::load_from_path(&json_path).unwrap();
    assert_eq!(loaded_json.contract_id, Some("C123".to_string()));
    assert_eq!(loaded_json.contract_name, Some("test-contract".to_string()));
    assert_eq!(loaded_json.records.len(), 2);
    assert_eq!(loaded_json.records[0].version_id, "v1.0.0");
    assert_eq!(loaded_json.records[1].version_id, "v1.1.0");

    // Test TOML save and load
    let toml_path = std::env::temp_dir().join(format!(
        "test_lineage_{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    store.save_to_path(&toml_path).unwrap();

    let loaded_toml = LineageStore::load_from_path(&toml_path).unwrap();
    assert_eq!(loaded_toml.contract_name, Some("test-contract".to_string()));
    assert_eq!(loaded_toml.records.len(), 2);

    let _ = std::fs::remove_file(json_path);
    let _ = std::fs::remove_file(toml_path);
}

#[test]
fn test_live_version_policy_retire_and_max_live() {
    let mut store = LineageStore {
        policy: LiveVersionPolicy {
            max_live_versions: Some(2),
            retire_before_version: None,
            allow_retired_data: false,
        },
        ..LineageStore::default()
    };

    for i in 1..=4 {
        let rec = LineageRecord {
            version_id: format!("v{}", i),
            order: i,
            created_at: format!("2026-08-25T0{}:00:00Z", i),
            status: LiveStatus::Live,
            wasm_hash: format!("hash_{}", i),
            interface_hash: format!("iface_{}", i),
            spec_json: None,
            storage_schema: None,
            metadata: BTreeMap::new(),
        };
        store.record_version(rec).unwrap();
    }

    let live = store.live_records();
    assert_eq!(live.len(), 2);
    assert_eq!(live[0].version_id, "v3");
    assert_eq!(live[1].version_id, "v4");

    // Explicit retire of v3
    store.retire_version("v3").unwrap();
    let live_after_retire = store.live_records();
    assert_eq!(live_after_retire.len(), 2);
    assert_eq!(live_after_retire[0].version_id, "v2");
    assert_eq!(live_after_retire[1].version_id, "v4");

    // Policy-based retirement cutoff before v4
    store.policy.retire_before_version = Some("v4".to_string());
    let live_with_cutoff = store.live_records();
    assert_eq!(live_with_cutoff.len(), 1);
    assert_eq!(live_with_cutoff[0].version_id, "v4");
}

#[test]
fn test_lineage_store_option_in_compare_options() {
    let mut store = LineageStore::default();
    let rec = LineageRecord {
        version_id: "v1".to_string(),
        order: 1,
        created_at: "2026-08-25T00:00:00Z".to_string(),
        status: LiveStatus::Live,
        wasm_hash: "hash_1".to_string(),
        interface_hash: "iface_1".to_string(),
        spec_json: None,
        storage_schema: None,
        metadata: BTreeMap::new(),
    };
    store.record_version(rec).unwrap();

    let wasm_empty = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let options = CompareOptions {
        suppressions: None,
        explain: false,
        strict: false,
        storage_schemas: None,
        lineage_store: Some(&store),
        contract: None,
        complexity_budget: None,
    };

    let report = compare_wasm_bytes_with_options(&wasm_empty, &wasm_empty, &options).unwrap();
    assert!(report.is_safe());
}

// ---------------------------------------------------------------------------
// --max-live-versions 0
// ---------------------------------------------------------------------------
//
// `--max-live-versions 0` validates the candidate against *zero* historical
// versions (see `LineageStore::live_records`): a real, defined outcome, not
// a crash or a hang, but one that's easy to mistake for "every historical
// version was checked and found compatible" unless it's surfaced somewhere.
// These confirm it's surfaced (`SafetyReport::lineage_versions_checked`) and
// show the concrete risk: a genuinely incompatible historical version is
// silently skipped rather than caught.

/// A store with one live record holding `v1.wasm`'s spec — structurally
/// incompatible with a `v2.wasm` candidate in exactly the direction this
/// session's other tests already rely on (3 Critical findings; see
/// `tests/suppression.rs`'s module doc for `v1 -> v2`). Historical-vs-
/// candidate order matters for a structural diff, so the record is built
/// from `v1` specifically to land on that well-established relationship
/// once compared against a `v2` candidate.
fn store_with_one_incompatible_historical_version() -> LineageStore {
    let v1_bytes = wasm_fixture("v1.wasm");
    let mut store = LineageStore::default();
    store
        .record_version(LineageRecord {
            version_id: "v1.0.0".to_string(),
            order: 1,
            created_at: "2026-08-25T00:00:00Z".to_string(),
            status: LiveStatus::Live,
            wasm_hash: "hash_v1".to_string(),
            interface_hash: "iface_v1".to_string(),
            spec_json: Some(extracted_spec_json("v1.wasm", &v1_bytes)),
            storage_schema: None,
            metadata: BTreeMap::new(),
        })
        .unwrap();
    store
}

#[test]
fn max_live_versions_zero_checks_nothing_and_passes_vacuously() {
    // Comparing v2 against itself keeps the *primary* old/new diff trivial
    // (always safe), isolating lineage validation as the only thing that
    // could fail this run. The candidate spec lineage validation actually
    // uses is extracted from `new_wasm` (the second argument) -- v2 here --
    // which is what the stored v1.0.0 record is incompatible with.
    let v2_bytes = wasm_fixture("v2.wasm");

    let mut store = store_with_one_incompatible_historical_version();
    store.policy.max_live_versions = Some(0);

    let options = CompareOptions {
        suppressions: None,
        explain: false,
        strict: false,
        storage_schemas: None,
        lineage_store: Some(&store),
        contract: None,
        complexity_budget: None,
    };

    let report = compare_wasm_bytes_with_options(&v2_bytes, &v2_bytes, &options)
        .expect("comparison should succeed");

    assert_eq!(
        report.lineage_versions_checked(),
        Some(0),
        "the report must say explicitly that zero historical versions were checked"
    );
    assert!(
        report.is_safe(),
        "with nothing checked, the run passes vacuously -- this is the defined outcome, \
         not a crash or a hang"
    );
}

#[test]
fn without_the_cap_the_same_incompatible_historical_version_is_caught() {
    // Same store, same candidate, no cap: proves the "vacuous pass" above
    // is actually due to the cap, by showing the historical incompatibility
    // *is* caught the moment it's actually checked.
    let v2_bytes = wasm_fixture("v2.wasm");

    let store = store_with_one_incompatible_historical_version();
    assert_eq!(store.policy.max_live_versions, None);

    let options = CompareOptions {
        suppressions: None,
        explain: false,
        strict: false,
        storage_schemas: None,
        lineage_store: Some(&store),
        contract: None,
        complexity_budget: None,
    };

    let report = compare_wasm_bytes_with_options(&v2_bytes, &v2_bytes, &options)
        .expect("comparison should succeed");

    assert_eq!(
        report.lineage_versions_checked(),
        Some(1),
        "without a cap, the one live historical version must actually be checked"
    );
    assert!(
        !report.is_safe(),
        "the stored v1.0.0 spec is structurally incompatible with the v2 candidate; \
         checking it must fail the run"
    );
}
