//! Integration tests for the persistent compatibility lineage ledger.

use soroban_upgrade_safeguard::lineage::{
    LineageRecord, LineageStore, LiveStatus, LiveVersionPolicy,
};
use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};
use std::collections::BTreeMap;

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
