//! CLI regression test for read-only lineage store listing.

use soroban_upgrade_safeguard::lineage::{LineageRecord, LineageStore, LiveStatus};
use std::collections::BTreeMap;
use std::process::Command;

#[test]
fn lists_live_and_retired_versions_without_wasm_inputs() {
    let mut store = LineageStore::default();
    for (version_id, order, status, interface_hash) in [
        ("v1.0.0", 1, LiveStatus::Retired, "interface-v1"),
        ("v2.0.0", 2, LiveStatus::Live, "interface-v2"),
    ] {
        store
            .record_version(LineageRecord {
                version_id: version_id.to_string(),
                order,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                status,
                wasm_hash: format!("wasm-{order}"),
                interface_hash: interface_hash.to_string(),
                spec_json: None,
                storage_schema: None,
                metadata: BTreeMap::new(),
            })
            .unwrap();
    }

    let path = std::env::temp_dir().join(format!(
        "safeguard-list-versions-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    store.save_to_path(&path).unwrap();
    let original = std::fs::read(&path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--lineage-store", path.to_str().unwrap(), "--list-versions"])
        .output()
        .expect("failed to run lineage listing");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "VERSION_ID\tORDER\tSTATUS\tINTERFACE_HASH\n\
         v1.0.0\t1\tRetired\tinterface-v1\n\
         v2.0.0\t2\tLive\tinterface-v2\n"
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::remove_file(path).unwrap();
}
