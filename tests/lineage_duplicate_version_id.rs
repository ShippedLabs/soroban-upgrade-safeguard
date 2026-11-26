// SPDX-License-Identifier: MIT
//! Test that duplicate lineage version ids are rejected.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_lineage(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "safeguard-lineage-test-{}-{}.json",
        name,
        std::process::id()
    ))
}

#[test]
fn duplicate_version_id_in_lineage_store_is_rejected() {
    let lineage_path = temp_lineage("duplicate-version");
    let _ = fs::remove_file(&lineage_path);

    // Record v1 as the first version
    let record_first = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&lineage_path)
        .arg("--record-version")
        .arg("v1")
        .output()
        .expect("failed to record first version");
    assert_eq!(
        record_first.status.code(),
        Some(0),
        "recording v1 must succeed"
    );

    // Read the store and manually duplicate the v1 record with a new order value
    let store_content = fs::read_to_string(&lineage_path).expect("failed to read lineage store");
    let mut store: serde_json::Value =
        serde_json::from_str(&store_content).expect("store must be valid JSON");

    // Duplicate the first version entry with order=1 (original has order=0)
    if let Some(versions) = store["versions"].as_array_mut() {
        if let Some(first_version) = versions.first().cloned() {
            let mut duplicated = first_version;
            if let Some(order_field) = duplicated.get_mut("order") {
                *order_field = serde_json::json!(1);
            }
            versions.push(duplicated);
        }
    }

    // Write the corrupted store back
    fs::write(
        &lineage_path,
        serde_json::to_string_pretty(&store).unwrap(),
    )
    .expect("failed to write corrupted store");

    // Attempt to run a comparison with the duplicate version_id store
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&lineage_path)
        .output()
        .expect("failed to run comparison");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "comparison with duplicate version_id must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("Duplicate version_id"),
        "stderr must mention Duplicate version_id, got: {stderr}"
    );

    fs::remove_file(&lineage_path).ok();
}
