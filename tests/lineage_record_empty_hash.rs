// SPDX-License-Identifier: MIT
//! Test that a lineage record with an empty wasm_hash is rejected.

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
fn lineage_record_with_empty_wasm_hash_is_rejected() {
    let lineage_path = temp_lineage("empty-hash");
    let _ = fs::remove_file(&lineage_path);

    // Record v1 as the first version
    let record_v1 = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&lineage_path)
        .arg("--record-version")
        .arg("v1")
        .output()
        .expect("failed to record v1");
    assert_eq!(
        record_v1.status.code(),
        Some(0),
        "recording v1 must succeed"
    );

    // Read the store and blank the wasm_hash
    let store_content = fs::read_to_string(&lineage_path).expect("failed to read lineage store");
    let mut store: serde_json::Value =
        serde_json::from_str(&store_content).expect("store must be valid JSON");

    // Blank the wasm_hash field
    if let Some(versions) = store["versions"].as_array_mut() {
        if let Some(first_version) = versions.first_mut() {
            if let Some(hash_field) = first_version.get_mut("wasm_hash") {
                *hash_field = serde_json::json!("");
            }
        }
    }

    // Write the corrupted store back
    fs::write(
        &lineage_path,
        serde_json::to_string_pretty(&store).unwrap(),
    )
    .expect("failed to write corrupted store");

    // Attempt to run a comparison with the empty wasm_hash store
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
        "comparison with empty wasm_hash must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("empty wasm_hash"),
        "stderr must mention empty wasm_hash, got: {stderr}"
    );

    fs::remove_file(&lineage_path).ok();
}
