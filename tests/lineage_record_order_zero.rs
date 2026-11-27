// SPDX-License-Identifier: MIT
//! Test that a lineage record with order = 0 is rejected.

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

fn temp_lineage_store(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "safeguard-lineage-{}-{}.json",
        name,
        std::process::id()
    ))
}

#[test]
fn lineage_record_with_order_zero_is_rejected() {
    let store_path = temp_lineage_store("order-zero");
    
    // Create a lineage store with a record that has order = 0
    let store_content = r#"{
  "schema_version": 1,
  "contract_name": "test-contract",
  "records": [
    {
      "version_id": "v1",
      "order": 0,
      "created_at": "2024-01-01T00:00:00Z",
      "status": "live",
      "wasm_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "interface_hash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "policy": {}
}"#;
    
    fs::write(&store_path, store_content).expect("failed to write lineage store");
    
    // Run a comparison with this lineage store
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .output()
        .expect("failed to run binary");
    
    // Should exit with code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "comparison with a lineage record having order 0 must fail"
    );
    
    // Error message should contain "invalid order 0"
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid order 0"),
        "error should mention 'invalid order 0', got: {stderr}"
    );
    
    // Clean up
    let _ = fs::remove_file(&store_path);
}

#[test]
fn lineage_record_with_valid_order_is_accepted() {
    let store_path = temp_lineage_store("order-valid");
    
    // Create a lineage store with a record that has order = 1 (valid)
    let store_content = r#"{
  "schema_version": 1,
  "contract_name": "test-contract",
  "records": [
    {
      "version_id": "v1",
      "order": 1,
      "created_at": "2024-01-01T00:00:00Z",
      "status": "live",
      "wasm_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "interface_hash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "policy": {}
}"#;
    
    fs::write(&store_path, store_content).expect("failed to write lineage store");
    
    // Run a comparison with this lineage store
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run binary");
    
    // Should not complain about invalid order
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid order 0"),
        "should not complain about order when it is >= 1, got: {stderr}"
    );
    
    // Clean up
    let _ = fs::remove_file(&store_path);
}
