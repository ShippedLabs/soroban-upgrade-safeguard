// SPDX-License-Identifier: MIT
//! Test that a lineage store with an unsupported schema version is rejected.
//!
//! A store whose `schema_version` is 99 must fail with exit code 1 and an
//! error message stating "Unsupported lineage store schema version 99 (expected 1)".

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

fn temp_store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "safeguard-lineage-unsupported-schema-{name}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let store_path = temp_store_path("schema-99");

    // First, record a version to create a valid store
    let record_output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("v1.0.0")
        .output()
        .expect("failed to record version");

    assert_eq!(
        record_output.status.code(),
        Some(0),
        "recording a version must succeed, stderr: {}",
        String::from_utf8_lossy(&record_output.stderr)
    );

    // Read the store, change schema_version to 99, and write it back
    let store_contents = fs::read_to_string(&store_path).expect("failed to read store");
    let mut store: serde_json::Value =
        serde_json::from_str(&store_contents).expect("store should be valid JSON");

    store["schema_version"] = serde_json::json!(99);

    fs::write(&store_path, serde_json::to_string_pretty(&store).unwrap())
        .expect("failed to write modified store");

    // Now try to run a comparison with the modified store
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "unsupported schema version must exit 1, stderr: {stderr}"
    );

    assert!(
        stderr.contains("Unsupported lineage store schema version"),
        "error should mention unsupported schema version, got: {stderr}"
    );

    assert!(
        stderr.contains("99"),
        "error should mention the actual schema version 99, got: {stderr}"
    );

    assert!(
        stderr.contains("failed integrity check"),
        "error should mention failed integrity check, got: {stderr}"
    );

    let _ = fs::remove_file(&store_path);
}
