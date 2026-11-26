// SPDX-License-Identifier: MIT
//! Test that --record-version rejects an empty version id.
//!
//! Running `--lineage-store store.json --record-version ""` must exit 1
//! with an error stating "Cannot record version with empty version_id",
//! and no store file should be written.

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
        "safeguard-record-version-empty-{name}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn empty_record_version_is_rejected() {
    let store_path = temp_store_path("empty");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("")
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "empty version_id must exit 1, stderr: {stderr}"
    );

    assert!(
        stderr.contains("empty version_id"),
        "error must mention empty version_id, got: {stderr}"
    );

    assert!(
        !store_path.exists(),
        "no store file should be written when version_id is empty"
    );
}

#[test]
fn whitespace_only_record_version_is_rejected() {
    let store_path = temp_store_path("whitespace");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("   ")
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "whitespace-only version_id must exit 1, stderr: {stderr}"
    );

    assert!(
        stderr.contains("empty version_id"),
        "error must mention empty version_id (after trimming), got: {stderr}"
    );

    assert!(
        !store_path.exists(),
        "no store file should be written when version_id is whitespace-only"
    );
}

#[test]
fn valid_record_version_is_accepted() {
    let store_path = temp_store_path("valid");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("v1.0.0")
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "valid version_id must succeed, stderr: {stderr}"
    );

    assert!(
        store_path.exists(),
        "store file should be written when version_id is valid"
    );

    // Verify the store contains the recorded version
    let store_contents = fs::read_to_string(&store_path).expect("failed to read store");
    assert!(
        store_contents.contains("v1.0.0"),
        "store should contain the recorded version_id"
    );

    let _ = fs::remove_file(&store_path);
}

#[test]
fn empty_record_version_prevents_store_update() {
    let store_path = temp_store_path("no-update");

    // First, create a valid store with a recorded version
    let first_output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("v1.0.0")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        first_output.status.code(),
        Some(0),
        "first recording must succeed"
    );
    assert!(store_path.exists(), "store should exist after first record");

    let original_contents = fs::read_to_string(&store_path).expect("failed to read store");

    // Now try to record an empty version
    let second_output = bin()
        .arg(wasm("v2.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&store_path)
        .arg("--record-version")
        .arg("")
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&second_output.stderr);

    assert_eq!(
        second_output.status.code(),
        Some(1),
        "empty version_id must exit 1, stderr: {stderr}"
    );

    // Verify the store file was not modified
    let updated_contents = fs::read_to_string(&store_path).expect("failed to read store");
    assert_eq!(
        original_contents, updated_contents,
        "store file should not be modified when empty version_id is rejected"
    );

    let _ = fs::remove_file(&store_path);
}
