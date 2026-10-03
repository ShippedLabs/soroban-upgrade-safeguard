//! CLI-level coverage for `--retire-version`: marking an existing lineage
//! version as retired via the main comparison command.
//!
//! `tests/lineage_tests.rs` covers the library API
//! (`LineageStore::retire_version`) directly; these drive the compiled
//! binary, because the behavior this ticket is about — what happens when
//! the given ID doesn't exist — is a property of the CLI's handling of
//! `--retire-version` (`src/main.rs`), not of the library function itself
//! (which just returns `Ok(false)` and leaves the caller to decide what
//! that means).

use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::lineage::{LineageRecord, LineageStore, LiveStatus};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn temp_store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "safeguard-lineage-cli-{name}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// A lineage store with one live record, `KNOWN_VERSION_ID`, saved to
/// `path`. Returns the exact bytes written, so a test can later confirm
/// the file is byte-for-byte unchanged.
const KNOWN_VERSION_ID: &str = "v1.0.0";

fn write_store_with_one_record(path: &PathBuf) -> Vec<u8> {
    let mut store = LineageStore::new(Some("test-contract".to_string()), None);
    store
        .record_version(LineageRecord {
            version_id: KNOWN_VERSION_ID.to_string(),
            order: 1,
            created_at: "2026-08-25T00:00:00Z".to_string(),
            status: LiveStatus::Live,
            wasm_hash: "deadbeef".to_string(),
            interface_hash: "feedface".to_string(),
            spec_json: None,
            storage_schema: None,
            metadata: Default::default(),
        })
        .expect("failed to record version");
    store.save_to_path(path).expect("failed to save lineage store");
    std::fs::read(path).expect("failed to read back saved lineage store")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout, stderr)
}

#[test]
fn retire_version_with_an_unknown_id_is_a_clear_error() {
    let store_path = temp_store_path("unknown-id");
    let original_bytes = write_store_with_one_record(&store_path);

    let old = wasm("v1.wasm").display().to_string();
    let new = wasm("v3.wasm").display().to_string();
    let store_path_str = store_path.display().to_string();

    let (code, stdout, stderr) = run(&[
        &old,
        &new,
        "--lineage-store",
        &store_path_str,
        "--retire-version",
        "v9.9.9",
        "--quiet",
    ]);

    assert_ne!(
        code, 0,
        "retiring an unknown version id must fail, stdout: {stdout}"
    );
    assert!(
        stderr.contains("v9.9.9"),
        "error should name the unknown id, got: {stderr}"
    );
    assert!(
        stderr.contains("--retire-version"),
        "error should name the offending flag, got: {stderr}"
    );
    assert!(
        stderr.contains(KNOWN_VERSION_ID),
        "error should list the store's actual known version(s), got: {stderr}"
    );

    let bytes_after = std::fs::read(&store_path).expect("lineage store file should still exist");
    assert_eq!(
        bytes_after, original_bytes,
        "the lineage store file must be byte-for-byte unchanged after a failed retire"
    );

    let _ = std::fs::remove_file(&store_path);
}

#[test]
fn retire_version_with_a_known_id_still_succeeds() {
    let store_path = temp_store_path("known-id");
    write_store_with_one_record(&store_path);

    let old = wasm("v1.wasm").display().to_string();
    let new = wasm("v3.wasm").display().to_string();
    let store_path_str = store_path.display().to_string();

    let (code, stdout, stderr) = run(&[
        &old,
        &new,
        "--lineage-store",
        &store_path_str,
        "--retire-version",
        KNOWN_VERSION_ID,
        "--quiet",
    ]);

    assert_eq!(
        code, 0,
        "retiring a known version id must still succeed, stderr: {stderr}"
    );
    assert!(
        stdout.contains("Status:") || stdout.contains("SOROBAN"),
        "a normal report should still be produced, got: {stdout}"
    );

    let _ = std::fs::remove_file(&store_path);
}
