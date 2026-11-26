// SPDX-License-Identifier: MIT
//! Test that a corrupt `--lineage-store` JSON file is reported.
//!
//! A lineage store the loader cannot parse must stop the run with a message
//! that names the file and says the store is corrupt, instead of being
//! silently ignored or surfacing as an unrelated failure.

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

/// A temporary path for a lineage store. The `.json` extension is what makes
/// the loader read the file as JSON rather than TOML.
fn temp_store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "safeguard-lineage-corrupt-{name}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn corrupt_lineage_store_json_is_reported() {
    let store_path = temp_store_path("bad-json");
    fs::write(&store_path, "not json {").expect("failed to write the corrupt store");

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
        "a corrupt lineage store must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("corrupt or not valid JSON"),
        "error should say the store is corrupt, got: {stderr}"
    );
    assert!(
        stderr.contains(&store_path.display().to_string()),
        "error should name the offending file, got: {stderr}"
    );

    let _ = fs::remove_file(&store_path);
}
