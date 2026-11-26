// SPDX-License-Identifier: MIT
//! Test that passing a directory as `--lineage-store` is reported.
//!
//! When a user accidentally points `--lineage-store` to a directory instead of
//! a file, the tool must exit 1 with a clear error stating that reading the
//! lineage store failed.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn lineage_store_directory_is_reported() {
    let store_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "lineage-store-directory-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&store_dir).expect("failed to create temporary store directory");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--lineage-store")
        .arg(&store_dir)
        .output()
        .expect("failed to run binary");

    let _ = fs::remove_dir_all(&store_dir);

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "passing a directory as --lineage-store must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("Failed to read lineage store"),
        "stderr must explain the lineage store read failure, got: {stderr}"
    );
    assert!(
        stderr.contains(&store_dir.display().to_string()),
        "stderr must name the offending directory path, got: {stderr}"
    );
}
