// SPDX-License-Identifier: MIT
//! Regression test for passing a directory to `lint --storage-schema`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn lint_rejects_directory_as_storage_schema() {
    let schema_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "storage-schema-directory-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&schema_dir).expect("failed to create temporary schema directory");

    let wasm = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .arg(wasm)
        .arg("--storage-schema")
        .arg(&schema_dir)
        .output()
        .expect("failed to run lint subcommand");

    let _ = std::fs::remove_dir(&schema_dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "lint must exit 1 when the storage schema is a directory. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Failed to read storage schema"),
        "stderr must explain the storage schema read failure. stderr:\n{stderr}"
    );
}
