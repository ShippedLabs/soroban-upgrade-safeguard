// SPDX-License-Identifier: MIT
//! Regression test for malformed JSON passed to `lint --storage-schema`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn lint_rejects_malformed_storage_schema_json() {
    let schema = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "malformed-storage-schema-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos()
    ));
    std::fs::write(&schema, "not json {").expect("failed to write malformed schema");

    let wasm = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .arg(wasm)
        .arg("--storage-schema")
        .arg(&schema)
        .output()
        .expect("failed to run lint subcommand");

    let _ = std::fs::remove_file(schema);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "lint must exit 1 for malformed storage schema JSON. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Failed to parse storage schema"),
        "stderr must explain the storage schema parse failure. stderr:\n{stderr}"
    );
}
