// SPDX-License-Identifier: MIT
//! Integration test verifying `--per-contract-output-dir` creates missing parent
//! and target directories when running a directory comparison.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn per_contract_output_dir_creates_missing_nested_directory() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "per-contract-dir-created-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);

    let old_dir = root.join("old");
    let new_dir = root.join("new");
    let out_dir = root.join("out").join("sub");

    fs::create_dir_all(&old_dir).expect("create old_dir");
    fs::create_dir_all(&new_dir).expect("create new_dir");
    fs::copy(wasm("v1.wasm"), old_dir.join("x.wasm")).expect("copy x old");
    fs::copy(wasm("v3.wasm"), new_dir.join("x.wasm")).expect("copy x new");
    fs::copy(wasm("v1.wasm"), old_dir.join("y.wasm")).expect("copy y old");
    fs::copy(wasm("v3.wasm"), new_dir.join("y.wasm")).expect("copy y new");

    assert!(
        !root.join("out").exists(),
        "parent output directory must not exist before running safeguard"
    );
    assert!(
        !out_dir.exists(),
        "target output directory must not exist before running safeguard"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--old-dir",
            old_dir.to_str().unwrap(),
            "--new-dir",
            new_dir.to_str().unwrap(),
            "--per-contract-output-dir",
            out_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run soroban-upgrade-safeguard");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0 for compatible v1->v3 pairs, got {:?}: {stderr}",
        output.status.code()
    );

    for contract in ["x.json", "y.json"] {
        let report_path = out_dir.join(contract);
        assert!(
            report_path.is_file(),
            "expected per-contract output file at {}",
            report_path.display()
        );
        let raw = fs::read_to_string(&report_path).expect("read per-contract JSON report");
        let parsed: Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
            panic!("invalid JSON in {}: {e}\n{raw}", report_path.display())
        });
        assert!(parsed.is_object(), "report must be a JSON object");
    }

    let _ = fs::remove_dir_all(&root);
}
