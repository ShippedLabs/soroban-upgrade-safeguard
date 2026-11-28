// SPDX-License-Identifier: MIT
//! Integration test that verifies duplicate --output destinations are rejected.

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

#[test]
fn duplicate_output_destinations_are_rejected() {
    let temp_dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-duplicate-output-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).expect("failed to create temp directory");

    let output_file = temp_dir.join("r.json");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--output")
        .arg("json:".to_owned() + output_file.to_str().unwrap())
        .arg("--output")
        .arg("markdown:".to_owned() + output_file.to_str().unwrap())
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "command must exit with code 1 when output destinations are duplicated"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Duplicate output destination"),
        "stderr must contain duplicate destination error message, got: {stderr}"
    );

    assert!(
        !output_file.exists(),
        "r.json must not be created when duplicate destinations are rejected"
    );

    // Clean up temporary directory
    let _ = fs::remove_dir_all(&temp_dir);
}
