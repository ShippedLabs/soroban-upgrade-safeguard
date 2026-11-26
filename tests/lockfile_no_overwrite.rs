// SPDX-License-Identifier: MIT
//! Test that `lockfile` refuses to replace an existing lockfile without `--force`.

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

fn temp_lockfile(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}.json",
        std::process::id()
    ))
}

#[test]
fn lockfile_refuses_to_replace_existing_lockfile() {
    let output_path = temp_lockfile("refuse_overwrite");
    let _ = fs::remove_file(&output_path);

    let v1 = wasm("v1.wasm");

    // 1. Create a lockfile with `lockfile tests/wasm/v1.wasm --output` and assert exit code 0
    let first = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to generate initial lockfile");

    assert_eq!(
        first.status.code(),
        Some(0),
        "initial lockfile generation should succeed"
    );

    let initial_content =
        fs::read_to_string(&output_path).expect("failed to read initial lockfile content");

    // 2. Run the same command again without --force
    let second = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to run lockfile overwrite attempt");

    // Assert exit code 1
    assert_eq!(
        second.status.code(),
        Some(1),
        "expected exit code 1 when attempting to overwrite lockfile without --force"
    );

    // Assert stderr contains "already exists" and "--force"
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected stderr to contain 'already exists', got: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "expected stderr to contain '--force', got: {stderr}"
    );

    // 3. Assert the file content is unchanged
    let current_content =
        fs::read_to_string(&output_path).expect("failed to read lockfile content after refusal");
    assert_eq!(
        current_content, initial_content,
        "lockfile content should be unchanged"
    );

    let _ = fs::remove_file(&output_path);
}
