// SPDX-License-Identifier: MIT
//! Test that `lockfile --output <path> --force` updates an existing lockfile.

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

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_lockfile(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}.json",
        std::process::id()
    ))
}

fn get_hash_only(wasm_file: &str) -> String {
    let output = bin()
        .arg("extract")
        .arg(wasm(wasm_file))
        .arg("--hash-only")
        .output()
        .expect("failed to run extract --hash-only");
    assert_eq!(
        output.status.code(),
        Some(0),
        "extract --hash-only must succeed"
    );
    String::from_utf8(output.stdout)
        .expect("stdout was not valid UTF-8")
        .trim()
        .to_string()
}

#[test]
fn lockfile_force_updates_existing_lockfile() {
    let lockfile_path = temp_lockfile("force_update");
    let _ = fs::remove_file(&lockfile_path);

    let v1_hash = get_hash_only("v1.wasm");
    let v2_hash = get_hash_only("v2.wasm");
    assert_ne!(
        v1_hash, v2_hash,
        "v1.wasm and v2.wasm must have distinct interface hashes"
    );

    // 1. Write initial lockfile for tests/wasm/v1.wasm
    let first = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&lockfile_path)
        .output()
        .expect("failed to run lockfile on v1.wasm");
    assert_eq!(first.status.code(), Some(0));

    let first_contents = fs::read_to_string(&lockfile_path).expect("lockfile should exist");
    let first_json: Value =
        serde_json::from_str(&first_contents).expect("lockfile should be valid JSON");
    assert_eq!(
        first_json["interface_hash"], v1_hash,
        "initial lockfile must contain v1 interface hash"
    );

    // 2. Run lockfile tests/wasm/v2.wasm --output <path> --force
    let second = bin()
        .arg("lockfile")
        .arg(wasm("v2.wasm"))
        .arg("--output")
        .arg(&lockfile_path)
        .arg("--force")
        .output()
        .expect("failed to run lockfile on v2.wasm with --force");

    // Assert exit code 0
    assert_eq!(
        second.status.code(),
        Some(0),
        "lockfile --force must exit with status code 0"
    );

    // Assert stdout starts with "Updated"
    let stdout = String::from_utf8(second.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.starts_with("Updated"),
        "expected stdout to start with 'Updated', got: {stdout}"
    );

    // Assert the file now contains the interface hash of v2.wasm
    let second_contents =
        fs::read_to_string(&lockfile_path).expect("lockfile should exist after force update");
    let second_json: Value =
        serde_json::from_str(&second_contents).expect("updated lockfile should be valid JSON");
    assert_eq!(
        second_json["interface_hash"], v2_hash,
        "lockfile must now contain v2 interface hash"
    );

    let _ = fs::remove_file(&lockfile_path);
}
