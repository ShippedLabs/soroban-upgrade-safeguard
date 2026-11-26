// SPDX-License-Identifier: MIT
//! Test that `--interface-lockfile` rejects multiple candidate WASM paths.

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
fn interface_lockfile_rejects_two_wasm_paths() {
    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");
    let lockfile = temp_lockfile("two_wasm");
    let _ = fs::remove_file(&lockfile);

    // Create a dummy lockfile so the flag points to an existing file
    let gen = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&lockfile)
        .output()
        .expect("failed to generate lockfile");
    assert_eq!(gen.status.code(), Some(0));

    // Run the binary with two WASM paths and --interface-lockfile
    let output = bin()
        .arg(&v1)
        .arg(&v2)
        .arg("--interface-lockfile")
        .arg(&lockfile)
        .output()
        .expect("failed to execute binary with two wasm paths and --interface-lockfile");

    // Assert exit code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 when passing two wasm paths with --interface-lockfile"
    );

    // Assert stderr contains "requires exactly one candidate WASM path"
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    assert!(
        stderr.contains("requires exactly one candidate WASM path"),
        "expected stderr to contain 'requires exactly one candidate WASM path', got: {stderr}"
    );

    let _ = fs::remove_file(&lockfile);
}
