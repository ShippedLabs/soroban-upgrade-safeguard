// SPDX-License-Identifier: MIT
//! Integration test verifying that --min-severity warning hides info findings
//! in text output while they remain visible without the flag.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
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
fn min_severity_warning_hides_info_findings() {
    // Run with --min-severity warning to filter out info findings
    let output_filtered = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--min-severity", "warning", "--no-color", "--no-timestamp"])
        .output()
        .expect("failed to run binary with --min-severity warning");

    let stdout_filtered =
        String::from_utf8(output_filtered.stdout).expect("stdout was not valid UTF-8");

    // Info findings like "Data segments changed" should be absent
    assert!(
        !stdout_filtered.contains("Data segments changed"),
        "info finding 'Data segments changed' should be hidden with --min-severity warning, got:\n{stdout_filtered}"
    );

    // Run without the flag to verify the finding is normally present
    let output_default = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--no-color", "--no-timestamp"])
        .output()
        .expect("failed to run binary without --min-severity");

    let stdout_default =
        String::from_utf8(output_default.stdout).expect("stdout was not valid UTF-8");

    // The info finding should be present without filtering
    assert!(
        stdout_default.contains("Data segments changed"),
        "info finding 'Data segments changed' should be present without --min-severity, got:\n{stdout_default}"
    );
}
