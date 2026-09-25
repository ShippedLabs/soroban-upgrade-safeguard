//! Integration regression test for CLI `--version` output.
//!
//! Verifies that running the binary with `--version` exits with code 0,
//! outputs the exact Cargo package version without requiring WASM inputs,
//! and does not emit extraneous progress text or errors.

use std::process::Command;

#[test]
fn version_flag_exits_successfully_and_matches_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--version")
        .output()
        .expect("failed to run binary with --version");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--version must exit with status code 0 without requiring WASM inputs"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    let expected_version = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(expected_version),
        "stdout must contain the exact Cargo package version ({expected_version}). Output:\n{stdout}"
    );

    assert!(
        stdout.contains("soroban-upgrade-safeguard"),
        "stdout must contain the binary name. Output:\n{stdout}"
    );

    assert!(
        !stdout.contains("Analyzing") && !stdout.contains("Processing"),
        "stdout must not emit analysis progress text. Output:\n{stdout}"
    );

    assert!(
        stderr.trim().is_empty(),
        "stderr must be empty when querying version. Got:\n{stderr}"
    );
}
