//! Integration regression test for CLI `--version` output.
//!
//! The executable derives its reported version from Cargo package metadata
//! (`#[command(version)]` on the top-level `clap::Parser`, which defaults to
//! `CARGO_PKG_VERSION`) rather than a hand-maintained string. This test pins
//! that behavior so a refactor of the CLI's `#[command(...)]` attributes
//! cannot silently drop or hardcode the version without a test failure.

use std::process::Command;

/// The crate version baked in at compile time by Cargo, independent of
/// anything `clap` does with it — the same value `Cargo.toml`'s `version`
/// field resolves to.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn version_flag_reports_the_crate_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--version")
        .output()
        .expect("failed to run binary with --version");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--version must exit with status code 0 without loading files"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(
        stdout.contains(CRATE_VERSION),
        "stdout must contain the crate version '{CRATE_VERSION}'. Output:\n{stdout}"
    );
    assert!(
        stdout.contains("soroban-upgrade-safeguard"),
        "stdout must contain the program name. Output:\n{stdout}"
    );

    // stderr should stay empty: --version is a well-formed, successful request,
    // not a usage error.
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    assert!(
        stderr.is_empty(),
        "stderr must be empty for --version. Output:\n{stderr}"
    );
}

#[test]
fn short_version_flag_matches_long_form() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("-V")
        .output()
        .expect("failed to run binary with -V");

    assert_eq!(
        output.status.code(),
        Some(0),
        "-V must exit with status code 0"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.contains(CRATE_VERSION),
        "stdout must contain the crate version '{CRATE_VERSION}'. Output:\n{stdout}"
    );
}
