// SPDX-License-Identifier: MIT
//! Integration test for an unknown `--format` value.
//!
//! `--format` accepts a fixed set of names (text, json, markdown,
//! github-actions). An unknown value must be rejected with the accepted
//! names listed, which is how a user discovers the valid options.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn unknown_format_value_is_rejected_with_valid_formats_listed() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "xml"])
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "an unknown --format value must not succeed"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");

    for valid in ["text", "json", "markdown", "github-actions"] {
        assert!(
            stderr.contains(valid),
            "error should list '{valid}' as an accepted format, got: {stderr}"
        );
    }
}
