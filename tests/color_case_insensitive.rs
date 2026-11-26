// SPDX-License-Identifier: MIT

//! `--color` value case-insensitivity (#775).
//!
//! `--format` already accepts values in any case (`--format Json`), but
//! `--color` used to reject `ALWAYS`. Both are fixed enumerations, so a value
//! sourced from a CI variable should not behave differently between them.
//! Unknown values must still be rejected, with the accepted spellings listed.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Compares a fixture against itself: a clean run, so the only thing under test
/// is whether the `--color` value was accepted.
fn compare(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(args)
        .output()
        .expect("failed to run binary")
}

#[test]
fn color_accepts_upper_and_mixed_case_values() {
    for value in ["ALWAYS", "NeVer", "Auto"] {
        let output = compare(&["--color", value]);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stderr.contains("invalid value"),
            "`--color {value}` must be accepted, not rejected as invalid. stderr:\n{stderr}"
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "`--color {value}` must run the comparison normally. stderr:\n{stderr}"
        );
    }
}

#[test]
fn unknown_color_value_is_still_rejected_with_the_valid_values_listed() {
    let output = compare(&["--color", "maybe"]);
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown --color value is a usage error (exit 2).\n---stderr---\n{stderr}"
    );

    for valid in ["auto", "always", "never"] {
        assert!(
            stderr.contains(valid),
            "the error must list '{valid}' as an accepted value.\n---stderr---\n{stderr}"
        );
    }
}
