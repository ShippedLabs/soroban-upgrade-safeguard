// SPDX-License-Identifier: MIT

//! `lint --max-walk-depth <non-numeric>` acceptance test (#773).
//!
//! The flag takes a `usize`. A value that is not a number must be rejected by
//! argument parsing (exit code 2, the clap usage-error status) with an error
//! that names both the flag and the offending value, so a typo in a CI
//! variable is diagnosable without reading the source.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn non_numeric_max_walk_depth_is_rejected() {
    let path = wasm("v1.wasm");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .arg(&path)
        .args(["--max-walk-depth", "abc"])
        .output()
        .expect("failed to run lint");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a non-numeric value is a usage error (exit 2).\n---stderr---\n{stderr}"
    );

    assert!(
        stderr.contains("--max-walk-depth"),
        "the error must name the rejected flag.\n---stderr---\n{stderr}"
    );

    assert!(
        stderr.contains("abc"),
        "the error must quote the offending value.\n---stderr---\n{stderr}"
    );
}
