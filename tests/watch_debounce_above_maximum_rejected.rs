// SPDX-License-Identifier: MIT
//! Integration test for `--watch-debounce-ms` above the documented maximum.
//!
//! The debounce window is bounded so watch mode stays responsive to a
//! genuine single-file edit; a value above the maximum must be rejected by
//! argument parsing, before any comparison runs.

use std::process::Command;

#[test]
fn watch_debounce_ms_above_maximum_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--watch-debounce-ms", "60001"])
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a --watch-debounce-ms value above the maximum must not succeed"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("60000"),
        "error must mention the documented maximum (60000ms), got: {stderr}"
    );
    assert!(
        stderr.contains("60001"),
        "error must echo back the offending value, got: {stderr}"
    );
}
