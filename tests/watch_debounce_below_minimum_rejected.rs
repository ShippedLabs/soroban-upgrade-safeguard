// SPDX-License-Identifier: MIT
//! Integration test for `--watch-debounce-ms` below the documented minimum.
//!
//! The debounce window is bounded so a burst of filesystem events for a
//! single logical change gets coalesced instead of each triggering a
//! separate re-run; a value below the minimum must be rejected by argument
//! parsing, before any comparison runs.

use std::process::Command;

#[test]
fn watch_debounce_ms_below_minimum_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--watch-debounce-ms", "9"])
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a --watch-debounce-ms value below the minimum must not succeed"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("10ms"),
        "error must mention the documented minimum (10ms), got: {stderr}"
    );
    assert!(
        stderr.contains("got 9ms"),
        "error must echo back the offending value, got: {stderr}"
    );
}
