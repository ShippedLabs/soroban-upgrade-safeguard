// SPDX-License-Identifier: MIT
//! Test that an https:// input without a digest fragment is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_https_input_without_digest() {
    let output = bin()
        .arg("https://example.org/x.wasm")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "https URL without digest must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing the required '#sha256=<hex>'"),
        "stderr must mention missing digest fragment: {stderr}"
    );
}
