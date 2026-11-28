// SPDX-License-Identifier: MIT
//! Test that an https:// input with an invalid sha256 digest is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_https_with_invalid_digest() {
    let output = bin()
        .arg("https://example.org/x.wasm#sha256=xyz")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "https URL with invalid digest must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid sha256 digest"),
        "stderr must mention invalid sha256 digest: {stderr}"
    );
}
