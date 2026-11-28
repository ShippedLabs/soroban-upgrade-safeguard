// SPDX-License-Identifier: MIT
//! Test that an https:// input with an unsupported digest fragment is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_https_input_with_unsupported_digest() {
    let output = bin()
        .arg("https://example.org/x.wasm#md5=abc")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "https URL with unsupported digest must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported digest fragment"),
        "stderr must mention unsupported digest fragment: {stderr}"
    );
}
