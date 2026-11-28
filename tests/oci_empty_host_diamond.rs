// SPDX-License-Identifier: MIT
//! Test that an oci:// reference with an empty registry host is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_oci_with_empty_host() {
    let output = bin()
        .arg("oci:///repo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "oci reference with empty host must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("empty registry host"),
        "stderr must mention empty registry host: {stderr}"
    );
}
