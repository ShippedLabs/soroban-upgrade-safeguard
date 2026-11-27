// SPDX-License-Identifier: MIT
//! Test that an oci:// reference without a digest or tag is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_oci_without_digest_or_tag() {
    let output = bin()
        .arg("oci://registry.example.com/repo")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "oci reference without digest or tag must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must pin a digest"),
        "stderr must mention must pin a digest: {stderr}"
    );
}
