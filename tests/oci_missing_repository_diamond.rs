// SPDX-License-Identifier: MIT
//! Test that an oci:// reference without a repository is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_oci_without_repository() {
    let output = bin()
        .arg("oci://registry.example.com")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "oci reference without repository must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing a repository path"),
        "stderr must mention missing repository path: {stderr}"
    );
}
