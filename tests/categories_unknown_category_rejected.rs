// SPDX-License-Identifier: MIT
//! Integration test for `categories --category` with an unknown name.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn categories_rejects_an_unknown_category() {
    let output = bin()
        .args(["categories", "--category", "Nope"])
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unknown category must exit 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown category"),
        "stderr should report the unknown category, got: {stderr}"
    );
    assert!(
        stderr.contains("Run `categories` without --category"),
        "stderr should hint at the unfiltered listing, got: {stderr}"
    );
}
