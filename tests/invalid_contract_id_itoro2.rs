// SPDX-License-Identifier: MIT
//! Test that an invalid contract ID is rejected.

use std::process::Command;
use std::path::PathBuf;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn reject_invalid_contract_id() {
    let output = bin()
        .arg("--contract-id")
        .arg("notanid")
        .arg("--rpc-url")
        .arg("https://example.org")
        .arg(wasm("v1.wasm"))
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "invalid contract ID must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid contract ID"),
        "stderr must mention invalid contract ID: {stderr}"
    );
    assert!(
        stderr.contains("strkey is invalid"),
        "stderr must mention strkey validation: {stderr}"
    );
}
