// SPDX-License-Identifier: MIT
//! Integration test that verifies --contract-id rejects two positional WASM paths.

use std::path::PathBuf;
use std::process::Command;

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
fn contract_id_with_two_positional_paths_is_rejected() {
    let output = bin()
        .arg("--contract-id")
        .arg("CABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")
        .arg("--rpc-url")
        .arg("https://example.org")
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "command must exit with code 1 when --contract-id is used with two positional paths"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("provide only the NEW_WASM path"),
        "stderr must contain the error about providing only NEW_WASM path, got: {stderr}"
    );
}
