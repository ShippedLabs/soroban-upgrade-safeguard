// SPDX-License-Identifier: MIT
//! Integration test that verifies --interface-lockfile cannot be combined with --contract-id.

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
fn interface_lockfile_with_contract_id_is_rejected() {
    let output = bin()
        .arg("--contract-id")
        .arg("CABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")
        .arg("--rpc-url")
        .arg("https://example.org")
        .arg(wasm("v1.wasm"))
        .arg("--interface-lockfile")
        .arg("x.json")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "command must exit with code 1 when --interface-lockfile is combined with --contract-id"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the lockfile supplies the baseline"),
        "stderr must contain the error about lockfile supplying the baseline, got: {stderr}"
    );
}
