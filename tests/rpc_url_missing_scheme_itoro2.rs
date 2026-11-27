// SPDX-License-Identifier: MIT
//! Test that an RPC URL without a scheme is rejected.

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
fn reject_rpc_url_without_scheme() {
    let output = bin()
        .arg("--contract-id")
        .arg("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4")
        .arg("--rpc-url")
        .arg("example.org")
        .arg(wasm("v1.wasm"))
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "RPC URL without scheme must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is missing a scheme"),
        "stderr must mention missing scheme: {stderr}"
    );
}
