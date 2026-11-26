// SPDX-License-Identifier: MIT
//! Tests that `--remote-max-bytes` rejects a non-numeric value.
//!
//! Spawns the compiled binary directly (via `CARGO_BIN_EXE_soroban-upgrade-safeguard`)
//! using the checked-in WASM fixtures under `tests/wasm/`.

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
fn remote_max_bytes_rejects_non_numeric_value() {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--remote-max-bytes")
        .arg("abc")
        .output()
        .expect("failed to spawn binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap exits with code 2 on invalid argument values"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("--remote-max-bytes"),
        "stderr must name the offending flag; got:\n{stderr}"
    );

    assert!(
        stderr.contains("abc"),
        "stderr must echo the invalid value; got:\n{stderr}"
    );
}
