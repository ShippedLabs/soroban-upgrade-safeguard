//! Positional WASM paths are rejected when batch mode is used.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn positional_wasm_paths_with_manifest_exit_1() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm = root.join("tests").join("wasm");
    let manifest = root.join("Cargo.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm.join("v1.wasm"))
        .arg(wasm.join("v2.wasm"))
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cannot specify positional WASM paths"),
        "unexpected stderr: {stderr}"
    );
}
