// SPDX-License-Identifier: MIT
//! Integration coverage for `init` when both inputs are identical.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn init_with_identical_wasm_reports_no_compatibility_issues() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-init-identical-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temporary working directory");

    let wasm = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("init")
        .arg(&wasm)
        .arg(&wasm)
        .current_dir(&dir)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("No compatibility issues detected"),
        "stdout should report no compatibility issues, got: {stdout}"
    );
    assert!(
        dir.join(".safeguard.toml").is_file(),
        "init should write .safeguard.toml in the working directory"
    );

    fs::remove_dir_all(dir).expect("failed to remove temporary working directory");
}
