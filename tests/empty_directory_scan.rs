// SPDX-License-Identifier: MIT
//! Integration coverage for directory scans with no WASM artifacts.

use std::fs;
use std::process::Command;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("failed to create temporary directory");
    path
}

#[test]
fn empty_directories_report_no_wasm_files() {
    let old_dir = temp_dir("empty-scan-old");
    let new_dir = temp_dir("empty-scan-new");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let old_dir_display = old_dir.display().to_string();
    let new_dir_display = new_dir.display().to_string();
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("No .wasm files found in batch directories"),
        "stderr should explain that no WASM files were found, got: {stderr}"
    );
    assert!(
        stderr.contains(old_dir_display.as_str()),
        "stderr should list the old directory, got: {stderr}"
    );
    assert!(
        stderr.contains(new_dir_display.as_str()),
        "stderr should list the new directory, got: {stderr}"
    );
    assert!(
        stderr.contains("Directory scan requires .wasm artifacts."),
        "stderr should explain the directory scan requirement, got: {stderr}"
    );

    fs::remove_dir_all(old_dir).expect("failed to remove temporary old directory");
    fs::remove_dir_all(new_dir).expect("failed to remove temporary new directory");
}
