// SPDX-License-Identifier: MIT
//! Test that `lockfile` reports a directory output path clearly.

use std::fs;
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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temp directory");
    dir
}

#[test]
fn lockfile_reports_directory_output_clearly_without_force() {
    let dir = temp_dir("lockfile_dir_no_force");
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&dir)
        .output()
        .expect("failed to run lockfile with directory output");

    assert_eq!(
        output.status.code(),
        Some(1),
        "lockfile with directory output must exit 1"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        stderr.contains("is a directory"),
        "error must state the path is a directory, got: {stderr}"
    );
    assert!(
        stderr.contains("Provide a file path instead"),
        "error must suggest providing a file path, got: {stderr}"
    );
    assert!(
        !stderr.contains("Use --force"),
        "error must not suggest --force for a directory, got: {stderr}"
    );

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn lockfile_reports_directory_output_clearly_with_force() {
    let dir = temp_dir("lockfile_dir_with_force");
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&dir)
        .arg("--force")
        .output()
        .expect("failed to run lockfile with directory output and --force");

    assert_eq!(
        output.status.code(),
        Some(1),
        "lockfile with directory output must exit 1 even with --force"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        stderr.contains("is a directory"),
        "error must state the path is a directory, got: {stderr}"
    );
    assert!(
        stderr.contains("Provide a file path instead"),
        "error must suggest providing a file path, got: {stderr}"
    );

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn lockfile_suggests_correct_file_path_in_directory_error() {
    let dir = temp_dir("lockfile_dir_path_suggestion");
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg("lockfile")
        .arg(&v1)
        .arg("--output")
        .arg(&dir)
        .output()
        .expect("failed to run lockfile");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    // Error message should suggest a file inside the directory
    assert!(
        stderr.contains("interface.lock.json") || stderr.contains(&dir.display().to_string()),
        "error must suggest a file path example, got: {stderr}"
    );

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}
