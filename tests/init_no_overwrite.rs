// SPDX-License-Identifier: MIT
//! Test that `init` refuses to overwrite an existing `.safeguard.toml` configuration.

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

#[test]
fn init_refuses_to_overwrite_existing_config() {
    let temp_dir = std::env::temp_dir().join(format!(
        "safeguard-init-no-overwrite-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).expect("failed to create temp directory");

    let config_path = temp_dir.join(".safeguard.toml");
    let original_content =
        "# Original suppression configuration\n[[suppress]]\ncategory = \"test\"\n";
    fs::write(&config_path, original_content).expect("failed to write original config");

    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    let output = bin()
        .current_dir(&temp_dir)
        .arg("init")
        .arg(&v1)
        .arg(&v2)
        .output()
        .expect("failed to execute init");

    // Asserts exit code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 when .safeguard.toml already exists without --force"
    );

    // Asserts stderr contains "already exists" and "--force"
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected stderr to contain 'already exists', got: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "expected stderr to contain '--force', got: {stderr}"
    );

    // Asserts the original file content is unchanged
    let current_content = fs::read_to_string(&config_path).expect("failed to read config file");
    assert_eq!(
        current_content, original_content,
        "config file content should be unchanged"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
