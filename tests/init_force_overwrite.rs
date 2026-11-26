// SPDX-License-Identifier: MIT
//! Test that `init --force` overwrites an existing `.safeguard.toml` configuration.

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
fn init_force_overwrites_existing_config() {
    let temp_dir =
        std::env::temp_dir().join(format!("safeguard-init-force-{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("failed to create temp directory");

    let config_path = temp_dir.join(".safeguard.toml");
    let placeholder = "# Placeholder config content that should be overwritten";
    fs::write(&config_path, placeholder).expect("failed to write placeholder config");

    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    let output = bin()
        .current_dir(&temp_dir)
        .arg("init")
        .arg("--force")
        .arg(&v1)
        .arg(&v2)
        .output()
        .expect("failed to execute init with --force");

    assert_eq!(
        output.status.code(),
        Some(0),
        "init --force should exit with code 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let new_content = fs::read_to_string(&config_path).expect("failed to read updated config");
    assert!(
        !new_content.contains(placeholder),
        "config should no longer contain the placeholder"
    );
    assert!(
        new_content.contains("[[suppress]]"),
        "config should now contain [[suppress]]"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
