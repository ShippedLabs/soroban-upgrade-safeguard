// SPDX-License-Identifier: MIT
//! Integration tests for the `init` subcommand.
//!
//! `init` compares two builds and writes a starter `.safeguard.toml` with
//! commented-out `[[suppress]]` blocks for each finding.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn init_writes_a_safeguard_toml_for_a_breaking_pair() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-init-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temp working directory");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("init")
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .current_dir(&dir)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let config = fs::read_to_string(dir.join(".safeguard.toml"));
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(0), "init must succeed: {stdout}");
    assert!(
        stdout.contains("Generated .safeguard.toml"),
        "init should announce the file it wrote, got: {stdout}"
    );

    let config = config.expect(".safeguard.toml should be written to the working directory");
    assert!(
        config.contains("[[suppress]]"),
        "the generated config should include suppress blocks, got: {config}"
    );
}

#[test]
fn init_output_uses_the_chosen_path_and_honors_force() {
    let dir = std::env::temp_dir().join(format!("sus-init-output-{}", std::process::id()));
    fs::create_dir_all(dir.join("ci")).unwrap();
    let default_path = dir.join(".safeguard.toml");
    fs::write(&default_path, "keep default config").unwrap();
    let path = dir.join("ci/safeguard.toml");
    let run = |force: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
        command
            .arg("init")
            .arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .args(["--output", "ci/safeguard.toml"])
            .current_dir(&dir);
        if force {
            command.arg("--force");
        }
        command.output().unwrap()
    };

    let output = run(false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fs::read_to_string(&path).unwrap();
    assert!(config.contains("[[suppress]]"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("ci/safeguard.toml"));

    fs::write(&path, "keep chosen config").unwrap();
    let output = run(false);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ci/safeguard.toml"));
    assert!(stderr.contains("--force"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "keep chosen config");

    assert!(run(true).status.success());
    assert_eq!(fs::read_to_string(&path).unwrap(), config);
    assert_eq!(
        fs::read_to_string(&default_path).unwrap(),
        "keep default config"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn init_help_documents_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["init", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--output <PATH>"));
    assert!(stdout.contains(".safeguard.toml"));
}
