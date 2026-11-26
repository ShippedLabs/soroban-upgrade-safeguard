// SPDX-License-Identifier: MIT
//! `--validate-config` rejects a suppression rule whose `expiry` date is not
//! formatted as `YYYY-MM-DD`, exiting 1 and naming the expected format.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_config(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}.toml",
        std::process::id()
    ))
}

#[test]
fn validate_config_reports_invalid_expiry_date() {
    let config_path = temp_config("invalid-expiry");
    let toml = r#"
[[suppress]]
category = "Struct Field Removed"
target = "ConfigData.threshold"
expiry = "31/12/2026"
"#;
    fs::write(&config_path, toml).expect("write temp config");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--validate-config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");

    let _ = fs::remove_file(&config_path);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(output.status.code(), Some(1), "expected exit 1: {combined}");
    assert!(
        combined.contains("expected YYYY-MM-DD"),
        "expected invalid expiry format message, got: {combined}"
    );
}
