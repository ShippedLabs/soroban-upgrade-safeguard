// SPDX-License-Identifier: MIT
use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::suppression::SuppressionConfig;

#[test]
fn init_stdout_emits_parseable_config_without_writing_a_file() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("safeguard-init-stdout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .current_dir(&dir)
        .arg("init")
        .arg("--stdout")
        .arg(root.join("tests/wasm/v1.wasm"))
        .arg(root.join("tests/wasm/v2.wasm"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let config = String::from_utf8(output.stdout).unwrap();
    assert!(config.starts_with("# Auto-generated suppression config"));
    SuppressionConfig::from_toml_str(&config).unwrap();
    assert!(!dir.join(".safeguard.toml").exists());
    std::fs::remove_dir_all(dir).unwrap();
}
