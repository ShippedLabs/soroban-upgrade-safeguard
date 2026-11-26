// SPDX-License-Identifier: MIT
//! `--validate-config` must reject a rule naming a category the tool never
//! emits, instead of silently accepting a suppression that can never match.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_config() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-validate-unknown-category-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp config directory");
    (dir.join(".safeguard.toml"), dir)
}

#[test]
fn validate_config_reports_unknown_category_and_exits_one() {
    let (path, dir) = temp_config();
    fs::write(
        &path,
        "[[suppress]]\ncategory = \"No Such Category\"\ntarget = \"legacy_init\"\n",
    )
    .expect("write suppression config");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--validate-config")
        .arg(&path)
        .arg("--no-color")
        .current_dir(&dir)
        .output()
        .expect("run --validate-config");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unknown category must fail validation\noutput:\n{combined}"
    );
    assert!(
        combined.contains("unknown finding category 'No Such Category'"),
        "output must name the unknown category\noutput:\n{combined}"
    );
}
