//! `--manifest` cannot be combined with `--old-dir` and `--new-dir`.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn manifest_with_old_and_new_dir_exits_1() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = root.join("Cargo.toml");
    let dir = root.join("tests");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest)
        .arg("--old-dir")
        .arg(&dir)
        .arg("--new-dir")
        .arg(&dir)
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cannot specify both"),
        "unexpected stderr: {stderr}"
    );
}
