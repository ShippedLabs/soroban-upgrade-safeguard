// SPDX-License-Identifier: MIT

//! `--interface-lockfile` has no meaning in batch mode, so combining it with
//! `--old-dir`/`--new-dir` must fail up front.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

#[test]
fn interface_lockfile_is_rejected_in_batch_mode() {
    let old_dir = temp_dir("lockfile-batch-old");
    let new_dir = temp_dir("lockfile-batch-new");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .arg("--interface-lockfile")
        .arg("x.json")
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = fs::remove_dir_all(&old_dir);
    let _ = fs::remove_dir_all(&new_dir);

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("with batch mode"), "stderr: {stderr}");
}
