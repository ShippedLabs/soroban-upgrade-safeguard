// SPDX-License-Identifier: MIT
//! Integration test for `--inspect-metadata-cache` on an empty cache
//! directory.
//!
//! No existing test exercises this flag. This spawns the binary directly,
//! as `tests/extract_subcommand.rs` does.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

/// A unique, empty directory under the OS temp dir for this test's cache.
fn temp_cache_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-metadata-cache-empty-{}",
        std::process::id()
    ))
}

#[test]
fn inspect_metadata_cache_reports_an_empty_cache_and_exits_without_analyzing() {
    let cache_dir = temp_cache_dir();
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).expect("failed to create empty cache dir");

    let output = bin()
        .arg("--inspect-metadata-cache")
        .arg("--metadata-cache-dir")
        .arg(&cache_dir)
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--inspect-metadata-cache on an empty dir must exit 0. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    assert!(
        stderr.contains(&format!(
            "metadata-cache: no entries in '{}'",
            cache_dir.display()
        )),
        "stderr must report that the cache is empty. stderr:\n{stderr}"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.is_empty(),
        "no WASM input was given, so nothing should have been analyzed. stdout:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
}
