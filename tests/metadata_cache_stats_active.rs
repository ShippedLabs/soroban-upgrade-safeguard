// SPDX-License-Identifier: MIT

//! Integration test for `--metadata-cache-stats` combined with
//! `--metadata-cache-dir`.
//!
//! No existing test exercises either flag. This spawns the binary directly,
//! as `tests/extract_subcommand.rs` does, using the checked-in fixtures
//! under `tests/wasm/`.

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

/// A unique directory under the OS temp dir for this test's metadata cache.
fn temp_cache_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-metadata-cache-active-{}",
        std::process::id()
    ))
}

#[test]
fn metadata_cache_stats_reports_the_active_cache_directory() {
    let cache_dir = temp_cache_dir();
    let _ = std::fs::create_dir_all(&cache_dir);

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--metadata-cache-stats")
        .arg("--metadata-cache-dir")
        .arg(&cache_dir)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        stderr.contains(&format!(
            "metadata-cache: active, dir='{}'",
            cache_dir.display()
        )),
        "stderr must report the active cache directory. stderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
}
