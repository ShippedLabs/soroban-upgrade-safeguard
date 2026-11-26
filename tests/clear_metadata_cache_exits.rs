// SPDX-License-Identifier: MIT
//! Integration test for `--clear-metadata-cache`.
//!
//! No existing test uses this flag. This spawns the binary directly, as
//! `tests/extract_subcommand.rs` does.

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

/// A unique directory under the OS temp dir for this test's cache.
fn temp_cache_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-clear-metadata-cache-{}",
        std::process::id()
    ))
}

#[test]
fn clear_metadata_cache_deletes_the_directory_and_exits_without_comparing() {
    let cache_dir = temp_cache_dir();
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).expect("failed to create cache dir");
    std::fs::write(cache_dir.join("entry.json"), b"{}").expect("failed to write cache file");

    // Both fixtures are supplied so that a comparison would have something to
    // report if the flag failed to short-circuit.
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--clear-metadata-cache")
        .arg("--metadata-cache-dir")
        .arg(&cache_dir)
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--clear-metadata-cache must exit 0. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.contains("Cleared parsed-metadata cache"),
        "stdout must confirm the cache was cleared. stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Soroban Upgrade Safety Report"),
        "no comparison report may be printed. stdout:\n{stdout}"
    );
    assert!(
        !cache_dir.exists(),
        "the cache directory must be deleted along with its contents"
    );
}
