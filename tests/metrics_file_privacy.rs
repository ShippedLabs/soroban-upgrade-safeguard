// SPDX-License-Identifier: MIT

//! Tests that the metrics file written by `--metrics-file` contains no input
//! file paths.
//!
//! `docs/metrics.md` documents that metrics never include contract IDs, RPC
//! URLs, file paths, or finding messages as label values.  This test guards
//! that promise for the file-path case by running a real comparison against
//! the checked-in WASM fixtures and asserting that neither the absolute WASM
//! paths nor the temp-directory prefix appear anywhere in the written file.
//!
//! Spawns the compiled binary directly via
//! `CARGO_BIN_EXE_soroban-upgrade-safeguard`, as `tests/extract_subcommand.rs`
//! does.

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
fn metrics_file_contains_no_input_wasm_paths() {
    let metrics_path = std::env::temp_dir().join(format!(
        "safeguard-metrics-privacy-{}.txt",
        std::process::id()
    ));
    let _ = fs::remove_file(&metrics_path);

    let old_wasm = wasm("v1.wasm");
    let new_wasm = wasm("v2.wasm");

    let output = bin()
        .arg(&old_wasm)
        .arg(&new_wasm)
        .arg("--metrics-file")
        .arg(&metrics_path)
        .output()
        .expect("failed to spawn binary");

    // The comparison between v1 and v2 is expected to find breaking changes,
    // so exit code 1 is the normal outcome here.  We accept both 0 and 1;
    // anything else is an unexpected error.
    let code = output.status.code().expect("process terminated by signal");
    assert!(
        code == 0 || code == 1,
        "expected exit code 0 or 1, got {code}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The metrics file must have been written.
    let contents = fs::read_to_string(&metrics_path)
        .expect("metrics file was not written after a successful run");

    // Neither the absolute WASM path nor the temp-directory prefix must appear.
    let old_path_str = old_wasm.to_string_lossy();
    let new_path_str = new_wasm.to_string_lossy();
    let temp_dir_str = std::env::temp_dir().to_string_lossy().into_owned();

    assert!(
        !contents.contains(old_path_str.as_ref()),
        "metrics file must not contain the old WASM path '{old_path_str}'"
    );

    assert!(
        !contents.contains(new_path_str.as_ref()),
        "metrics file must not contain the new WASM path '{new_path_str}'"
    );

    assert!(
        !contents.contains(temp_dir_str.as_str()),
        "metrics file must not contain the temp directory path '{temp_dir_str}'"
    );

    fs::remove_file(&metrics_path).unwrap();
}
