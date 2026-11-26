// SPDX-License-Identifier: MIT

//! Integration test for `--metrics-file`.
//!
//! No existing test exercises this flag. This spawns the binary directly,
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

/// A unique path under the OS temp dir for this test's `--metrics-file` output.
fn temp_metrics_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-metrics-{}.prom",
        std::process::id()
    ))
}

#[test]
fn metrics_file_is_written_as_openmetrics_on_a_passing_run() {
    let metrics_path = temp_metrics_path();
    let _ = std::fs::remove_file(&metrics_path);

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm")) // compared against itself: a passing run
        .arg("--metrics-file")
        .arg(&metrics_path)
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "comparing a WASM against itself must pass. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        metrics_path.exists(),
        "--metrics-file must create the metrics file at '{}'",
        metrics_path.display()
    );

    let contents = std::fs::read_to_string(&metrics_path).expect("failed to read metrics file");
    assert!(
        contents.contains("# HELP"),
        "metrics file must contain OpenMetrics '# HELP' lines. Contents:\n{contents}"
    );
    assert!(
        contents.contains("# TYPE"),
        "metrics file must contain OpenMetrics '# TYPE' lines. Contents:\n{contents}"
    );

    let _ = std::fs::remove_file(&metrics_path);
}
