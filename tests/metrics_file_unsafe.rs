//! `--metrics-file` must be written for every verdict, including an unsafe one.
//!
//! The snapshot used to be written only after the run function returned, but an
//! unsafe verdict exits the process from inside it, so the file was never
//! created on exactly the runs most worth inspecting. These tests drive the
//! real binary against the checked-in fixtures:
//!
//! - `v1 -> v1` is identical and safe (exit 0).
//! - `v1 -> v2` has Critical findings and is unsafe (exit 1).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// A fresh, empty path under the per-test temp dir. Any file left over from an
/// earlier run is removed so that "the file exists" can only mean this run
/// wrote it.
fn fresh_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_file(&path);
    path
}

/// Run the binary with `--no-config`, so an ambient `.safeguard.toml` can never
/// suppress the findings these tests rely on.
fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .arg("--no-config")
        .arg("--quiet")
        .output()
        .expect("failed to run binary")
}

fn assert_valid_snapshot(path: &Path) {
    assert!(
        path.exists(),
        "metrics file {} was not written",
        path.display()
    );
    let text = std::fs::read_to_string(path).expect("metrics file should be readable");
    assert!(
        text.contains("soroban_safeguard_pairs_total"),
        "metrics file is missing the pairs counter: {text}"
    );
    assert!(
        text.ends_with("# EOF\n"),
        "metrics file should be complete OpenMetrics text: {text:?}"
    );
}

#[test]
fn metrics_file_is_written_when_the_verdict_is_unsafe() {
    let metrics = fresh_path("metrics_unsafe_single.prom");
    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    let output = run(&[
        v1.as_os_str(),
        v2.as_os_str(),
        "--metrics-file".as_ref(),
        metrics.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unsafe verdict must still exit 1"
    );
    assert_valid_snapshot(&metrics);
}

#[test]
fn metrics_file_is_still_written_when_the_verdict_is_safe() {
    let metrics = fresh_path("metrics_safe_single.prom");
    let v1 = wasm("v1.wasm");

    let output = run(&[
        v1.as_os_str(),
        v1.as_os_str(),
        "--metrics-file".as_ref(),
        metrics.as_os_str(),
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert_valid_snapshot(&metrics);
}

#[test]
fn metrics_file_is_written_when_a_batch_verdict_is_unsafe() {
    // Batch mode had the same early exit, so it gets the same guarantee.
    let metrics = fresh_path("metrics_unsafe_batch.prom");

    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("metrics_unsafe_batch_dirs");
    let old_dir = root.join("old");
    let new_dir = root.join("new");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&old_dir).expect("create old dir");
    std::fs::create_dir_all(&new_dir).expect("create new dir");
    std::fs::copy(wasm("v1.wasm"), old_dir.join("token.wasm")).expect("copy old");
    std::fs::copy(wasm("v2.wasm"), new_dir.join("token.wasm")).expect("copy new");

    let output = run(&[
        "--old-dir".as_ref(),
        old_dir.as_os_str(),
        "--new-dir".as_ref(),
        new_dir.as_os_str(),
        "--metrics-file".as_ref(),
        metrics.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unsafe batch verdict must still exit 1"
    );
    assert_valid_snapshot(&metrics);
}
