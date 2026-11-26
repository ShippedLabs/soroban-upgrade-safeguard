// SPDX-License-Identifier: MIT
//! `--record-version`, `--retire-version`, and `--max-live-versions` only act on
//! a lineage store, so clap rejects them (exit code 2) when `--lineage-store`
//! is absent, instead of running the comparison and silently doing nothing.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
        .display()
        .to_string()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    (
        output.status.code().expect("process terminated by signal"),
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
    )
}

fn assert_rejected_without_store(flag: &str, value: &str) {
    let old = wasm("v1.wasm");
    let new = wasm("v2.wasm");
    let (code, stdout, stderr) = run(&[&old, &new, flag, value]);

    assert_eq!(
        code, 2,
        "{flag} without --lineage-store must exit 2: {stderr}"
    );
    assert!(
        stderr.contains("--lineage-store"),
        "error must name --lineage-store: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "no comparison should run before the usage error: {stdout}"
    );
}

#[test]
fn record_version_without_lineage_store_is_rejected() {
    assert_rejected_without_store("--record-version", "v2.0.0");
}

#[test]
fn retire_version_without_lineage_store_is_rejected() {
    assert_rejected_without_store("--retire-version", "v1.0.0");
}

#[test]
fn max_live_versions_without_lineage_store_is_rejected() {
    assert_rejected_without_store("--max-live-versions", "3");
}

#[test]
fn max_live_versions_with_lineage_store_is_still_accepted() {
    let store_path = std::env::temp_dir().join(format!(
        "safeguard-lineage-requires-store-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&store_path);

    let old = wasm("v1.wasm");
    let new = wasm("v2.wasm");
    let (code, _stdout, stderr) = run(&[
        &old,
        &new,
        "--lineage-store",
        store_path.to_str().unwrap(),
        "--max-live-versions",
        "3",
        "--quiet",
    ]);

    assert_ne!(
        code, 2,
        "flag with --lineage-store must not be a usage error: {stderr}"
    );
    let _ = std::fs::remove_file(&store_path);
}

#[test]
fn record_version_with_lineage_store_is_still_accepted() {
    let store_path = std::env::temp_dir().join(format!(
        "safeguard-lineage-requires-store-record-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&store_path);

    let old = wasm("v1.wasm");
    let new = wasm("v2.wasm");
    let (code, _stdout, stderr) = run(&[
        &old,
        &new,
        "--lineage-store",
        store_path.to_str().unwrap(),
        "--record-version",
        "v2.0.0",
        "--quiet",
    ]);

    assert_ne!(
        code, 2,
        "flag with --lineage-store must not be a usage error: {stderr}"
    );
    let _ = std::fs::remove_file(&store_path);
}
