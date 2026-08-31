//! CLI-level wiring tests for `oci://` input positions.
//!
//! These don't hit the network (the CLI's OCI-fetch policy always sets
//! `https_only: true`, and CI has no network access) — they confirm that an
//! `oci://` positional argument is dispatched to the resolver at all
//! (rejected before any local-file lookup, with a message naming what's
//! wrong) and that `--clear-oci-cache` / `--allow-oci-tags` are wired
//! end-to-end. Network behavior itself is covered by the local-registry
//! tests in `tests/oci_fetch.rs`.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout, stderr)
}

#[test]
fn oci_input_missing_a_digest_or_tag_fails_before_any_wasm_analysis() {
    let old = wasm("v1.wasm").display().to_string();
    let (code, _stdout, stderr) = run(&[&old, "oci://example.invalid/contract", "--quiet"]);
    assert_ne!(
        code, 0,
        "a reference with neither a digest nor a tag must be rejected"
    );
    assert!(
        stderr.to_lowercase().contains("digest") || stderr.to_lowercase().contains("tag"),
        "error should mention the missing digest/tag, got: {stderr}"
    );
}

#[test]
fn oci_input_with_a_malformed_digest_is_rejected_with_a_clear_message() {
    let old = wasm("v1.wasm").display().to_string();
    let (code, _stdout, stderr) = run(&[
        &old,
        "oci://example.invalid/contract@sha256:not-hex",
        "--quiet",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr.to_lowercase().contains("digest"),
        "error should mention the invalid digest, got: {stderr}"
    );
}

#[test]
fn oci_input_with_a_tag_is_rejected_by_default_without_allow_oci_tags() {
    let old = wasm("v1.wasm").display().to_string();
    let (code, _stdout, stderr) = run(&[&old, "oci://example.invalid/contract:latest", "--quiet"]);
    assert_ne!(
        code, 0,
        "a mutable tag reference must be rejected without --allow-oci-tags"
    );
    assert!(
        stderr.contains("allow-oci-tags"),
        "error should point at the opt-in flag, got: {stderr}"
    );
}

#[test]
fn clear_oci_cache_removes_the_directory_and_exits_zero() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-oci-cli-clear-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(dir.join("sha256_deadbeef")).expect("create fake cache entry dir");
    std::fs::write(dir.join("sha256_deadbeef").join("artifact.bin"), b"x")
        .expect("write fake artifact");
    assert!(dir.exists());

    let dir_str = dir.display().to_string();
    let (code, stdout, _stderr) = run(&["--clear-oci-cache", "--oci-cache-dir", &dir_str]);

    assert_eq!(code, 0, "clearing the OCI cache should succeed");
    assert!(!dir.exists(), "cache directory should be removed");
    assert!(stdout.contains("Cleared OCI artifact cache"));
}

#[test]
fn clear_oci_cache_on_an_already_absent_directory_is_a_no_op_success() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-oci-cli-clear-absent-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!dir.exists());

    let dir_str = dir.display().to_string();
    let (code, _stdout, _stderr) = run(&["--clear-oci-cache", "--oci-cache-dir", &dir_str]);
    assert_eq!(code, 0);
}
