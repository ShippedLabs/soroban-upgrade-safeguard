//! CLI-level wiring tests for `https://` input positions.
//!
//! These don't hit the network (the CLI's remote-fetch policy always sets
//! `https_only: true`, and CI has no network access) — they confirm that a
//! `https://` positional argument is dispatched to the resolver at all
//! (rejected before any local-file lookup, with a message about the missing
//! digest) and that `--clear-remote-cache` works end-to-end. Network
//! behavior itself is covered by the local-server tests in
//! `tests/remote_fetch.rs`.

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
fn https_input_without_a_digest_fragment_fails_before_any_wasm_analysis() {
    let old = wasm("v1.wasm").display().to_string();
    let (code, _stdout, stderr) = run(&[&old, "https://example.invalid/contract.wasm", "--quiet"]);
    assert_ne!(code, 0, "missing digest must be rejected");
    assert!(
        stderr.to_lowercase().contains("sha256"),
        "error should mention the required digest fragment, got: {stderr}"
    );
}

#[test]
fn https_input_with_a_malformed_digest_is_rejected_with_a_clear_message() {
    let old = wasm("v1.wasm").display().to_string();
    let (code, _stdout, stderr) = run(&[
        &old,
        "https://example.invalid/contract.wasm#sha256=not-hex",
        "--quiet",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr.to_lowercase().contains("digest") || stderr.to_lowercase().contains("sha256"),
        "error should mention the invalid digest, got: {stderr}"
    );
}

#[test]
fn clear_remote_cache_removes_the_directory_and_exits_zero() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-remote-cli-clear-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(dir.join("deadbeef")).expect("create fake cache entry dir");
    std::fs::write(dir.join("deadbeef").join("artifact.bin"), b"x").expect("write fake artifact");
    assert!(dir.exists());

    let dir_str = dir.display().to_string();
    let (code, stdout, _stderr) = run(&["--clear-remote-cache", "--remote-cache-dir", &dir_str]);

    assert_eq!(code, 0, "clearing the cache should succeed");
    assert!(!dir.exists(), "cache directory should be removed");
    assert!(stdout.contains("Cleared remote artifact cache"));
}

#[test]
fn clear_remote_cache_exits_without_a_comparison_or_any_wasm_inputs() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-remote-cli-clear-no-comparison-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(dir.join("cafef00d")).expect("create fake cache entry dir");
    std::fs::write(dir.join("cafef00d").join("artifact.bin"), b"cached")
        .expect("write fake artifact");
    assert!(dir.exists());

    // No positional WASM paths are passed at all: --clear-remote-cache must
    // succeed on its own, without the usual "provide OLD_WASM/NEW_WASM"
    // validation that a comparison run would require.
    let dir_str = dir.display().to_string();
    let (code, stdout, stderr) = run(&["--clear-remote-cache", "--remote-cache-dir", &dir_str]);

    assert_eq!(
        code, 0,
        "clearing the cache without any WASM inputs should succeed, stderr: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "no WASM-input or comparison error should be printed, got: {stderr}"
    );

    // The success message confirms a cache clear happened, not a comparison
    // (which would report a verdict/compatibility result instead).
    assert!(stdout.contains("Cleared remote artifact cache"));
    assert!(
        !stdout.to_lowercase().contains("compat"),
        "no comparison verdict should be reported, got: {stdout}"
    );

    assert!(
        !dir.exists(),
        "cached artifacts present before the run should be gone afterward"
    );
}

#[test]
fn clear_remote_cache_on_an_already_absent_directory_is_a_no_op_success() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-remote-cli-clear-absent-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!dir.exists());

    let dir_str = dir.display().to_string();
    let (code, _stdout, _stderr) = run(&["--clear-remote-cache", "--remote-cache-dir", &dir_str]);
    assert_eq!(code, 0);
}
