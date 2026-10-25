//! Integration test for `attest` rejecting an invalid report file.
//!
//! The existing `attestation_cli.rs` covers the happy path (real report to
//! signed DSSE envelope) and `verify_attestation_read_errors.rs` covers
//! verification read failures. This file fills the remaining gap: passing
//! `attest` a file that is not valid JSON must fail cleanly with exit 1,
//! name the problem on stderr, and leave `--output` untouched.

use std::path::{Path, PathBuf};
use std::process::Command;

use ring::{rand::SystemRandom, signature};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/wasm")
        .join(name)
}

/// A fresh per-test directory under the OS temp dir. Same pattern as
/// `tests/attestation_cli.rs`, with enough isolation that parallel test
/// binaries cannot collide, no extra dependency needed.
fn temp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    let tid = format!("{:?}", std::thread::current().id());
    let tid_clean: String = tid.chars().filter(|c| c.is_alphanumeric()).collect();
    let path = std::env::temp_dir().join(format!(
        "safeguard-attest-invalid-{pid}-{tid_clean}-{nonce}-{count}"
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Write a real Ed25519 PKCS8 key. `attest` parses `--private-key` before
/// it validates the report, so the test must satisfy that half to reach
/// the JSON validation the acceptance criteria are about.
fn write_signing_key(path: &Path) {
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    std::fs::write(path, pkcs8.as_ref()).unwrap();
}

#[test]
fn attest_rejects_a_report_that_is_not_json() {
    let dir = temp_dir();
    let bad_report = dir.join("bad.json");
    std::fs::write(&bad_report, b"not json").unwrap();

    let key = dir.join("signing-key.pk8");
    write_signing_key(&key);

    let out = dir.join("out.json");

    let output = bin()
        .arg("attest")
        .arg(&bad_report)
        .arg("--old-wasm")
        .arg(wasm("v1.wasm"))
        .arg("--new-wasm")
        .arg(wasm("v2.wasm"))
        .arg("--private-key")
        .arg(&key)
        .arg("--key-id")
        .arg("test-key")
        .arg("--output")
        .arg(&out)
        .output()
        .expect("failed to run attest");

    assert_eq!(
        output.status.code(),
        Some(1),
        "attest must exit 1 on an invalid report file; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid Soroban Upgrade Safeguard JSON report"),
        "stderr must name the specific problem, got: {stderr}",
    );

    assert!(
        !out.exists(),
        "attest must not create --output when the report is invalid: {}",
        out.display(),
    );

    // Cleanup: temp dir is per-test, so this is safe even if the test
    // runs in parallel with other attestation tests.
    let _ = std::fs::remove_dir_all(&dir);
}
