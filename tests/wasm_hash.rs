// SPDX-License-Identifier: MIT
//! Provenance-hash coverage: every loaded WASM carries a SHA-256 fingerprint.

use std::path::Path;
use std::process::Command;

use soroban_upgrade_safeguard::loader::{load_wasm, sha256_hex};

/// The SHA-256 of a byte slice matches an independently known vector, so the
/// fingerprint the report displays is a real SHA-256, not an internal digest.
#[test]
fn sha256_hex_matches_known_vector() {
    // SHA-256("abc"), per FIPS 180-4.
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // SHA-256 of the empty input.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// Loading a fixture WASM populates `sha256` with the hash of its exact bytes,
/// matching the value `shasum -a 256` reports for the same file.
#[test]
fn load_wasm_populates_sha256_of_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm");
    let module = load_wasm(&path).expect("fixture v1.wasm should load");

    assert_eq!(
        module.sha256,
        "31fc0a23f04c6fc647ac44ba791228d8f0f12308685f0ac3798d37c79518906b"
    );
    // The stored hash equals hashing the returned bytes directly.
    assert_eq!(module.sha256, sha256_hex(&module.bytes));
}

fn run_with_expected_hash(expected: &str) -> (i32, String) {
    let wasm = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/wasm")
            .join(name)
    };
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--expected-wasm-hash", expected])
        .output()
        .expect("failed to run binary");
    (
        output.status.code().expect("process terminated by signal"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
    )
}

/// A value with non-hex characters is rejected as malformed, not compared
/// against the baseline's actual hash.
#[test]
fn expected_wasm_hash_with_non_hex_characters_is_rejected_as_malformed() {
    let (code, stderr) =
        run_with_expected_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");

    assert_ne!(code, 0, "malformed hash must be rejected: {stderr}");
    assert!(
        stderr.contains("must be a 64-character hex SHA-256 digest"),
        "expected a malformed-value error, got: {stderr}"
    );
}

/// A value of the wrong length is rejected as malformed, distinct from a
/// well-formed hash that simply does not match.
#[test]
fn expected_wasm_hash_with_wrong_length_is_rejected_as_malformed() {
    let (code, stderr) = run_with_expected_hash("a1b2c3");

    assert_ne!(code, 0, "wrong-length hash must be rejected: {stderr}");
    assert!(
        stderr.contains("must be a 64-character hex SHA-256 digest"),
        "expected a malformed-value error, got: {stderr}"
    );
}

/// A well-formed 64-character hex value that just doesn't match the
/// baseline's real hash is reported as a mismatch, not as malformed — the two
/// failure modes must be distinguishable.
#[test]
fn expected_wasm_hash_well_formed_but_wrong_is_reported_as_mismatch() {
    let (code, stderr) = run_with_expected_hash(&"0".repeat(64));

    assert_ne!(code, 0, "hash mismatch must be rejected: {stderr}");
    assert!(
        stderr.contains("Baseline hash mismatch"),
        "expected a mismatch error, not a malformed-value error, got: {stderr}"
    );
    assert!(
        !stderr.contains("must be a 64-character hex SHA-256 digest"),
        "mismatch must not be reported as malformed: {stderr}"
    );
}
