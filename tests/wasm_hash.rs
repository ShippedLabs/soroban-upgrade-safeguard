//! Provenance-hash coverage: every loaded WASM carries a SHA-256 fingerprint.

use std::path::Path;

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
