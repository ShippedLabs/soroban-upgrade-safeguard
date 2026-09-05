//! Known-vector test for the WASM SHA-256 helper.
//!
//! The loader exposes a SHA-256 helper used in report provenance and hash
//! pinning. This test verifies it against a published SHA-256 known vector
//! so the implementation cannot regress to a different encoding or digest
//! representation. The assertion is independent of any WASM fixture.

use soroban_upgrade_safeguard::loader::sha256_hex;

#[test]
fn sha256_helper_matches_known_vector() {
    // Known vector: SHA-256 of the string "abc"
    // Source: NIST FIPS 180-4, Appendix B.1
    // https://csrc.nist.gov/publications/detail/fips/180/4/final
    let input = b"abc";
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    let result = sha256_hex(input);

    assert_eq!(
        result, expected,
        "SHA-256 of 'abc' must match the published NIST vector"
    );
}

#[test]
fn sha256_helper_empty_input_matches_known_vector() {
    // Known vector: SHA-256 of the empty string
    // Source: NIST FIPS 180-4, Appendix B.1
    let input = b"";
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let result = sha256_hex(input);

    assert_eq!(
        result, expected,
        "SHA-256 of empty input must match the published NIST vector"
    );
}

#[test]
fn sha256_helper_longer_input_matches_known_vector() {
    // Known vector: SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    // Source: NIST FIPS 180-4, Appendix B.1
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    let result = sha256_hex(input);

    assert_eq!(
        result, expected,
        "SHA-256 of multi-block input must match the published NIST vector"
    );
}

#[test]
fn sha256_helper_output_is_lowercase_hex() {
    // Verify the output is lowercase hexadecimal, not uppercase or binary
    let input = b"test";
    let result = sha256_hex(input);

    // SHA-256 produces 32 bytes = 64 hex characters
    assert_eq!(
        result.len(),
        64,
        "SHA-256 hex output must be exactly 64 characters"
    );

    // All characters must be lowercase hex digits
    assert!(
        result
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "SHA-256 output must be lowercase hexadecimal, got: {}",
        result
    );
}

#[test]
fn sha256_helper_deterministic_across_calls() {
    // The same input must always produce the same output
    let input = b"deterministic test";

    let result1 = sha256_hex(input);
    let result2 = sha256_hex(input);
    let result3 = sha256_hex(input);

    assert_eq!(
        result1, result2,
        "SHA-256 must be deterministic across calls"
    );
    assert_eq!(
        result2, result3,
        "SHA-256 must be deterministic across calls"
    );
}

#[test]
fn sha256_helper_sensitive_to_input_changes() {
    // A single bit change in input must produce a completely different hash
    let input1 = b"test";
    let input2 = b"Test"; // Only first letter capitalized

    let hash1 = sha256_hex(input1);
    let hash2 = sha256_hex(input2);

    assert_ne!(
        hash1, hash2,
        "SHA-256 must produce different hashes for different inputs"
    );

    // The hashes should differ in many positions (avalanche effect)
    let diff_count = hash1
        .chars()
        .zip(hash2.chars())
        .filter(|(a, b)| a != b)
        .count();
    assert!(
        diff_count > 20,
        "SHA-256 should exhibit avalanche effect (many bits changed), but only {} of 64 hex digits differ",
        diff_count
    );
}
