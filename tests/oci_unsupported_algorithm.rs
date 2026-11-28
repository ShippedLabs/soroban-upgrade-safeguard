// SPDX-License-Identifier: MIT
//! Integration test: OCI reference with an unsupported digest algorithm is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn oci_reference_with_unsupported_digest_algorithm_is_rejected() {
    let output = bin()
        .arg("oci://registry.example.com/repo@md5:abc123def456")
        .arg("oci://registry.example.com/repo@sha256:0000000000000000000000000000000000000000000000000000000000000001")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "OCI reference with md5 digest algorithm must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported digest algorithm"),
        "stderr must mention unsupported digest algorithm, got: {stderr}"
    );
}

#[test]
fn oci_reference_with_valid_sha256_digest_does_not_complain_about_algorithm() {
    // This test ensures that a valid sha256 digest does not trigger the
    // unsupported algorithm error. It will fail for other reasons (network,
    // auth, etc.), but the error message should not mention digest algorithm.
    let output = bin()
        .arg("oci://registry.example.com/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000")
        .arg("oci://registry.example.com/repo@sha256:0000000000000000000000000000000000000000000000000000000000000001")
        .output()
        .expect("failed to run binary");

    // Will fail (non-zero exit), but not because of algorithm
    assert_ne!(
        output.status.code(),
        Some(0),
        "references to nonexistent registry will fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unsupported digest algorithm"),
        "valid sha256 digest should not trigger algorithm error, got: {stderr}"
    );
}

#[test]
fn oci_reference_with_md5_in_comparison_context_is_rejected() {
    // Test that the unsupported algorithm check applies equally to both OLD and NEW positions.
    let output = bin()
        .arg("oci://registry.example.com/old@sha256:0000000000000000000000000000000000000000000000000000000000000000")
        .arg("oci://registry.example.com/new@md5:fedcba987654")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "OCI reference with md5 in NEW position must exit with code 1"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported digest algorithm"),
        "stderr must mention unsupported digest algorithm for NEW position, got: {stderr}"
    );
}
