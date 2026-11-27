// SPDX-License-Identifier: MIT
//! Test that an oci:// reference with an empty tag is rejected.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn oci_reference_with_empty_tag_is_rejected() {
    // Run extract with an OCI reference that has an empty tag
    let output = bin()
        .arg("extract")
        .arg("oci://registry.example.com/repo:")
        .arg("--allow-oci-tags")
        .output()
        .expect("failed to run binary");
    
    // Should exit with code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "oci reference with empty tag must fail"
    );
    
    // Error message should contain "has an empty tag"
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("has an empty tag"),
        "error should mention 'has an empty tag', got: {stderr}"
    );
}

#[test]
fn oci_reference_with_valid_tag_does_not_complain_about_empty_tag() {
    // Run extract with an OCI reference that has a valid tag
    // This will fail for other reasons (network, auth, etc.) but should not
    // complain about an empty tag
    let output = bin()
        .arg("extract")
        .arg("oci://registry.example.com/repo:v1.0.0")
        .arg("--allow-oci-tags")
        .output()
        .expect("failed to run binary");
    
    // Will fail, but not due to empty tag
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("has an empty tag"),
        "should not complain about empty tag when tag is valid, got: {stderr}"
    );
}

#[test]
fn oci_reference_in_comparison_with_empty_tag_is_rejected() {
    // Test with oci:// reference in a comparison context
    let output = bin()
        .arg("oci://registry.example.com/old:")
        .arg("oci://registry.example.com/new:v2")
        .arg("--allow-oci-tags")
        .output()
        .expect("failed to run binary");
    
    // Should exit with code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "oci reference with empty tag in comparison must fail"
    );
    
    // Error message should contain "has an empty tag"
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("has an empty tag"),
        "error should mention 'has an empty tag', got: {stderr}"
    );
}
