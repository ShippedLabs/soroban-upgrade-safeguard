// SPDX-License-Identifier: MIT
//! `verify-attestation` must name the attestation file when it cannot read or
//! parse it, like `lint`, `upgrade-report`, and `attest` do for their inputs.

use std::path::PathBuf;
use std::process::Command;

fn run_verify(attestation: &std::path::Path) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("verify-attestation")
        .arg(attestation)
        .args(["--trusted-key", "unused=/nonexistent/public-key.raw"])
        .output()
        .expect("failed to run binary");
    (
        output.status.code(),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
    )
}

#[test]
fn nonexistent_attestation_error_names_the_path() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("does-not-exist.dsse.json");
    let (code, stderr) = run_verify(&path);

    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("Failed to read attestation"),
        "must say what failed: {stderr}"
    );
    assert!(
        stderr.contains(&path.display().to_string()),
        "must name the missing file: {stderr}"
    );
}

#[test]
fn malformed_attestation_error_names_the_path() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("malformed.dsse.json");
    std::fs::write(&path, "not json").expect("failed to write fixture");
    let (code, stderr) = run_verify(&path);
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("Failed to parse attestation"),
        "must say what failed: {stderr}"
    );
    assert!(
        stderr.contains(&path.display().to_string()),
        "must name the unparseable file: {stderr}"
    );
}
