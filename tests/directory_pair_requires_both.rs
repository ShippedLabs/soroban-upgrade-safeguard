// SPDX-License-Identifier: MIT
//! Integration tests for incomplete `--old-dir` / `--new-dir` pairs.
//!
//! Both flags are required together (`clap`'s `requires` attribute enforces
//! this at argument-parsing time), but a user can still type only one of the
//! two. These tests check that supplying just one half of the pair is
//! rejected with an error naming the missing flag.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn new_dir_without_old_dir_is_rejected() {
    let output = bin()
        .args(["--new-dir", "/tmp/does-not-need-to-exist-new"])
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "--new-dir without --old-dir must not succeed"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("--old-dir"),
        "error should name the missing flag '--old-dir', got: {stderr}"
    );
}

#[test]
fn old_dir_without_new_dir_is_rejected() {
    let output = bin()
        .args(["--old-dir", "/tmp/does-not-need-to-exist-old"])
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "--old-dir without --new-dir must not succeed"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("--new-dir"),
        "error should name the missing flag '--new-dir', got: {stderr}"
    );
}
