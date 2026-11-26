// SPDX-License-Identifier: MIT
//! `stream` reads one job per line from stdin, so empty stdin means no jobs:
//! it must write nothing and exit cleanly.

use std::fs;
use std::process::{Command, Stdio};

#[test]
fn stream_exits_zero_with_no_output_for_empty_stdin() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-stream-empty-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temp working directory");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .current_dir(&dir)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run binary");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        output.status.code(),
        Some(0),
        "empty stdin must not fail the stream"
    );
    assert!(
        output.stdout.is_empty(),
        "no jobs means no results, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
