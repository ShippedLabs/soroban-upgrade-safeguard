// SPDX-License-Identifier: MIT
//! `stream` reports a job whose `old` input points at a missing file as a
//! `failure` result rather than aborting the whole stream.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn stream_reports_a_missing_old_input_file_as_a_failure() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-stream-missing-input-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temp working directory");

    let new = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let job = serde_json::json!({
        "schema_version": 1,
        "id": "missing-old",
        "old": { "local": "/nonexistent.wasm" },
        "new": { "local": new.to_str().unwrap() },
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(format!("{job}\n").as_bytes())
        .expect("failed to write to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a missing input file must not fail the stream"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one result line: {stdout}");

    let result: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{}", lines[0]));
    assert_eq!(result["status"], "failure", "unexpected result: {result}");
    let error = result["error"].as_str().expect("error must be a string");
    assert!(
        error.contains("File not found"),
        "error should mention the missing file: {error}"
    );
}
