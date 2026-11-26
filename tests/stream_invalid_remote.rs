// SPDX-License-Identifier: MIT
//! `stream` reports a job whose `remote` input is not a parseable reference as
//! a per-job `failure` result rather than aborting the whole stream.

use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn stream_reports_an_invalid_remote_reference_as_a_failure() {
    let new_wasm = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let job = serde_json::json!({
        "schema_version": 1,
        "id": "bad-remote",
        "old": { "remote": "not a url" },
        "new": { "local": new_wasm.to_str().unwrap() },
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "a job with an invalid remote must not fail the stream\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one result line: {stdout}");

    let result: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{}", lines[0]));
    assert_eq!(result["id"], "bad-remote");
    assert_eq!(result["status"], "failure");

    let error = result["error"].as_str().expect("error must be a string");
    assert!(
        error.contains("not a valid remote reference"),
        "unexpected error: {error}"
    );
}
