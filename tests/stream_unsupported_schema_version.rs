// SPDX-License-Identifier: MIT
//! Test that `stream` rejects a job with an unsupported `schema_version`.
//!
//! A job with `"schema_version": 2` must return a result with
//! `{"status": "malformed", "error": "Unsupported schema_version 2 (expected 1)"}`,
//! and the stream must exit 0 (a malformed job is not a stream failure).

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn stream_rejects_unsupported_schema_version() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-stream-unsupported-schema-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("failed to create temp working directory");

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    // Create a job with schema_version 2 (unsupported)
    let v1_path = wasm("v1.wasm");
    let v2_path = wasm("v2.wasm");
    let job = serde_json::json!({
        "schema_version": 2,
        "id": "test-job-unsupported",
        "old": {
            "local": v1_path.to_str().unwrap()
        },
        "new": {
            "local": v2_path.to_str().unwrap()
        }
    });

    let job_line = format!("{}\n", serde_json::to_string(&job).unwrap());

    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(job_line.as_bytes())
        .expect("failed to write to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stream must exit 0 even when a job has an unsupported schema_version"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one result line: {stdout}"
    );

    let result: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{}", lines[0]));

    assert_eq!(result["status"], "malformed", "status must be malformed");
    assert_eq!(
        result["id"], "test-job-unsupported",
        "id must be echoed from the job"
    );

    let error = result["error"]
        .as_str()
        .expect("error field must be present");
    assert!(
        error.contains("Unsupported schema_version"),
        "error must mention unsupported schema_version, got: {error}"
    );
    assert!(
        error.contains("2"),
        "error must mention the actual schema version 2, got: {error}"
    );
    assert!(
        error.contains("expected 1") || error.contains("(expected 1)"),
        "error must mention expected version 1, got: {error}"
    );
}
