// SPDX-License-Identifier: MIT
//! `stream` reports a job line that omits its `id` as a `malformed` result
//! with a synthetic line id, rather than aborting the whole stream.

use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
        .to_str()
        .expect("fixture path was not valid UTF-8")
        .to_string()
}

#[test]
fn stream_reports_a_job_without_an_id_as_malformed() {
    // Otherwise valid job, so the only thing wrong with it is the missing id.
    let job = serde_json::json!({
        "schema_version": 1,
        "old": { "local": wasm("v1.wasm") },
        "new": { "local": wasm("v2.wasm") },
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    {
        let mut stdin = child.stdin.take().expect("stdin was not piped");
        writeln!(stdin, "{job}").expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "a job missing its id must not fail the stream; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one result line: {stdout}");

    let result: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{}", lines[0]));
    assert_eq!(result["status"], "malformed", "got: {result}");
    assert_eq!(result["id"], "__line_1", "got: {result}");

    let error = result["error"]
        .as_str()
        .unwrap_or_else(|| panic!("malformed result must carry an error: {result}"));
    assert!(
        error.contains("missing field") && error.contains("id"),
        "error must say the `id` field is missing, got: {error}"
    );
}
