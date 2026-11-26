// SPDX-License-Identifier: MIT
//! `stream` reports an unparseable job line as a `malformed` result rather
//! than aborting, so one bad line cannot take down a long-running pipeline.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn stream_reports_a_malformed_json_line_as_a_malformed_result() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-stream-malformed-{}",
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

    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(b"{\"bad json\n")
        .expect("failed to write to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a malformed line must not fail the stream"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one result line: {stdout}");

    let result: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{}", lines[0]));
    assert_eq!(result["status"], "malformed");
    assert_eq!(result["id"], "__line_1");
}
