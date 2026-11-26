// SPDX-License-Identifier: MIT
//! Integration test: a `stream` job carrying `"overrides":{"strict":true}`
//! succeeds and produces a report whose `strict` field is `true`.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn isolated_workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-stream-overrides-strict-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp workdir");
    dir
}

fn strict_job_line(id: &str, old: &Path, new: &Path) -> String {
    serde_json::json!({
        "schema_version": 1,
        "id": id,
        "old": { "local": old.to_str().expect("fixture path is UTF-8") },
        "new": { "local": new.to_str().expect("fixture path is UTF-8") },
        "overrides": { "strict": true },
    })
    .to_string()
}

#[test]
fn stream_job_with_strict_override_reports_strict_true() {
    let fixture = wasm("v1.wasm");
    assert!(fixture.exists(), "missing fixture {}", fixture.display());

    let workdir = isolated_workdir("strict");
    let input = strict_job_line("strict-job", &fixture, &fixture) + "\n";

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .current_dir(&workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn soroban-upgrade-safeguard stream");

    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(input.as_bytes())
        .expect("write job to stdin");

    let output = child.wait_with_output().expect("wait for process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stream should exit 0 for identical fixtures\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let results: Vec<Value> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("result line was not JSON: {e}\nline: {l}"))
        })
        .collect();

    assert_eq!(
        results.len(),
        1,
        "expected exactly one result line\nstdout:\n{stdout}"
    );
    let result = &results[0];

    assert_eq!(result["id"], "strict-job", "result: {result}");
    assert_eq!(result["status"], "success", "result: {result}");
    assert_eq!(
        result["report"]["strict"],
        Value::Bool(true),
        "report.strict must reflect the job's strict override\nresult: {result}"
    );

    let _ = fs::remove_dir_all(&workdir);
}
