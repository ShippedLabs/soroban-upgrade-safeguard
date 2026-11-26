// SPDX-License-Identifier: MIT
//! `stream` must flag a repeated job id as a duplicate while still processing
//! the first job normally.

use serde_json::{json, Value};
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

fn isolated_workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-stream-duplicate-job-id-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp workdir");
    dir
}

fn job_line(id: &str, wasm_path: &Path) -> String {
    json!({
        "schema_version": 1,
        "id": id,
        "old": { "local": wasm_path },
        "new": { "local": wasm_path },
    })
    .to_string()
}

#[test]
fn stream_reports_repeated_job_id_as_duplicate() {
    let workdir = isolated_workdir();
    let fixture = wasm("v1.wasm");
    let id = "repeated-job-id";
    let input = format!("{}\n{}\n", job_line(id, &fixture), job_line(id, &fixture));

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .arg("--input-order")
        .arg("--no-config")
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
        .expect("write jobs to stdin");

    let output = child.wait_with_output().expect("wait for process");
    let _ = fs::remove_dir_all(&workdir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stream must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let results: Vec<Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("result line was not valid JSON: {e}\n{line}"))
        })
        .collect();

    assert_eq!(results.len(), 2, "expected exactly two results: {stdout}");
    assert!(
        results
            .iter()
            .all(|result| result["id"].as_str() == Some(id)),
        "both results must keep the submitted job id: {stdout}"
    );

    let duplicate_count = results
        .iter()
        .filter(|result| result["status"].as_str() == Some("duplicate"))
        .count();
    let success_count = results
        .iter()
        .filter(|result| result["status"].as_str() == Some("success"))
        .count();

    assert_eq!(
        duplicate_count, 1,
        "expected exactly one duplicate result: {stdout}"
    );
    assert_eq!(
        success_count, 1,
        "expected exactly one success result: {stdout}"
    );
}
