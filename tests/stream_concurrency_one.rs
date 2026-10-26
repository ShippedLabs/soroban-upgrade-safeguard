//! A single stream worker must still return one result for each input job.

use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn stream_concurrency_one_processes_every_job_without_config() {
    let working_dir = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-stream-concurrency-one-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&working_dir);
    std::fs::create_dir_all(&working_dir).expect("failed to create temporary working directory");
    assert!(!working_dir.join(".safeguard.toml").exists());

    let wasm_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm");
    let jobs = ["job-one", "job-two", "job-three"];
    let input = jobs
        .iter()
        .map(|id| {
            format!(
                r#"{{"schema_version":1,"id":"{id}","old":{{"local":"{}"}},"new":{{"local":"{}"}}}}"#,
                wasm_dir.join("v1.wasm").display(),
                wasm_dir.join("v3.wasm").display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["stream", "--concurrency", "1"])
        .current_dir(&working_dir)
        .env_remove("SOROBAN_SAFEGUARD_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start stream command");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(input.as_bytes())
        .expect("failed to write stream jobs");
    let output = child
        .wait_with_output()
        .expect("failed to wait for stream command");

    let _ = std::fs::remove_dir_all(&working_dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stream should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        jobs.len(),
        "stdout should contain one line per job"
    );

    let mut result_ids = Vec::new();
    for line in lines {
        let result: Value = serde_json::from_str(line).expect("each output line should be JSON");
        assert_eq!(
            result["status"], "success",
            "job result should succeed: {line}"
        );
        result_ids.push(
            result["id"]
                .as_str()
                .expect("each result should contain its job id")
                .to_owned(),
        );
    }
    assert_eq!(result_ids, jobs.map(str::to_owned));
}
