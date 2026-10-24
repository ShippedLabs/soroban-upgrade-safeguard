use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixture_wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("wasm")
}

fn list_wasm_fixtures() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(fixture_wasm_dir())
        .expect("tests/wasm fixture directory must exist")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|ext| ext == "wasm").unwrap_or(false))
        .collect();
    files.sort();
    files
}

fn isolated_workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-stream-input-order-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp workdir");
    assert!(
        !dir.join(".safeguard.toml").exists(),
        "workdir must not contain a .safeguard.toml"
    );
    dir
}

fn job_line(id: &str, wasm: &Path) -> String {
    format!("{{\"id\":\"{}\",\"wasm\":\"{}\"}}", id, wasm.display())
}

#[test]
fn stream_input_order_preserves_job_order() {
    let fixtures = list_wasm_fixtures();
    assert!(
        fixtures.len() >= 2,
        "need at least two wasm fixtures in tests/wasm"
    );

    let workdir = isolated_workdir("order");
    let ids = ["a", "b", "c", "d"];
    let input: String = ids
        .iter()
        .enumerate()
        .map(|(i, id)| job_line(id, &fixtures[i % fixtures.len()]) + "\n")
        .collect();

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .arg("--input-order")
        .current_dir(&workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn soroban-upgrade-safeguard stream --input-order");

    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(input.as_bytes())
        .expect("write jobs to stdin");

    let output = child.wait_with_output().expect("wait for process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stream --input-order should exit 0\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let result_ids: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
            value.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
        })
        .collect();

    assert_eq!(
        result_ids,
        vec!["a", "b", "c", "d"],
        "result ids must follow input order\nstdout:\n{}",
        stdout
    );

    let _ = fs::remove_dir_all(&workdir);
}
