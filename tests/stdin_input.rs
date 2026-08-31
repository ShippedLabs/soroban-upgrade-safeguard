use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_with_stdin(args: &[String], stdin_bytes: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    let mut stdin = child.stdin.take().expect("stdin should be piped");
    stdin.write_all(stdin_bytes).expect("failed to write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("failed to wait on binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    (code, stdout, stderr)
}

#[test]
fn dash_reads_new_wasm_from_stdin() {
    let bytes = std::fs::read(wasm("v1.wasm")).expect("read fixture");
    let args = vec![
        wasm("v1.wasm").display().to_string(),
        "-".to_string(),
        "--quiet".to_string(),
    ];

    let (code, stdout, stderr) = run_with_stdin(&args, &bytes);

    assert_eq!(code, 0, "identical upgrade should pass");
    assert!(
        stdout.contains("Status:"),
        "stdin input should still produce a report"
    );
    assert!(
        stdout.contains("Recommended Bump:"),
        "stdin input should run the normal report path"
    );
    assert!(
        stderr.is_empty(),
        "valid stdin input should not emit errors"
    );
}

#[test]
fn dash_for_both_wasm_positions_is_rejected() {
    let args = vec!["-".to_string(), "-".to_string(), "--quiet".to_string()];

    let (code, _stdout, stderr) = run_with_stdin(&args, &[]);

    assert_ne!(code, 0, "using stdin twice must fail");
    assert!(
        stderr.contains("stdin can only be read once"),
        "error should explain why '-' cannot be used twice: {stderr}"
    );
}

#[test]
fn invalid_stdin_wasm_uses_validation_error() {
    let args = vec![
        wasm("v1.wasm").display().to_string(),
        "-".to_string(),
        "--quiet".to_string(),
    ];

    let (code, _stdout, stderr) = run_with_stdin(&args, b"not wasm");

    assert_ne!(code, 0, "invalid stdin data must fail");
    assert!(
        stderr.contains("WASM validation error"),
        "invalid stdin should use the WASM validation error path: {stderr}"
    );
}
