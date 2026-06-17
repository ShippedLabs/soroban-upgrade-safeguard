//! Integration tests for plain text output without ANSI color codes.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn contains_ansi(text: &str) -> bool {
    text.contains('\u{1b}')
}

#[test]
fn no_color_flag_strips_ansi_from_text_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--no-color")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        output.status.code() == Some(1),
        "breaking fixture should still exit 1; stderr:\n{stderr}"
    );
    assert!(
        !contains_ansi(&stdout),
        "--no-color output must not contain ANSI escape codes:\n{stdout}"
    );
}

#[test]
fn no_color_environment_strips_ansi_from_text_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        output.status.code() == Some(1),
        "breaking fixture should still exit 1; stderr:\n{stderr}"
    );
    assert!(
        !contains_ansi(&stdout),
        "NO_COLOR output must not contain ANSI escape codes:\n{stdout}"
    );
}

#[test]
fn captured_text_output_is_plain_without_explicit_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(
        output.status.code() == Some(1),
        "breaking fixture should still exit 1; stderr:\n{stderr}"
    );
    assert!(
        !contains_ansi(&stdout),
        "captured text output must not contain ANSI escape codes:\n{stdout}"
    );
}
