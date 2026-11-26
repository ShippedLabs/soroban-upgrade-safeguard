// SPDX-License-Identifier: MIT
//! Integration tests for the `lint` subcommand's `--output` flag.
//!
//! `lint` always printed to stdout. CI jobs that need to archive the result as
//! a file had to redirect stdout, which also captures any progress text. With
//! `--output`, the rendered result goes to the file and stdout stays silent,
//! consistent with how `extract` and `upgrade-report` already behave.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn tmp(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// Run `lint` with the given args, returning (stdout, exit_code).
fn lint(args: &[&str]) -> (String, i32) {
    let output = bin()
        .arg("lint")
        .args(args)
        .output()
        .expect("failed to run binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

// --- --output flag -----------------------------------------------------------

#[test]
fn lint_output_flag_appears_in_help() {
    let output = bin()
        .arg("lint")
        .arg("--help")
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--output"),
        "--output must appear in `lint --help`\n---stdout---\n{stdout}"
    );
}

#[test]
fn lint_output_json_writes_to_file_not_stdout() {
    let out = tmp("lint_output_json.json");
    let wasm_path = wasm("v1.wasm");

    let (stdout, code) = lint(&[
        wasm_path.to_str().unwrap(),
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "a valid WASM must lint without errors");

    // stdout must be empty — result went to the file.
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used, got: {stdout}"
    );

    // File must exist and contain valid JSON.
    assert!(out.exists(), "output file must be created");
    let contents = std::fs::read_to_string(&out).expect("failed to read output file");
    let json: serde_json::Value = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("output file not valid JSON: {e}\n{contents}"));
    assert!(
        json.get("findings").is_some() || json.get("errors").is_some() || json.is_object(),
        "output must be a JSON object"
    );
}

#[test]
fn lint_output_markdown_writes_to_file_not_stdout() {
    let out = tmp("lint_output_markdown.md");
    let wasm_path = wasm("v1.wasm");

    let (stdout, code) = lint(&[
        wasm_path.to_str().unwrap(),
        "--format",
        "markdown",
        "--output",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "a valid WASM must lint without errors");
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used"
    );

    let contents = std::fs::read_to_string(&out).expect("failed to read output file");
    assert!(!contents.is_empty(), "output file must not be empty");
}

#[test]
fn lint_output_text_writes_to_file_not_stdout() {
    let out = tmp("lint_output_text.txt");
    let wasm_path = wasm("v1.wasm");

    let (stdout, code) = lint(&[
        wasm_path.to_str().unwrap(),
        "--format",
        "text",
        "--output",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "a valid WASM must lint without errors");
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used"
    );

    let contents = std::fs::read_to_string(&out).expect("failed to read output file");
    assert!(!contents.is_empty(), "output file must not be empty");
}

#[test]
fn lint_without_output_flag_still_prints_to_stdout() {
    let wasm_path = wasm("v1.wasm");
    let (stdout, code) = lint(&[wasm_path.to_str().unwrap(), "--format", "json"]);

    assert_eq!(code, 0);
    assert!(
        !stdout.trim().is_empty(),
        "without --output the result must go to stdout"
    );
    // Must be valid JSON.
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n{stdout}"));
}

#[test]
fn lint_output_exit_code_unchanged() {
    // Exit code must reflect the lint verdict regardless of --output.
    // v1.wasm is a well-formed fixture; lint must exit 0.
    let out = tmp("lint_exit_code.json");
    let wasm_path = wasm("v1.wasm");

    let (_stdout, code) = lint(&[
        wasm_path.to_str().unwrap(),
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
    ]);

    assert_eq!(
        code, 0,
        "exit code must be 0 for a clean lint even with --output"
    );
}

#[test]
fn lint_output_overwrites_existing_file_atomically() {
    let out = tmp("lint_overwrite.json");
    // Write sentinel content first.
    std::fs::write(&out, b"old content").expect("failed to write sentinel");

    let wasm_path = wasm("v1.wasm");
    let (_, code) = lint(&[
        wasm_path.to_str().unwrap(),
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 0);
    let contents = std::fs::read_to_string(&out).expect("failed to read output file");
    // Old content must be gone.
    assert!(
        !contents.contains("old content"),
        "output file must be overwritten, not appended to"
    );
    // New content must be valid JSON.
    serde_json::from_str::<serde_json::Value>(&contents)
        .unwrap_or_else(|e| panic!("overwritten file must be valid JSON: {e}"));
}
