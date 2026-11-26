// SPDX-License-Identifier: MIT
//! `--verbose` writes stage diagnostics to stderr; the default run does not.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn isolated_workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-verbose-debug-output-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp workdir");
    dir
}

/// Run an identical-pair comparison and return (stdout, stderr, exit code).
fn compare(extra_args: &[&str]) -> (String, String, Option<i32>) {
    let fixture = wasm("v1.wasm");
    let workdir = isolated_workdir();

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(&fixture)
        .arg(&fixture)
        .args(["--format", "json", "--no-config", "--no-color"])
        .args(extra_args)
        .current_dir(&workdir)
        .output()
        .expect("run soroban-upgrade-safeguard comparison");

    let _ = fs::remove_dir_all(&workdir);

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn verbose_writes_debug_diagnostics_and_default_does_not() {
    let (verbose_stdout, verbose_stderr, verbose_code) = compare(&["--verbose"]);
    assert_eq!(
        verbose_code,
        Some(0),
        "an identical comparison should succeed\nstdout:\n{verbose_stdout}\nstderr:\n{verbose_stderr}"
    );
    assert!(
        verbose_stderr.lines().any(|line| line.contains("[debug]")),
        "--verbose must write [debug] diagnostics to stderr, got:\n{verbose_stderr}"
    );

    let (plain_stdout, plain_stderr, plain_code) = compare(&[]);
    assert_eq!(
        plain_code,
        Some(0),
        "an identical comparison should succeed\nstdout:\n{plain_stdout}\nstderr:\n{plain_stderr}"
    );
    assert!(
        !plain_stderr.lines().any(|line| line.contains("[debug]")),
        "stderr must have no [debug] lines without --verbose, got:\n{plain_stderr}"
    );
}
