//! Integration tests for the `lint` subcommand CLI surface.

use std::process::Command;

fn lint(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .args(args)
        .output()
        .expect("failed to run lint subcommand")
}

#[test]
fn lint_errors_clearly_when_no_input_is_given() {
    let output = lint(&[]);

    assert!(
        !output.status.success(),
        "lint with neither a WASM path nor an RPC source must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    assert!(
        stderr.contains("Missing WASM path"),
        "error must clearly state that the WASM path is missing. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--contract-id"),
        "error must mention the RPC alternative (--contract-id). stderr:\n{stderr}"
    );
}
