//! Integration regression test for CLI `--help` flag exit status.

use std::process::Command;

#[test]
fn help_flag_exits_successfully_without_inputs() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--help")
        .output()
        .expect("failed to run binary with --help");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--help must exit with status code 0 without loading files"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(
        stdout.contains("soroban-upgrade-safeguard"),
        "stdout must contain the program name. Output:\n{stdout}"
    );

    assert!(
        stdout.contains("Usage:")
            || stdout.contains("USAGE:")
            || stdout.contains("soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>"),
        "stdout must contain at least one usage form. Output:\n{stdout}"
    );
}
