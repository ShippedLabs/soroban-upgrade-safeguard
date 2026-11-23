//! `--per-contract-output-name-template` only takes effect together with
//! `--per-contract-output-dir`. clap enforces the dependency during argument
//! parsing, so this test needs no fixtures.

use std::process::Command;

#[test]
fn name_template_without_output_dir_exits_2_naming_the_dir_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--per-contract-output-name-template", "{name}_x.{ext}"])
        .output()
        .expect("failed to run binary");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert_eq!(output.status.code(), Some(2), "must be a usage error: {stderr}");
    assert!(
        stderr.contains("--per-contract-output-dir"),
        "must name the missing flag: {stderr}"
    );
}
