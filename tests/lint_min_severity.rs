use std::process::Command;

#[test]
fn lint_help_lists_minimum_severity() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["lint", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--min-severity"));
    assert!(help.contains("warning"));
}
