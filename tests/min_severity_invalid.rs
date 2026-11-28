// SPDX-License-Identifier: MIT
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

/// `--min-severity bogus` is rejected by clap with exit code 2 and
/// the accepted set on stderr, so a scripted user can fix a typo without
/// re-running `--help`.
#[test]
fn rejects_an_unknown_min_severity() {
    let output = bin()
        .args(["--min-severity", "bogus"])
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap must exit 2 on an invalid --min-severity value",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bogus"),
        "stderr should quote the invalid value, got: {stderr}",
    );
    for expected in ["info", "warning", "critical"] {
        assert!(
            stderr.contains(expected),
            "stderr should list {expected} as a possible value, got: {stderr}",
        );
    }
}
