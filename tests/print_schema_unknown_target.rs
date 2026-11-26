// SPDX-License-Identifier: MIT

//! `print-schema --target <unknown>` acceptance test (#774).
//!
//! `--target` is a closed set (report, config, manifest, impact-graph). An
//! unknown value must fail argument parsing and list the accepted values, which
//! is how a user discovers that `impact-graph` — not `graph` — is the name.

use std::process::Command;

#[test]
fn unknown_print_schema_target_is_rejected_with_the_valid_targets_listed() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["print-schema", "--target", "bogus"])
        .output()
        .expect("failed to run print-schema");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown --target value is a usage error (exit 2).\n---stderr---\n{stderr}"
    );

    for valid in ["report", "config", "manifest", "impact-graph"] {
        assert!(
            stderr.contains(valid),
            "the error must list '{valid}' as an accepted target.\n---stderr---\n{stderr}"
        );
    }
}
