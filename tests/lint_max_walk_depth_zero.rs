// SPDX-License-Identifier: MIT

//! `lint --max-walk-depth 0` acceptance test (#772).
//!
//! With a walk budget of zero every container nest is too deep to analyze, so
//! the recursive-shape rule must report a warning. A warning is not an error:
//! without `--strict` the command still exits 0, which keeps a deliberately
//! tiny budget usable for a "report everything as unanalyzable" pass.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn max_walk_depth_zero_warns_but_exits_zero() {
    let path = wasm("v1.wasm");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .arg(&path)
        .args(["--max-walk-depth", "0"])
        .output()
        .expect("failed to run lint");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert_eq!(
        output.status.code(),
        Some(0),
        "a warning-only lint run must exit 0 without --strict.\n---stdout---\n{stdout}\n---stderr---\n{stderr}"
    );

    assert!(
        stdout.contains("unanalyzable-recursive-shape"),
        "the finding must name its rule so it can be suppressed or looked up.\n---stdout---\n{stdout}"
    );

    assert!(
        stdout.contains("exceeds the configured limit of 0"),
        "the message must name the limit that was exceeded (0).\n---stdout---\n{stdout}"
    );
}
