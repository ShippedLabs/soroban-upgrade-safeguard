// SPDX-License-Identifier: MIT
//! Regression test for `lint --format markdown` on a spec with no findings.
//!
//! `lint tests/wasm/v1.wasm --format markdown` is meant to print the clean
//! banner (`**No lint findings.**`) and exit `0`. PR-comment pipelines render
//! this Markdown directly, so a silent empty document or a non-zero exit would
//! be a regression. This test pins that behaviour by spawning the built binary,
//! as `extract_subcommand.rs` does.

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

#[test]
fn lint_markdown_reports_a_clean_spec() {
    let path = wasm("v1.wasm");
    let output = bin()
        .arg("lint")
        .arg(&path)
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("failed to run the lint subcommand");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert_eq!(
        output.status.code(),
        Some(0),
        "a clean spec must lint successfully\n---stdout---\n{stdout}"
    );
    assert!(
        stdout.contains("No lint findings"),
        "markdown output must report a clean spec, got:\n{stdout}"
    );
    assert!(
        stdout.contains("**No lint findings.**"),
        "the clean banner must be Markdown-formatted, got:\n{stdout}"
    );
}
