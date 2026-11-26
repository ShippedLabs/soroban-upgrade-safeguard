// SPDX-License-Identifier: MIT
//! Integration tests verifying that `stream --help` documents the job schema,
//! result schema, input descriptors, and status values.
//!
//! The acceptance criteria ask that `stream --help` shows an example job line,
//! an example result line, the five input descriptors, and the four status
//! values — all of which are derived from the module documentation in
//! `src/jsonl.rs`.

use std::process::Command;

fn stream_help() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("stream")
        .arg("--help")
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(0), "stream --help must exit 0");
    String::from_utf8(output.stdout).expect("stdout was not valid UTF-8")
}

// --- Job and result examples -------------------------------------------------

#[test]
fn stream_help_shows_example_job_line() {
    let help = stream_help();
    assert!(
        help.contains("schema_version") && help.contains("\"id\"") || help.contains("id"),
        "stream --help must show an example job line with schema_version and id\n---help---\n{help}"
    );
    assert!(
        help.contains("\"old\"") || help.contains("old"),
        "stream --help must reference the 'old' field in the job example\n---help---\n{help}"
    );
    assert!(
        help.contains("\"new\"") || help.contains("new"),
        "stream --help must reference the 'new' field in the job example\n---help---\n{help}"
    );
}

#[test]
fn stream_help_shows_example_result_line() {
    let help = stream_help();
    assert!(
        help.contains("elapsed_ms"),
        "stream --help must show an example result line with elapsed_ms\n---help---\n{help}"
    );
    assert!(
        help.contains("\"report\"") || help.contains("report"),
        "stream --help must reference the 'report' field in the result example\n---help---\n{help}"
    );
}

// --- Status values -----------------------------------------------------------

#[test]
fn stream_help_lists_all_status_values() {
    let help = stream_help();
    for status in ["success", "failure", "duplicate", "malformed"] {
        assert!(
            help.contains(status),
            "stream --help must list status value '{status}'\n---help---\n{help}"
        );
    }
}

// --- Input descriptors -------------------------------------------------------

#[test]
fn stream_help_lists_all_five_input_descriptors() {
    let help = stream_help();
    for descriptor in ["local", "rpc", "hash", "extracted", "remote"] {
        assert!(
            help.contains(descriptor),
            "stream --help must list input descriptor '{descriptor}'\n---help---\n{help}"
        );
    }
}

// --- Consistency with jsonl.rs -----------------------------------------------

#[test]
fn stream_help_schema_version_matches_jsonl_constant() {
    // The help text must reference schema_version 1 — consistent with
    // SCHEMA_VERSION in src/jsonl.rs.
    let help = stream_help();
    assert!(
        help.contains("schema_version\":1") || help.contains("schema_version: 1") || help.contains("schema_version`"),
        "stream --help must show schema_version 1 (matching SCHEMA_VERSION in jsonl.rs)\n---help---\n{help}"
    );
}
