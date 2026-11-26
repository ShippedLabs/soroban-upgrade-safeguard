// SPDX-License-Identifier: MIT

//! Test that --metadata-cache-stats does not report cache activity when
//! --no-metadata-cache is set.

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
fn metadata_cache_stats_with_bypass_prints_only_bypass_message() {
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg(&v1)
        .arg(&v1)
        .arg("--metadata-cache-stats")
        .arg("--no-metadata-cache")
        .output()
        .expect("failed to run with --metadata-cache-stats --no-metadata-cache");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    // Should print the bypass message
    assert!(
        stderr.contains("metadata-cache: bypassed (--no-metadata-cache)"),
        "must print bypass message, got: {stderr}"
    );

    // Should NOT print hit/miss counts
    assert!(
        !stderr.contains("hit(s)"),
        "must not print hit counts when cache is bypassed, got: {stderr}"
    );
    assert!(
        !stderr.contains("miss(es)"),
        "must not print miss counts when cache is bypassed, got: {stderr}"
    );
    assert!(
        !stderr.contains("invalidation(s)"),
        "must not print invalidation counts when cache is bypassed, got: {stderr}"
    );

    // Should NOT print cache directory summary
    assert!(
        !stderr.contains("entries in") && !stderr.contains("entry in"),
        "must not print cache directory summary when cache is bypassed, got: {stderr}"
    );
}

#[test]
fn metadata_cache_stats_without_bypass_prints_activity() {
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg(&v1)
        .arg(&v1)
        .arg("--metadata-cache-stats")
        .output()
        .expect("failed to run with --metadata-cache-stats");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    // Should print the active message
    assert!(
        stderr.contains("metadata-cache: active"),
        "must print active message, got: {stderr}"
    );

    // Should print hit/miss counts
    assert!(
        stderr.contains("hit(s)") && stderr.contains("miss(es)"),
        "must print hit/miss counts when cache is active, got: {stderr}"
    );

    // Should print cache directory summary
    assert!(
        stderr.contains("entries in")
            || stderr.contains("entry in")
            || stderr.contains("no entries in"),
        "must print cache directory summary when cache is active, got: {stderr}"
    );
}

#[test]
fn metadata_cache_stats_bypass_message_appears_before_comparison() {
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg(&v1)
        .arg(&v1)
        .arg("--metadata-cache-stats")
        .arg("--no-metadata-cache")
        .output()
        .expect("failed to run");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    // Find the position of the bypass message
    let bypass_pos = stderr
        .find("metadata-cache: bypassed")
        .expect("bypass message not found");

    // The bypass message should appear early (before comparison output)
    // Compare output typically includes "Comparing" or similar
    if let Some(compare_pos) = stderr.find("Comparing") {
        assert!(
            bypass_pos < compare_pos,
            "bypass message should appear before comparison output"
        );
    }

    // Verify no other cache-related output after the bypass message
    let bypass_message = "metadata-cache: bypassed (--no-metadata-cache)";
    let after_bypass = &stderr[bypass_pos + bypass_message.len()..];
    assert!(
        !after_bypass.contains("metadata-cache:"),
        "no other metadata-cache output should appear after bypass message, got: {stderr}"
    );
}

#[test]
fn no_metadata_cache_without_stats_flag_prints_no_cache_output() {
    let v1 = wasm("v1.wasm");

    let output = bin()
        .arg(&v1)
        .arg(&v1)
        .arg("--no-metadata-cache")
        .output()
        .expect("failed to run with --no-metadata-cache only");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    // Without --metadata-cache-stats, nothing about the cache should be printed
    assert!(
        !stderr.contains("metadata-cache:"),
        "must not print any cache messages without --metadata-cache-stats, got: {stderr}"
    );
}
