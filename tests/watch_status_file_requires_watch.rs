//! `--watch-status-file` is only meaningful alongside `--watch` (it names the
//! file that `--watch` mode updates after every cycle). clap enforces the
//! dependency via `requires = "watch"` on the argument definition, and that
//! enforcement happens during argument parsing, before any WASM is loaded or
//! any watch loop starts — so this test needs no fixtures and runs on every
//! platform, unlike the `watch`-feature-gated process tests in
//! `watch_batch.rs` / `watch_sigterm.rs`.

use std::path::PathBuf;
use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    (
        output.status.code().expect("process terminated by signal"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
    )
}

#[test]
fn watch_status_file_without_watch_is_rejected() {
    let status_file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("unused-status.json");
    let (code, stderr) = run(&["--watch-status-file", status_file.to_str().unwrap()]);

    assert_ne!(code, 0, "must be rejected without --watch: {stderr}");
    assert!(
        stderr.contains("--watch"),
        "must point at the missing flag: {stderr}"
    );
}

#[test]
fn watch_debounce_ms_without_watch_exits_2_naming_watch() {
    let (code, stderr) = run(&["--watch-debounce-ms", "500"]);

    assert_eq!(code, 2, "must be a clap usage error: {stderr}");
    assert!(
        stderr.contains("--watch"),
        "must point at the missing flag: {stderr}"
    );
}
