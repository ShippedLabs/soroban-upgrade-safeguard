//! Smoke tests for the commands shown in the README.
//!
//! The README shows many commands as documentation, not as tests — nothing
//! stops one of them drifting from the actual CLI (a renamed flag, a moved
//! subcommand) without anyone noticing until a user copy-pastes it and it
//! fails. This file runs a small, representative set of README examples
//! against the checked-in fixtures and asserts on the outcomes the README
//! itself describes, so that kind of drift fails CI instead.
//!
//! It is not a full transcription of the README — commands that need
//! network access (RPC baseline mode), a signing key (attest/verify), or an
//! interactive/long-running process (watch mode) are out of scope for a
//! fixture-based smoke test.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn tmp(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "readme-smoke-{}-{}",
        std::process::id(),
        name
    ))
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(configure: impl FnOnce(&mut Command)) -> Run {
    let mut cmd = bin();
    configure(&mut cmd);
    let output = cmd.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code().expect("process terminated by signal"),
    }
}

/// README: "Compare two WASM contract builds to see if the upgrade is safe"
#[test]
fn readme_basic_comparison_reports_the_known_breaking_upgrade() {
    let result = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .arg("--no-color");
    });

    assert_eq!(result.code, 1, "v1 -> v2 is a known breaking upgrade");
    assert!(
        result.stdout.contains("Critical breaking changes detected"),
        "text report should surface the breaking verdict, got: {}",
        result.stdout
    );
}

/// README: "Inspecting a single build" — `extract` as JSON.
#[test]
fn readme_extract_emits_decoded_interface_json() {
    let result = run(|cmd| {
        cmd.arg("extract").arg(wasm("v1.wasm"));
    });

    assert_eq!(result.code, 0, "extract on a valid fixture must succeed");
    let json: serde_json::Value = serde_json::from_str(&result.stdout)
        .unwrap_or_else(|e| panic!("extract stdout was not valid JSON: {e}\n{}", result.stdout));
    assert!(
        json["spec_schema_version"].is_number(),
        "extract output should carry a spec_schema_version field"
    );
}

/// README: "Just the interface hash, for scripting and cache keys"
#[test]
fn readme_extract_hash_only_emits_a_bare_sha256() {
    let result = run(|cmd| {
        cmd.arg("extract").arg(wasm("v1.wasm")).arg("--hash-only");
    });

    assert_eq!(result.code, 0);
    let hash = result.stdout.trim();
    assert_eq!(
        hash.len(),
        64,
        "--hash-only should print a bare 64-char hex SHA-256, got: {hash:?}"
    );
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "hash-only output should be pure hex, got: {hash:?}"
    );
}

/// README: "Pinning an interface with a lockfile" — generate, then gate a
/// candidate build against the committed lockfile.
#[test]
fn readme_lockfile_generate_and_gate_round_trip() {
    let lockfile = tmp("readme-lockfile.json");

    let generate = run(|cmd| {
        cmd.arg("lockfile")
            .arg(wasm("v1.wasm"))
            .args(["--output", lockfile.to_str().unwrap()]);
    });
    assert_eq!(
        generate.code, 0,
        "lockfile generation should succeed: {}",
        generate.stderr
    );
    assert!(
        lockfile.exists(),
        "lockfile command should write its output file"
    );

    // The same build's interface must match the lockfile it was generated from.
    let gate = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .args(["--interface-lockfile", lockfile.to_str().unwrap()])
            .args(["--format", "json"]);
    });
    assert_eq!(
        gate.code, 0,
        "a build must pass its own freshly generated lockfile: {}",
        gate.stdout
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// README: "Re-rendering a saved report" — piping a JSON report from a live
/// run into `render` via stdin, and asserting it matches the same run in
/// `--format text` directly.
#[test]
fn readme_render_from_stdin_matches_a_live_text_run() {
    let live_json = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .arg("--no-color")
        .arg("--no-timestamp")
        .output()
        .expect("failed to run binary");
    let report_json =
        String::from_utf8(live_json.stdout).expect("json report stdout was not valid UTF-8");

    let live_text = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "text"])
        .arg("--no-color")
        .arg("--no-timestamp")
        .output()
        .expect("failed to run binary");
    let live_text_stdout =
        String::from_utf8(live_text.stdout).expect("text stdout was not valid UTF-8");
    // A live run prefixes decorative progress lines (banner, per-file
    // loading) ahead of the report body; `render` has no WASM to load, so it
    // only ever reproduces the body itself, starting at the banner rule.
    let body_start = live_text_stdout
        .find("========================================")
        .expect("live text output should contain the report banner");
    let expected_text = &live_text_stdout[body_start..];

    let mut child = bin()
        .arg("render")
        .arg("-")
        .args(["--format", "text"])
        .arg("--no-color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn render");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(report_json.as_bytes())
        .expect("failed to write report to render's stdin");
    let rendered = child.wait_with_output().expect("failed to wait for render");
    let rendered_text =
        String::from_utf8(rendered.stdout).expect("render stdout was not valid UTF-8");

    assert!(
        rendered_text.contains(expected_text),
        "render - should reproduce the equivalent live run's report body"
    );
}

/// README: "Quiet output" — the report survives, progress narration doesn't.
#[test]
fn readme_quiet_still_gates_on_json_with_no_narration() {
    let result = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .args(["--format", "json"])
            .arg("--quiet");
    });

    assert_eq!(
        result.code, 1,
        "quiet must not change the verdict/exit code"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&result.stdout).is_ok(),
        "stdout should be clean JSON with no narration mixed in"
    );
    assert!(
        result.stderr.trim().is_empty(),
        "--quiet should silence progress narration on stderr, got: {}",
        result.stderr
    );
}

/// README: "Multiple output formats" — write JSON and Markdown to separate
/// files in one run.
#[test]
fn readme_multiple_output_formats_writes_each_destination() {
    let json_path = tmp("readme-multi.json");
    let md_path = tmp("readme-multi.md");

    let result = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .arg("--output")
            .arg(format!("json:{}", json_path.display()))
            .arg("--output")
            .arg(format!("markdown:{}", md_path.display()));
    });

    assert_eq!(result.code, 1, "still gates on the known breaking upgrade");
    assert!(json_path.exists(), "json destination should be written");
    assert!(md_path.exists(), "markdown destination should be written");

    let json_content = std::fs::read_to_string(&json_path).expect("failed to read json output");
    assert!(
        serde_json::from_str::<serde_json::Value>(&json_content).is_ok(),
        "json destination should contain valid JSON"
    );
    let md_content = std::fs::read_to_string(&md_path).expect("failed to read markdown output");
    assert!(
        !md_content.trim().is_empty(),
        "markdown destination should be non-empty"
    );

    let _ = std::fs::remove_file(&json_path);
    let _ = std::fs::remove_file(&md_path);
}

/// README: "Deterministic output for snapshot testing" — `--no-timestamp`
/// blanks the timestamp in report provenance.
#[test]
fn readme_no_timestamp_blanks_provenance_timestamp() {
    let result = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .args(["--format", "json"])
            .arg("--no-timestamp");
    });

    let json: serde_json::Value = serde_json::from_str(&result.stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n{}", result.stdout));
    let timestamp = json["provenance"]["timestamp"].as_str().unwrap_or("");
    assert!(
        timestamp.is_empty(),
        "--no-timestamp should blank provenance.timestamp, got: '{timestamp}'"
    );
}

/// README: "Ignoring configuration entirely" — `--no-config` still runs the
/// comparison on the tool's own rules.
#[test]
fn readme_no_config_flag_is_accepted_and_still_gates() {
    let result = run(|cmd| {
        cmd.arg(wasm("v1.wasm"))
            .arg(wasm("v2.wasm"))
            .arg("--no-config");
    });

    assert_eq!(
        result.code, 1,
        "--no-config must still run the comparison and gate on findings"
    );
}
