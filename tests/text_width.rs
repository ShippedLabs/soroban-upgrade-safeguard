//! Integration tests for `--width`: explicit, width-aware wrapping of
//! finding messages in text output. Complements the exact-line "snapshot"
//! tests in `src/render.rs` (which exercise `wrap_with_prefix` directly with
//! a fully controlled message) by covering the CLI surface: the `--width`
//! flag on the main command and on the `render` subcommand, and proof that
//! JSON and Markdown output are byte-for-byte unaffected by it.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout was not valid UTF-8")
}

// ---------------------------------------------------------------------------
// narrow / standard / wide, on the main command
// ---------------------------------------------------------------------------

#[test]
fn narrow_width_changes_output_from_the_unwrapped_default() {
    // Piped stdout (not a terminal) means no `--width` at all leaves
    // wrapping off entirely; an explicit narrow `--width` must actually
    // engage it. Every finding message in this codebase is well over the 18
    // columns available at the width-20 floor, so wrapping is guaranteed to
    // insert line breaks that aren't there otherwise.
    let default_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
    ]);
    let narrow_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
        "--width",
        "20",
    ]);

    assert_eq!(default_output.status.code(), narrow_output.status.code());
    let default_stdout = stdout_of(&default_output);
    let narrow_stdout = stdout_of(&narrow_output);
    assert_ne!(
        default_stdout, narrow_stdout,
        "--width 20 must change the rendered text"
    );
    assert!(
        narrow_stdout.lines().count() > default_stdout.lines().count(),
        "wrapping at width 20 must add line breaks; default:\n{default_stdout}\nnarrow:\n{narrow_stdout}"
    );
}

#[test]
fn narrow_width_never_leaves_a_severity_marker_alone_on_its_own_line() {
    let output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
        "--width",
        "20",
    ]);
    let stdout = stdout_of(&output);

    for marker in ["🔴", "🟡", "🔵"] {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(marker) {
                assert!(
                    trimmed.chars().count() > marker.chars().count() + 1,
                    "a severity marker must never stand alone on its own line, got: {line:?}"
                );
            }
        }
    }
}

#[test]
fn wide_width_keeps_short_reports_compact() {
    // A generous width should render the same content as no width at all
    // (piped, unwrapped) for reports whose messages fit comfortably —
    // wrapping at 500 columns is a no-op here.
    let default_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
    ]);
    let wide_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
        "--width",
        "500",
    ]);

    assert_eq!(default_output.status.code(), wide_output.status.code());
    assert_eq!(stdout_of(&default_output), stdout_of(&wide_output));
}

#[test]
fn a_width_below_the_floor_is_clamped_rather_than_rejected() {
    // MIN_TEXT_WIDTH is 20; an absurdly small explicit value must still
    // produce a well-formed report rather than failing the run.
    let output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--quiet",
        "--no-timestamp",
        "--width",
        "1",
    ]);
    let stdout = stdout_of(&output);
    assert!(output.status.code().is_some());
    assert!(stdout.contains("SOROBAN UPGRADE SAFETY REPORT"));
}

// ---------------------------------------------------------------------------
// JSON / Markdown must never be affected
// ---------------------------------------------------------------------------

#[test]
fn width_never_affects_json_output() {
    let default_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "json",
        "--no-timestamp",
    ]);
    let narrow_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "json",
        "--width",
        "20",
        "--no-timestamp",
    ]);

    assert_eq!(stdout_of(&default_output), stdout_of(&narrow_output));
}

#[test]
fn width_never_affects_markdown_output() {
    let default_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "markdown",
        "--no-timestamp",
    ]);
    let narrow_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "markdown",
        "--width",
        "20",
        "--no-timestamp",
    ]);

    assert_eq!(stdout_of(&default_output), stdout_of(&narrow_output));
}

// ---------------------------------------------------------------------------
// batch / manifest rendering
// ---------------------------------------------------------------------------

fn write_manifest(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).expect("failed to write manifest file");
    path
}

#[test]
fn narrow_width_wraps_batch_text_output_too() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );
    let manifest_path = write_manifest("text_width_batch_manifest.toml", &manifest_content);

    let default_output = run(&["--manifest", manifest_path.to_str().unwrap(), "--quiet"]);
    let narrow_output = run(&[
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--quiet",
        "--width",
        "20",
    ]);

    assert_eq!(default_output.status.code(), narrow_output.status.code());
    let default_stdout = stdout_of(&default_output);
    let narrow_stdout = stdout_of(&narrow_output);
    assert!(
        narrow_stdout.lines().count() > default_stdout.lines().count(),
        "batch text wrapping at width 20 must add line breaks; default:\n{default_stdout}\nnarrow:\n{narrow_stdout}"
    );
}

#[test]
fn width_never_affects_batch_json_output() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );
    let manifest_path = write_manifest("text_width_batch_json_manifest.toml", &manifest_content);

    let default_output = run(&[
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--format",
        "json",
        "--no-timestamp",
    ]);
    let narrow_output = run(&[
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--format",
        "json",
        "--width",
        "20",
        "--no-timestamp",
    ]);

    assert_eq!(stdout_of(&default_output), stdout_of(&narrow_output));
}

// ---------------------------------------------------------------------------
// `render` subcommand
// ---------------------------------------------------------------------------

#[test]
fn render_subcommand_supports_width() {
    let json_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "json",
    ]);
    let report_json = stdout_of(&json_output);

    let tmp = std::env::temp_dir().join(format!(
        "safeguard_width_render_test_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, &report_json).expect("failed to write report json");

    let default_render = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("render")
        .arg(&tmp)
        .output()
        .expect("failed to run render subcommand");
    let narrow_render = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("render")
        .arg(&tmp)
        .args(["--width", "20"])
        .output()
        .expect("failed to run render subcommand");

    let default_stdout = stdout_of(&default_render);
    let narrow_stdout = stdout_of(&narrow_render);
    assert!(
        narrow_stdout.lines().count() > default_stdout.lines().count(),
        "`render --width 20` must wrap; default:\n{default_stdout}\nnarrow:\n{narrow_stdout}"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn render_subcommand_width_never_affects_markdown() {
    let json_output = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--format",
        "json",
    ]);
    let report_json = stdout_of(&json_output);

    let tmp = std::env::temp_dir().join(format!(
        "safeguard_width_render_markdown_test_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, &report_json).expect("failed to write report json");

    let default_render = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("render")
        .arg(&tmp)
        .args(["--format", "markdown"])
        .output()
        .expect("failed to run render subcommand");
    let narrow_render = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("render")
        .arg(&tmp)
        .args(["--format", "markdown", "--width", "20"])
        .output()
        .expect("failed to run render subcommand");

    assert_eq!(stdout_of(&default_render), stdout_of(&narrow_render));

    let _ = std::fs::remove_file(&tmp);
}
