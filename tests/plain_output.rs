//! Integration tests for the `--plain` flag: a single switch that disables
//! color, Unicode markers, and decorative separators together, for log
//! processors that can't handle any of the three. Covers stdout, file
//! output (`--output`), and batch/manifest rendering, and confirms report
//! content (severity, messages, scope, remediation) survives unchanged.

use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::report::plainify;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Decorative characters `--plain` must remove from report content: color
/// escapes, emoji/Unicode status markers, the guidance arrow, and the
/// box-drawing separator.
const DECORATIVE_CHARS: [char; 10] = [
    '\u{1b}', // ANSI escape
    '↳', '─', // guidance arrow, box-drawing separator
    '🔴', '🟡', '🔵', '✅', '❌', '⚠', '🔕',
];

fn assert_no_decoration(text: &str, context: &str) {
    for ch in DECORATIVE_CHARS {
        assert!(
            !text.contains(ch),
            "{context} must not contain decorative character {ch:?}. Output:\n{text}"
        );
    }
}

fn write_manifest(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).expect("failed to write manifest file");
    path
}

// ---------------------------------------------------------------------------
// Unit-level: report::plainify
// ---------------------------------------------------------------------------

#[test]
fn plainify_converts_markers_and_strips_decorative_unicode() {
    // 🔕 is always emitted as a prefix immediately before the literal text
    // "[SUPPRESSED]" (see render.rs); asciify_markers strips the redundant
    // emoji rather than inserting the bracketed label itself in that case.
    let input = "🔴 critical\n🟡 warn\n🔵 info\n✅ pass\n❌ fail\n⚠️ warning\n\
                 🔕 [SUPPRESSED] finding\n    ↳ guidance: fix it\n────────\n";
    let out = plainify(input);
    assert_no_decoration(&out, "plainify output");
    assert!(out.contains("[CRITICAL]"));
    assert!(out.contains("[WARN]"));
    assert!(out.contains("[INFO]"));
    assert!(out.contains("[PASS]"));
    assert!(out.contains("[FAIL]"));
    assert!(out.contains("[WARNING]"));
    assert!(out.contains("[SUPPRESSED] finding"));
    assert!(out.contains("-> guidance: fix it"));
    assert!(out.contains("--------"));
}

#[test]
fn plainify_converts_a_standalone_suppressed_marker_too() {
    // A bare 🔕 with no trailing space (not the "🔕 " prefix form above)
    // converts to the bracketed label directly.
    let out = plainify("🔕\n");
    assert_no_decoration(&out, "plainify output");
    assert!(out.contains("[SUPPRESSED]"));
}

#[test]
fn plainify_is_a_no_op_on_already_plain_text() {
    let input = "[CRITICAL] Struct 'X': field removed.\n-> guidance: restore the field.\n";
    assert_eq!(plainify(input), input);
}

// ---------------------------------------------------------------------------
// stdout
// ---------------------------------------------------------------------------

#[test]
fn plain_stdout_text_report_is_fully_decoration_free() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--plain", "--explain", "--quiet"])
        .env("CLICOLOR_FORCE", "1") // try to force color; --plain must still win
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert_eq!(output.status.code(), Some(1), "breaking upgrade exits 1");
    assert_no_decoration(&stdout, "--plain --quiet stdout");

    // Content must survive: severity markers, scope, remediation guidance.
    assert!(
        stdout.contains("[CRITICAL]") || stdout.contains("[FAIL]"),
        "severity markers must remain, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Analysis scope:"),
        "scope line must remain, got:\n{stdout}"
    );
    assert!(
        stdout.contains("-> guidance:"),
        "remediation guidance must remain (as plain text), got:\n{stdout}"
    );
    assert!(
        stdout.contains("Critical:") && stdout.contains("Warnings:") && stdout.contains("Info:"),
        "severity counts must remain, got:\n{stdout}"
    );
}

#[test]
fn plain_stdout_markdown_report_is_fully_decoration_free() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--plain", "--explain", "--format", "markdown"])
        .output()
        .expect("failed to run binary");

    // Markdown to stdout already routes progress to stderr, so no --quiet needed.
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert_no_decoration(&stdout, "--plain markdown stdout");
    assert!(stdout.contains("Soroban Upgrade Safety Report"));
}

#[test]
fn plain_report_body_is_decoration_free_even_without_quiet() {
    // Without --quiet, decorative *progress* lines (unaffected by --plain,
    // matching --ascii's existing precedent) still appear on stdout for the
    // default text format. The report body itself, though, must still be
    // fully plain. Isolate the body by its banner.
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--plain", "--explain"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let body = stdout
        .split("SOROBAN UPGRADE SAFETY REPORT")
        .nth(1)
        .expect("report banner must be present");
    assert_no_decoration(body, "--plain report body");
}

// ---------------------------------------------------------------------------
// file output (--output)
// ---------------------------------------------------------------------------

#[test]
fn plain_file_output_is_fully_decoration_free() {
    let tmp =
        std::env::temp_dir().join(format!("safeguard_plain_file_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let text_path = tmp.join("report.txt");
    let md_path = tmp.join("report.md");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--plain", "--explain"])
        .args(["--output", &format!("text:{}", text_path.display())])
        .args(["--output", &format!("markdown:{}", md_path.display())])
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(1));

    let text_content = std::fs::read_to_string(&text_path).expect("text report should exist");
    assert_no_decoration(&text_content, "plain text file output");
    assert!(text_content.contains("[CRITICAL]") || text_content.contains("[FAIL]"));
    assert!(text_content.contains("-> guidance:"));

    let md_content = std::fs::read_to_string(&md_path).expect("markdown report should exist");
    assert_no_decoration(&md_content, "plain markdown file output");

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// batch / manifest rendering
// ---------------------------------------------------------------------------

#[test]
fn plain_batch_rendering_is_fully_decoration_free_on_stdout() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );
    let manifest_path = write_manifest("plain_batch_manifest.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--plain", "--quiet"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert_eq!(output.status.code(), Some(1));
    assert_no_decoration(&stdout, "--plain --quiet batch stdout");

    assert!(stdout.contains("SOROBAN BATCH SAFETY REPORT"));
    assert!(stdout.contains("clean_contract"));
    assert!(stdout.contains("breaking_contract"));
    assert!(
        stdout.contains("[PASS]") || stdout.contains("PASSED"),
        "batch summary must still report pass/fail status, got:\n{stdout}"
    );
}

#[test]
fn plain_batch_file_output_is_fully_decoration_free() {
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
    let manifest_path = write_manifest("plain_batch_manifest_file.toml", &manifest_content);

    let tmp = std::env::temp_dir().join(format!(
        "safeguard_plain_batch_file_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let out_path = tmp.join("batch_report.txt");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--plain")
        .args(["--output", &format!("text:{}", out_path.display())])
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(1));

    let content = std::fs::read_to_string(&out_path).expect("batch report file should exist");
    assert_no_decoration(&content, "plain batch file output");
    assert!(content.contains("breaking_contract"));

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// interaction with --color / --ascii
// ---------------------------------------------------------------------------

#[test]
fn plain_overrides_color_always() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--plain", "--color", "always", "--quiet"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        !stdout.contains('\u{1b}'),
        "--plain must force color off even with --color always. Output:\n{stdout}"
    );
}

#[test]
fn render_subcommand_supports_plain() {
    // First, produce a saved JSON report.
    let json_output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--explain"])
        .output()
        .expect("failed to run binary");
    let report_json =
        String::from_utf8(json_output.stdout).expect("json report stdout was not valid UTF-8");

    let tmp = std::env::temp_dir().join(format!(
        "safeguard_plain_render_test_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, &report_json).expect("failed to write report json");

    let render_output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("render")
        .arg(&tmp)
        .args(["--explain", "--plain"])
        .output()
        .expect("failed to run render subcommand");

    let stdout = String::from_utf8(render_output.stdout).expect("stdout was not valid UTF-8");
    assert_no_decoration(&stdout, "render --plain stdout");
    assert!(stdout.contains("[CRITICAL]") || stdout.contains("[FAIL]"));

    let _ = std::fs::remove_file(&tmp);
}
