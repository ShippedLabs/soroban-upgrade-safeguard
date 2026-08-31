//! Regression tests for reports that omit optional provenance fields.
//!
//! Report consumers may receive older or manually generated JSON that omits
//! optional provenance fields (old_spec_summary, new_spec_summary). The
//! renderer must handle these gracefully — no panics, no invented source values.

use std::path::PathBuf;

use soroban_upgrade_safeguard::compare_wasm_files;
use soroban_upgrade_safeguard::report::SafetyReport;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn build_report_without_provenance() -> SafetyReport {
    compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed on valid fixtures")
}

#[test]
fn text_renderer_handles_missing_provenance() {
    let report = build_report_without_provenance();

    assert!(!report.is_safe, "v1 -> v2 must be flagged as unsafe");
    assert!(
        report.critical_count >= 1,
        "v1 -> v2 must report at least one critical finding"
    );

    let output = std::panic::catch_unwind(|| report.generate_summary_text(false));
    assert!(
        output.is_ok(),
        "generate_summary_text must not panic on missing provenance"
    );

    let text = output.unwrap();

    assert!(
        text.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "text output must contain report title"
    );
    assert!(
        text.contains("FAILED"),
        "text output must contain failed verdict for unsafe report"
    );
    assert!(
        text.contains("Critical"),
        "text output must list critical findings"
    );

    assert!(
        !text.contains("Baseline Source:"),
        "text output must not contain Baseline Source line when field is None"
    );
    assert!(
        !text.contains("Verified Code Hash:"),
        "text output must not contain Verified Code Hash line when field is None"
    );
}

#[test]
fn markdown_renderer_handles_missing_provenance() {
    let report = build_report_without_provenance();

    assert!(!report.is_safe, "v1 -> v2 must be flagged as unsafe");
    assert!(
        report.critical_count >= 1,
        "v1 -> v2 must report at least one critical finding"
    );

    let output = std::panic::catch_unwind(|| report.generate_summary_markdown());
    assert!(
        output.is_ok(),
        "generate_summary_markdown must not panic on missing provenance"
    );

    let markdown = output.unwrap();

    assert!(
        markdown.contains("# Soroban Upgrade Safety Report"),
        "markdown output must contain report title"
    );
    assert!(
        markdown.contains("FAILED"),
        "markdown output must contain failed verdict for unsafe report"
    );
    assert!(
        markdown.contains("**Critical**"),
        "markdown output must list critical findings"
    );

    assert!(
        !markdown.contains("**Baseline Source**"),
        "markdown output must not contain Baseline Source when field is None"
    );
    assert!(
        !markdown.contains("**Verified Code Hash**"),
        "markdown output must not contain Verified Code Hash when field is None"
    );
}

#[test]
fn safe_report_also_handles_missing_provenance() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm"))
        .expect("comparison should succeed on identical fixtures");

    assert!(report.is_safe, "identical builds must be safe");
    assert_eq!(
        report.critical_count, 0,
        "identical builds have no criticals"
    );

    let text_output = std::panic::catch_unwind(|| report.generate_summary_text(false));
    assert!(
        text_output.is_ok(),
        "text renderer must not panic on safe report without provenance"
    );
    let text = text_output.unwrap();

    assert!(
        text.contains("PASSED"),
        "safe text output must contain passed verdict"
    );
    assert!(
        !text.contains("Baseline Source:"),
        "safe text output must not fabricate provenance"
    );

    let md_output = std::panic::catch_unwind(|| report.generate_summary_markdown());
    assert!(
        md_output.is_ok(),
        "markdown renderer must not panic on safe report without provenance"
    );
    let md = md_output.unwrap();

    assert!(
        md.contains("PASSED"),
        "safe markdown output must contain passed verdict"
    );
    assert!(
        !md.contains("**Baseline Source**"),
        "safe markdown output must not fabricate provenance"
    );
}
