//! Format conformance: the structural guarantee that the three formats agree.
//!
//! The three renderers used to be independent, so keeping them in sync was a
//! matter of discipline — every new field had to be added in each format by
//! hand, and nothing failed if one was missed. Now all formats render from one
//! view model, and these tests assert the property that shape is supposed to
//! buy us:
//!
//! - Every field present in the JSON for a finding is either surfaced verbatim
//!   in *both* the text and Markdown output, or listed in an explicit,
//!   commented allow-list of transformed/omitted keys. Add a new string field to
//!   a finding and forget a format, and [`finding_fields_are_surfaced`] fails.
//! - Every top-level summary key is either surfaced or registered as a declared
//!   omission, so adding a summary field forces a decision in
//!   [`summary_fields_are_registered`].

mod common;

use std::collections::BTreeSet;

use common::{provenance_report, rich_report};
use serde_json::Value;
use soroban_upgrade_safeguard::view::{render_single_markdown, render_single_text};

/// Per-finding JSON keys intentionally NOT surfaced verbatim in the human
/// formats. Each entry is a deliberate presentation decision:
const FINDING_DECLARED: &[&str] = &[
    // Rendered as a section header, upper-cased in text — checked case-insensitively below.
    "category",
    // Rendered as a leading emoji (🔴/🟡/🔵 or the 🔕 suppression marker), never the word.
    "severity",
    // Structured, machine-only identifiers; deliberately kept out of the prose.
    "type_name",
    "target",
    // Presence-driven flags/fields, asserted explicitly below rather than verbatim.
    "suppressed",
    "suppression_reason",
    "remediation",
];

/// Top-level summary keys, each surfaced in the human formats. Every key the
/// JSON emits must appear here (or in the declared-omitted list), so a newly
/// added summary field breaks the test until a decision is recorded.
const SUMMARY_SURFACED: &[&str] = &[
    "is_safe",              // -> PASSED/FAILED status headline
    "strict",               // -> "[STRICT MODE ACTIVE]" banner / strict-aware status
    "counts",               // -> per-severity numbers
    "suppressed_count",     // -> "Suppressed" line/row when > 0
    "recommended_bump",     // -> "Recommended (SemVer) Bump"
    "baseline_source",      // -> "Baseline Source" line/row when present
    "verified_code_hash",   // -> "Verified Code Hash" line/row when present
    "findings_by_category", // -> the finding sections themselves
];
/// Summary keys that are legitimately absent from the human formats.
const SUMMARY_DECLARED_OMITTED: &[&str] = &[
    // A derived aggregate (critical + warning + info); the three parts are shown
    // individually, so the sum is redundant in prose.
    "total_findings",
];

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[test]
fn finding_fields_are_surfaced() {
    // Colored spans would embed ANSI in the text output and defeat substring
    // checks; disable color so the text is plain.
    colored::control::set_override(false);

    let report = rich_report();
    let view = report.to_view(true); // explain on, so remediation is surfaced
    let text = render_single_text(&view);
    let markdown = render_single_markdown(&view);
    let json: Value = serde_json::to_value(&view).expect("view serializes to JSON");

    let declared: BTreeSet<&str> = FINDING_DECLARED.iter().copied().collect();

    let mut checked_any = false;
    for (_category, findings) in json["findings_by_category"]
        .as_object()
        .expect("findings_by_category is an object")
    {
        for finding in findings.as_array().expect("findings is an array") {
            for (key, value) in finding.as_object().expect("finding is an object") {
                let Some(text_value) = value.as_str() else {
                    continue; // non-string scalars are covered by other checks
                };
                if declared.contains(key.as_str()) {
                    continue;
                }
                checked_any = true;
                assert!(
                    text.contains(text_value),
                    "text output is missing finding field `{key}` = {text_value:?}.\n\
                     Either surface it in render_single_text or declare it in FINDING_DECLARED."
                );
                assert!(
                    markdown.contains(text_value),
                    "markdown output is missing finding field `{key}` = {text_value:?}.\n\
                     Either surface it in render_single_markdown or declare it in FINDING_DECLARED."
                );
            }
        }
    }
    assert!(
        checked_any,
        "the representative report should have at least one verbatim finding field (message)"
    );
}

#[test]
fn transformed_and_presence_fields_are_surfaced() {
    colored::control::set_override(false);

    let report = rich_report();
    let view = report.to_view(true);
    let text = render_single_text(&view);
    let markdown = render_single_markdown(&view);

    // category -> section header (case-insensitive: text upper-cases it).
    for category in [
        "Environment",
        "Struct Field Removed",
        "Function Signature Changed",
    ] {
        assert!(
            contains_ci(&text, category),
            "text missing category `{category}`"
        );
        assert!(
            contains_ci(&markdown, category),
            "markdown missing category `{category}`"
        );
    }

    // severity -> emoji in both formats.
    for emoji in ["🔴", "🔵"] {
        assert!(text.contains(emoji), "text missing severity emoji {emoji}");
        assert!(
            markdown.contains(emoji),
            "markdown missing severity emoji {emoji}"
        );
    }

    // suppressed -> the [SUPPRESSED] marker, plus its reason.
    assert!(
        text.contains("[SUPPRESSED]"),
        "text missing suppression marker"
    );
    assert!(
        markdown.contains("[SUPPRESSED]"),
        "markdown missing suppression marker"
    );
    assert!(
        text.contains("Planned re-init for the v2 migration."),
        "text missing suppression reason"
    );
    assert!(
        markdown.contains("Planned re-init for the v2 migration."),
        "markdown missing suppression reason"
    );

    // remediation -> guidance in both formats when explain is on (this is the
    // divergence the refactor fixes: Markdown used to drop it).
    assert!(
        text.contains("↳ guidance:"),
        "text missing remediation guidance"
    );
    assert!(
        markdown.contains("↳ guidance:"),
        "markdown missing remediation guidance"
    );
}

#[test]
fn baseline_provenance_is_surfaced_in_every_format() {
    colored::control::set_override(false);

    let report = provenance_report();
    let view = report.to_view(false);
    let text = render_single_text(&view);
    let markdown = render_single_markdown(&view);
    let json: Value = serde_json::to_value(&view).expect("view serializes to JSON");

    // JSON carries the machine-readable values.
    assert_eq!(json["baseline_source"], "RPC");
    assert_eq!(
        json["verified_code_hash"],
        "deadbeefcafef00d1122334455667788990011223344556677889900aabbccddee"
    );

    // Text and Markdown both surface source and hash.
    assert!(
        text.contains("Baseline Source: RPC"),
        "text baseline source"
    );
    assert!(
        text.contains("Verified Code Hash: deadbeef"),
        "text verified hash"
    );
    assert!(
        markdown.contains("**Baseline Source**: `RPC`"),
        "markdown baseline source"
    );
    assert!(
        markdown.contains("**Verified Code Hash**: `deadbeef"),
        "markdown verified hash"
    );
}

#[test]
fn summary_fields_are_registered() {
    colored::control::set_override(false);

    let report = rich_report();
    let view = report.to_view(true);
    let json: Value = serde_json::to_value(&view).expect("view serializes to JSON");

    let emitted: BTreeSet<String> = json
        .as_object()
        .expect("top level is an object")
        .keys()
        .cloned()
        .collect();
    let registered: BTreeSet<String> = SUMMARY_SURFACED
        .iter()
        .chain(SUMMARY_DECLARED_OMITTED)
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        emitted, registered,
        "a top-level report field changed. Surface it in the text and Markdown \
         renderers and add it to SUMMARY_SURFACED, or add it to \
         SUMMARY_DECLARED_OMITTED with a reason."
    );
}

#[test]
fn summary_values_match_across_formats() {
    colored::control::set_override(false);

    let report = rich_report();
    let view = report.to_view(true);
    let text = render_single_text(&view);
    let markdown = render_single_markdown(&view);

    // Verdict: the same PASSED/FAILED word in both.
    assert!(text.contains("FAILED"), "text verdict");
    assert!(markdown.contains("FAILED"), "markdown verdict");

    // Counts: 2 critical / 0 warning / 1 info, identical in both formats.
    assert!(text.contains("Critical: 2"), "text critical count");
    assert!(
        markdown.contains("| **Critical** | 2 |"),
        "markdown critical count"
    );
    assert!(text.contains("Info:     1"), "text info count");
    assert!(markdown.contains("| **Info** | 1 |"), "markdown info count");

    // Suppression state: one suppressed finding, surfaced in both.
    assert!(text.contains("Suppressed: 1"), "text suppressed count");
    assert!(
        markdown.contains("| **Suppressed** | 1 |"),
        "markdown suppressed count"
    );

    // Recommended bump: `major`, in both.
    assert!(text.contains("Recommended Bump: major"), "text bump");
    assert!(
        markdown.contains("**Recommended SemVer Bump**: `major`"),
        "markdown bump"
    );
}

#[test]
fn category_ordering_is_identical_across_formats() {
    colored::control::set_override(false);

    let report = rich_report();
    let view = report.to_view(true);
    let text = render_single_text(&view);
    let markdown = render_single_markdown(&view);
    let json: Value = serde_json::to_value(&view).expect("view serializes to JSON");

    // The canonical order: Environment first, then alphabetical.
    let json_order: Vec<String> = json["findings_by_category"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        json_order,
        vec![
            "Environment".to_string(),
            "Function Signature Changed".to_string(),
            "Struct Field Removed".to_string(),
        ],
        "JSON must emit categories Environment-first, then alphabetical"
    );

    // Text and Markdown must present the categories in that same order.
    let text_positions: Vec<usize> = json_order
        .iter()
        .map(|c| {
            text.to_uppercase()
                .find(&c.to_uppercase())
                .unwrap_or_else(|| panic!("category {c} missing from text"))
        })
        .collect();
    assert!(
        text_positions.windows(2).all(|w| w[0] < w[1]),
        "text category order must match JSON: {text_positions:?}"
    );

    let md_positions: Vec<usize> = json_order
        .iter()
        .map(|c| {
            markdown
                .find(&format!("### {c}"))
                .unwrap_or_else(|| panic!("category {c} missing from markdown"))
        })
        .collect();
    assert!(
        md_positions.windows(2).all(|w| w[0] < w[1]),
        "markdown category order must match JSON: {md_positions:?}"
    );
}
