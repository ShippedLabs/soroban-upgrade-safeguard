//! Snapshot coverage for every renderer, single-pair and batch, in each format.
//!
//! These lock the exact rendered output so an unintended change to any format is
//! caught in review (via `cargo insta review`). Color is disabled so the text
//! snapshots are stable and readable. Edge cases are covered explicitly: a report
//! with zero findings, a fully suppressed report, a warning-only strict report,
//! baseline provenance (RPC source + verified hash), a single-pair batch, a batch
//! with a failed pair, and a batch whose contract name contains a pipe character
//! that would otherwise break the Markdown summary table.

mod common;

use std::collections::BTreeMap;

use common::{
    all_suppressed_report, batch_results, empty_report, provenance_report, report_from,
    rich_report, strict_warning_report,
};
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::view::{
    render_batch_json, render_batch_markdown, render_batch_text, render_single_json,
    render_single_markdown, render_single_text, BatchReportView, PairFailureInfo,
};

/// Disable ANSI color so text snapshots are plain and deterministic.
fn plain() {
    colored::control::set_override(false);
}

// ----- single-pair: text -----

#[test]
fn snapshot_single_text_rich() {
    plain();
    insta::assert_snapshot!(
        "single_text_rich",
        render_single_text(&rich_report().to_view(true))
    );
}

#[test]
fn snapshot_single_text_empty() {
    plain();
    insta::assert_snapshot!(
        "single_text_empty",
        render_single_text(&empty_report().to_view(false))
    );
}

#[test]
fn snapshot_single_text_all_suppressed() {
    plain();
    insta::assert_snapshot!(
        "single_text_all_suppressed",
        render_single_text(&all_suppressed_report().to_view(false))
    );
}

#[test]
fn snapshot_single_text_strict_warning() {
    plain();
    insta::assert_snapshot!(
        "single_text_strict_warning",
        render_single_text(&strict_warning_report().to_view(false))
    );
}

#[test]
fn snapshot_single_text_provenance() {
    plain();
    insta::assert_snapshot!(
        "single_text_provenance",
        render_single_text(&provenance_report().to_view(false))
    );
}

// ----- single-pair: markdown -----

#[test]
fn snapshot_single_markdown_rich() {
    plain();
    insta::assert_snapshot!(
        "single_markdown_rich",
        render_single_markdown(&rich_report().to_view(true))
    );
}

#[test]
fn snapshot_single_markdown_empty() {
    plain();
    insta::assert_snapshot!(
        "single_markdown_empty",
        render_single_markdown(&empty_report().to_view(false))
    );
}

#[test]
fn snapshot_single_markdown_strict_warning() {
    plain();
    insta::assert_snapshot!(
        "single_markdown_strict_warning",
        render_single_markdown(&strict_warning_report().to_view(false))
    );
}

#[test]
fn snapshot_single_markdown_provenance() {
    plain();
    insta::assert_snapshot!(
        "single_markdown_provenance",
        render_single_markdown(&provenance_report().to_view(false))
    );
}

// ----- single-pair: json -----

#[test]
fn snapshot_single_json_rich() {
    let json = render_single_json(&rich_report().to_view(true)).expect("json renders");
    insta::assert_snapshot!("single_json_rich", json);
}

#[test]
fn snapshot_single_json_empty() {
    let json = render_single_json(&empty_report().to_view(false)).expect("json renders");
    insta::assert_snapshot!("single_json_empty", json);
}

#[test]
fn snapshot_single_json_provenance() {
    let json = render_single_json(&provenance_report().to_view(false)).expect("json renders");
    insta::assert_snapshot!("single_json_provenance", json);
}

// ----- batch -----

fn two_pair_batch() -> BTreeMap<String, SafetyReport> {
    batch_results(vec![
        ("clean_contract", empty_report()),
        ("breaking_contract", rich_report()),
    ])
}

fn no_failures() -> BTreeMap<String, PairFailureInfo> {
    BTreeMap::new()
}

#[test]
fn snapshot_batch_text() {
    plain();
    let results = two_pair_batch();
    let failed = no_failures();
    let view = BatchReportView::new(&results, &failed, false, 2, false);
    insta::assert_snapshot!("batch_text", render_batch_text(&view));
}

#[test]
fn snapshot_batch_markdown() {
    plain();
    let results = two_pair_batch();
    let failed = no_failures();
    let view = BatchReportView::new(&results, &failed, false, 2, false);
    insta::assert_snapshot!("batch_markdown", render_batch_markdown(&view));
}

#[test]
fn snapshot_batch_json() {
    let results = two_pair_batch();
    let failed = no_failures();
    let view = BatchReportView::new(&results, &failed, false, 2, false);
    let json = render_batch_json(&view).expect("json renders");
    insta::assert_snapshot!("batch_json", json);
}

#[test]
fn snapshot_batch_single_pair() {
    // Edge case: a batch run with exactly one pair still uses the batch layout.
    plain();
    let results = batch_results(vec![("only_contract", rich_report())]);
    let failed = no_failures();
    let view = BatchReportView::new(&results, &failed, false, 1, false);
    insta::assert_snapshot!("batch_text_single_pair", render_batch_text(&view));
}

#[test]
fn snapshot_batch_with_failures() {
    // Edge case: a batch where one pair compared and one failed (a resource
    // limit) — exercises the failed-pair rows, the "Errored Pairs" section, and
    // the limit_violation flag.
    plain();
    let results = batch_results(vec![("breaking_contract", rich_report())]);
    let mut failed = BTreeMap::new();
    failed.insert(
        "broken_pair".to_string(),
        PairFailureInfo {
            message: "resource limit exceeded: max_xdr_depth (64)".to_string(),
            is_limit: true,
        },
    );
    let view = BatchReportView::new(&results, &failed, false, 2, false);
    insta::assert_snapshot!("batch_text_with_failures", render_batch_text(&view));
    insta::assert_snapshot!("batch_markdown_with_failures", render_batch_markdown(&view));
    insta::assert_snapshot!(
        "batch_json_with_failures",
        render_batch_json(&view).expect("json renders")
    );
}

#[test]
fn snapshot_batch_markdown_pipe_in_name() {
    // Edge case: a contract name containing a pipe would break the Markdown
    // summary table unless escaped. The snapshot pins the escaped cell.
    plain();
    let results = batch_results(vec![
        ("safe|weird", empty_report()),
        ("normal", report_from(vec![], false)),
    ]);
    let failed = no_failures();
    let view = BatchReportView::new(&results, &failed, false, 2, false);
    insta::assert_snapshot!("batch_markdown_pipe_in_name", render_batch_markdown(&view));
}
