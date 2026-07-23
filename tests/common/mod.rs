//! Shared builders for the report-rendering tests.
//!
//! These construct [`SafetyReport`]s directly from in-memory findings (every
//! field is public) so the format tests exercise the renderers without needing
//! to compile WASM fixtures for every shape — including shapes that are awkward
//! to produce from real contracts, such as a pipe character in a contract name.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use soroban_upgrade_safeguard::diff::{Finding, Severity};
use soroban_upgrade_safeguard::report::{ReportedFinding, SafetyReport};

/// Build a raw [`Finding`].
pub fn finding(
    severity: Severity,
    category: &str,
    message: &str,
    type_name: Option<&str>,
    target: Option<&str>,
) -> Finding {
    Finding {
        severity,
        category: category.to_string(),
        message: message.to_string(),
        type_name: type_name.map(str::to_string),
        target: target.map(str::to_string),
    }
}

/// Build a [`ReportedFinding`] with explicit suppression/remediation state.
pub fn reported(
    finding: Finding,
    suppressed: bool,
    suppression_reason: Option<&str>,
    remediation: Option<&str>,
) -> ReportedFinding {
    ReportedFinding {
        finding,
        suppressed,
        suppression_reason: suppression_reason.map(str::to_string),
        remediation: remediation.map(str::to_string),
    }
}

/// Assemble a [`SafetyReport`] from a flat list of reported findings, computing
/// the counts exactly the way the report layer does. Baseline provenance is left
/// unset; use [`with_provenance`] to add it.
pub fn report_from(findings: Vec<ReportedFinding>, strict: bool) -> SafetyReport {
    let mut by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();
    let mut critical_count = 0;
    let mut warning_count = 0;
    let mut info_count = 0;
    let mut suppressed_count = 0;
    let mut failing_critical = 0;
    let mut failing_warning = 0;

    for reported in &findings {
        match reported.finding.severity {
            Severity::Critical => critical_count += 1,
            Severity::Warning => warning_count += 1,
            Severity::Info => info_count += 1,
        }
        if reported.suppressed {
            suppressed_count += 1;
        } else {
            match reported.finding.severity {
                Severity::Critical => failing_critical += 1,
                Severity::Warning => failing_warning += 1,
                Severity::Info => {}
            }
        }
    }

    let total_findings = findings.len();
    for reported in findings {
        by_category
            .entry(reported.finding.category.clone())
            .or_default()
            .push(reported);
    }

    let is_safe = if strict {
        failing_critical == 0 && failing_warning == 0
    } else {
        failing_critical == 0
    };

    SafetyReport {
        critical_count,
        warning_count,
        info_count,
        suppressed_count,
        total_findings,
        is_safe,
        findings_by_category: by_category,
        strict,
        baseline_source: None,
        verified_code_hash: None,
    }
}

/// Attach baseline provenance (source + verified hash) to a report.
pub fn with_provenance(mut report: SafetyReport, source: &str, hash: &str) -> SafetyReport {
    report.baseline_source = Some(source.to_string());
    report.verified_code_hash = Some(hash.to_string());
    report
}

/// A representative failing report that exercises every presentation concern:
/// an `Environment` finding (proving the canonical ordering), an active critical
/// with remediation and a structured target, and a *suppressed* critical with a
/// reason. Built as non-strict; two active criticals keep it unsafe.
pub fn rich_report() -> SafetyReport {
    report_from(
        vec![
            reported(
                finding(
                    Severity::Info,
                    "Environment",
                    "Protocol version changed from 20 to 21",
                    None,
                    None,
                ),
                false,
                None,
                Some("Verify that the target network supports the new protocol version."),
            ),
            reported(
                finding(
                    Severity::Critical,
                    "Struct Field Removed",
                    "Field 'threshold' removed from struct 'ConfigData'",
                    Some("ConfigData"),
                    Some("ConfigData.threshold"),
                ),
                false,
                None,
                Some("Restore the field or perform a state migration."),
            ),
            reported(
                finding(
                    Severity::Critical,
                    "Function Signature Changed",
                    "Function 'initialize' signature changed",
                    None,
                    Some("initialize"),
                ),
                true,
                Some("Planned re-init for the v2 migration."),
                Some("Update call sites, SDKs, and tests to match the new parameter structure."),
            ),
        ],
        false,
    )
}

/// A clean report with no findings at all.
pub fn empty_report() -> SafetyReport {
    report_from(vec![], false)
}

/// A report whose only finding is a suppressed critical — safe, yet the finding
/// is still listed and counted.
pub fn all_suppressed_report() -> SafetyReport {
    report_from(
        vec![reported(
            finding(
                Severity::Critical,
                "Struct Field Removed",
                "Field 'threshold' removed from struct 'ConfigData'",
                Some("ConfigData"),
                Some("ConfigData.threshold"),
            ),
            true,
            Some("Reviewed: storage migration ships in v2."),
            None,
        )],
        false,
    )
}

/// A warning-only report under strict mode — unsafe purely because of strict.
pub fn strict_warning_report() -> SafetyReport {
    report_from(
        vec![reported(
            finding(
                Severity::Warning,
                "Struct Field Added",
                "Field 'nickname' added to struct 'Account'",
                Some("Account"),
                Some("Account.nickname"),
            ),
            false,
            None,
            None,
        )],
        true,
    )
}

/// A report carrying baseline provenance, as an RPC-fetched baseline would: a
/// `baseline_source` and a `verified_code_hash`. Used to prove those fields are
/// surfaced in every format.
pub fn provenance_report() -> SafetyReport {
    with_provenance(
        empty_report(),
        "RPC",
        "deadbeefcafef00d1122334455667788990011223344556677889900aabbccddee",
    )
}

/// A batch keyed by contract name. Names are ordered by the map, matching the
/// binary's `BTreeMap` result ordering.
pub fn batch_results(pairs: Vec<(&str, SafetyReport)>) -> BTreeMap<String, SafetyReport> {
    pairs
        .into_iter()
        .map(|(name, report)| (name.to_string(), report))
        .collect()
}
