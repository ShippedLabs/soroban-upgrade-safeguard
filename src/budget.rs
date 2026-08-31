//! Per-axis and per-rule compatibility budgets.
//!
//! Axis gating ([`crate::suppression::PolicyConfig`]) and `--strict` decide
//! *which kinds* of findings can fail a run, but they are boolean: an axis
//! either gates or it doesn't. A budget expresses a bounded *count* instead
//! -- "at most 2 new events this release", "zero warnings in this specific
//! rule" -- evaluated after analysis, without changing how any individual
//! finding is classified or suppressed.
//!
//! ## Config shape (`.safeguard.toml`)
//!
//! ```toml
//! [[budget]]
//! scope  = "global"
//! metric = "unsuppressed"
//! limit  = 0
//!
//! [[budget]]
//! scope  = "axis"
//! axis   = "event_indexer"
//! metric = "raw"
//! limit  = 3
//!
//! [[budget]]
//! scope    = "rule"
//! rule_id  = "enum_case_added"
//! severity = "warning"
//! metric   = "unsuppressed"
//! limit    = 1
//! ```
//!
//! `rule_id` is the same canonical, snake_case identifier already exposed as
//! [`crate::report::ReportedFinding::rule_id`] (e.g. `"Enum Case Added"` ->
//! `"enum_case_added"`), so a budget rule and a suppression rule name the
//! same rule the same way.
//!
//! ## Precedence
//!
//! Scopes narrow from `global` to `axis` to `rule`, and a narrower budget
//! **replaces** a broader one for the findings it covers rather than
//! stacking with it:
//!
//! 1. Every finding whose `rule_id` matches a configured `rule` budget is
//!    claimed by that budget alone.
//! 2. Every remaining finding that carries an axis matching a configured
//!    `axis` budget is claimed by that budget alone.
//! 3. Whatever is left is evaluated against the `global` budget, if any.
//!
//! This means setting `limit = 0` globally and `limit = 2` for one specific
//! rule allows exactly 2 findings of that rule and zero of everything else --
//! the rule budget overrides the global default for its own findings, it
//! does not add to them.
//!
//! ## Metric
//!
//! Each budget entry evaluates either `raw` (every finding it claims,
//! suppressed or not) or `unsuppressed` (only findings not acknowledged by a
//! `[[suppress]]` rule) findings, filtered further by `severity` when given.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::diff::{CompatibilityAxis, Severity};
use crate::report::ReportedFinding;

/// Which finding count a budget entry evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum BudgetMetric {
    /// Every finding the entry's scope claims, suppressed or not.
    Raw,
    /// Only findings not acknowledged by a suppression rule.
    #[default]
    Unsuppressed,
}

impl BudgetMetric {
    fn as_str(self) -> &'static str {
        match self {
            BudgetMetric::Raw => "raw",
            BudgetMetric::Unsuppressed => "unsuppressed",
        }
    }
}

/// The scope a budget entry applies to, narrowest to broadest being
/// `Rule` > `Axis` > `Global`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    Global,
    Axis(CompatibilityAxis),
    Rule(String),
}

impl BudgetScope {
    /// A short, stable label identifying this scope for provenance and
    /// deduplication purposes (e.g. `"rule:enum_case_added"`).
    pub fn label(&self) -> String {
        match self {
            BudgetScope::Global => "global".to_string(),
            BudgetScope::Axis(axis) => format!("axis:{}", axis_label(*axis)),
            BudgetScope::Rule(rule_id) => format!("rule:{rule_id}"),
        }
    }
}

fn axis_label(axis: CompatibilityAxis) -> &'static str {
    match axis {
        CompatibilityAxis::StorageLayout => "storage_layout",
        CompatibilityAxis::CallAbi => "call_abi",
        CompatibilityAxis::EventIndexer => "event_indexer",
        CompatibilityAxis::SourceLevel => "source_level",
        CompatibilityAxis::RuntimeSurface => "runtime_surface",
    }
}

/// [`Severity`] derives neither `Ord` nor `Hash`, so it can't be used
/// directly as a map key; this gives a stable, comparable stand-in without
/// requiring changes to the shared type in [`crate::diff`].
fn severity_key(severity: Option<Severity>) -> Option<&'static str> {
    severity.map(|s| match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    })
}

/// One configured budget, as parsed from a `[[budget]]` table.
///
/// Deserialized directly from TOML via a flat, optional-field shape (see
/// [`BudgetEntryFile`]) and then validated/normalized into this type by
/// [`BudgetConfig::from_file_entries`], so callers downstream of validation
/// never see an entry with a scope/field mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEntry {
    pub scope: BudgetScope,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub metric: BudgetMetric,
    pub limit: usize,
}

/// The raw, flat shape a `[[budget]]` TOML table deserializes into.
///
/// Flat rather than an internally-tagged enum so `scope = "axis"` reads
/// naturally as a string in TOML; [`BudgetConfig::from_file_entries`] does
/// the work of turning this into a validated [`BudgetEntry`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BudgetEntryFile {
    pub scope: String,
    #[serde(default)]
    pub axis: Option<CompatibilityAxis>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub metric: Option<BudgetMetric>,
    /// Signed so an explicitly negative limit can be rejected with a clear
    /// message instead of failing TOML deserialization into `usize`.
    pub limit: i64,
}

/// A validated set of compatibility budgets.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub entries: Vec<BudgetEntry>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) entries: Vec<BudgetEntry>,
}

impl BudgetConfig {
    /// Validate and normalize raw `[[budget]]` entries.
    ///
    /// Rejects (as `Err(messages)`, one message per problem, so a config
    /// with several mistakes reports all of them at once):
    /// - an unknown `scope` string,
    /// - `scope = "axis"` without `axis`, or `scope = "rule"` without `rule_id`,
    /// - a `rule_id` that names no known finding rule,
    /// - a negative `limit`,
    /// - two entries with the same effective scope (and, for rule scopes,
    ///   the same `severity` filter) but different limits/metrics, which
    ///   would make the outcome depend on config ordering rather than a
    ///   deterministic rule.
    pub fn from_file_entries(raw: Vec<BudgetEntryFile>) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut entries = Vec::new();
        let mut seen: BTreeMap<(String, Option<&'static str>), (BudgetMetric, usize)> =
            BTreeMap::new();

        for (index, raw_entry) in raw.iter().enumerate() {
            let position = index + 1;
            let scope = match raw_entry.scope.as_str() {
                "global" => Some(BudgetScope::Global),
                "axis" => match raw_entry.axis {
                    Some(axis) => Some(BudgetScope::Axis(axis)),
                    None => {
                        errors.push(format!(
                            "budget #{position}: scope = \"axis\" requires an `axis` field"
                        ));
                        None
                    }
                },
                "rule" => match &raw_entry.rule_id {
                    Some(rule_id) if !rule_id.is_empty() => {
                        if is_known_rule_id(rule_id) {
                            Some(BudgetScope::Rule(rule_id.clone()))
                        } else {
                            errors.push(format!("budget #{position}: unknown rule_id '{rule_id}'"));
                            None
                        }
                    }
                    _ => {
                        errors.push(format!(
                            "budget #{position}: scope = \"rule\" requires a `rule_id` field"
                        ));
                        None
                    }
                },
                other => {
                    errors.push(format!(
                        "budget #{position}: unknown scope '{other}' \
                         (expected \"global\", \"axis\", or \"rule\")"
                    ));
                    None
                }
            };

            if raw_entry.limit < 0 {
                errors.push(format!(
                    "budget #{position}: limit must not be negative (got {})",
                    raw_entry.limit
                ));
            }

            let Some(scope) = scope else { continue };
            if raw_entry.limit < 0 {
                continue;
            }

            let metric = raw_entry.metric.unwrap_or_default();
            let limit = raw_entry.limit as usize;
            let key = (scope.label(), severity_key(raw_entry.severity.clone()));

            match seen.get(&key) {
                Some((prev_metric, prev_limit))
                    if *prev_metric != metric || *prev_limit != limit =>
                {
                    errors.push(format!(
                        "budget #{position}: contradicts an earlier budget for the same \
                         scope{} -- one entry per (scope, severity) pair, please combine them",
                        raw_entry
                            .severity
                            .as_ref()
                            .map(|s| format!(" and severity ({s:?})"))
                            .unwrap_or_default()
                    ));
                    continue;
                }
                Some(_) => {
                    // Exact duplicate of an already-accepted entry: harmless, skip it.
                    continue;
                }
                None => {
                    seen.insert(key, (metric, limit));
                }
            }

            entries.push(BudgetEntry {
                scope,
                severity: raw_entry.severity.clone(),
                metric,
                limit,
            });
        }

        if errors.is_empty() {
            Ok(Self { entries })
        } else {
            Err(errors)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn is_known_rule_id(rule_id: &str) -> bool {
    crate::category::FindingCategory::all()
        .iter()
        .any(|category| crate::suppression::canonical_rule_id(category.as_str()) == rule_id)
}

/// A single budget entry exceeded by the findings it claimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetViolation {
    /// Stable label for the entry's scope, e.g. `"rule:enum_case_added"`.
    pub scope: String,
    pub metric: BudgetMetric,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub measured: usize,
    pub limit: usize,
}

impl std::fmt::Display for BudgetViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} exceeded: {} {} finding(s){} against a limit of {}",
            self.scope,
            self.measured,
            self.metric.as_str(),
            self.severity
                .as_ref()
                .map(|s| format!(" ({s:?})"))
                .unwrap_or_default(),
            self.limit
        )
    }
}

/// Evaluate every configured budget against a flattened list of reported
/// findings, applying rule-over-axis-over-global precedence, and return one
/// [`BudgetViolation`] per entry whose measured count exceeds its limit.
///
/// Order of `violations` follows `entries` order (which is itself the order
/// entries appeared in the config), so output is deterministic.
pub fn evaluate(findings: &[&ReportedFinding], entries: &[BudgetEntry]) -> Vec<BudgetViolation> {
    if entries.is_empty() {
        return Vec::new();
    }

    let rule_entries: Vec<&BudgetEntry> = entries
        .iter()
        .filter(|e| matches!(e.scope, BudgetScope::Rule(_)))
        .collect();
    let axis_entries: Vec<&BudgetEntry> = entries
        .iter()
        .filter(|e| matches!(e.scope, BudgetScope::Axis(_)))
        .collect();

    // Partition findings by the *most specific* scope that claims them, so a
    // narrower budget replaces a broader one for its own findings rather
    // than being counted under both.
    let mut claimed_by_rule: Vec<&ReportedFinding> = Vec::new();
    let mut claimed_by_axis: BTreeMap<&'static str, Vec<&ReportedFinding>> = BTreeMap::new();
    let mut unclaimed: Vec<&ReportedFinding> = Vec::new();

    'finding: for finding in findings {
        if rule_entries
            .iter()
            .any(|e| matches!(&e.scope, BudgetScope::Rule(r) if *r == finding.rule_id))
        {
            claimed_by_rule.push(finding);
            continue 'finding;
        }
        for axis in &finding.axes {
            if axis_entries
                .iter()
                .any(|e| matches!(e.scope, BudgetScope::Axis(a) if a == *axis))
            {
                claimed_by_axis
                    .entry(axis_label(*axis))
                    .or_default()
                    .push(finding);
                continue 'finding;
            }
        }
        unclaimed.push(finding);
    }

    let mut violations = Vec::new();
    for entry in entries {
        let scoped_pool: Vec<&&ReportedFinding> = match &entry.scope {
            BudgetScope::Rule(rule_id) => claimed_by_rule
                .iter()
                .filter(|f| f.rule_id == *rule_id)
                .collect(),
            BudgetScope::Axis(axis) => claimed_by_axis
                .get(axis_label(*axis))
                .map(|v| v.iter().collect())
                .unwrap_or_default(),
            BudgetScope::Global => unclaimed.iter().collect(),
        };

        let measured = scoped_pool
            .iter()
            .filter(|f| {
                entry.severity.is_none() || entry.severity.as_ref() == Some(&f.finding.severity)
            })
            .filter(|f| entry.metric == BudgetMetric::Raw || !f.suppressed)
            .count();

        if measured > entry.limit {
            violations.push(BudgetViolation {
                scope: entry.scope.label(),
                metric: entry.metric,
                severity: entry.severity.clone(),
                measured,
                limit: entry.limit,
            });
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Finding;

    fn reported(category: &str, axes: Vec<CompatibilityAxis>, suppressed: bool) -> ReportedFinding {
        ReportedFinding {
            rule_id: crate::suppression::canonical_rule_id(category),
            finding: Finding::new(
                axes.clone(),
                category.to_string(),
                "msg".into(),
                None,
                None,
                None,
            ),
            axes,
            suppressed,
            suppression_reason: None,
            remediation: None,
            migrated_by: None,
        }
    }

    fn entry(scope: BudgetScope, metric: BudgetMetric, limit: usize) -> BudgetEntry {
        BudgetEntry {
            scope,
            severity: None,
            metric,
            limit,
        }
    }

    #[test]
    fn global_budget_counts_unclaimed_findings() {
        let findings = vec![
            reported(
                "Enum Case Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
            reported(
                "Function Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let entries = vec![entry(BudgetScope::Global, BudgetMetric::Unsuppressed, 1)];

        let violations = evaluate(&refs, &entries);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 2);
        assert_eq!(violations[0].limit, 1);
        assert_eq!(violations[0].scope, "global");
    }

    #[test]
    fn axis_budget_claims_matching_findings_and_excludes_them_from_global() {
        let findings = vec![
            reported(
                "Event Enum Case Added",
                vec![CompatibilityAxis::EventIndexer],
                false,
            ),
            reported(
                "Event Enum Case Added",
                vec![CompatibilityAxis::EventIndexer],
                false,
            ),
            reported(
                "Function Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let entries = vec![
            entry(
                BudgetScope::Axis(CompatibilityAxis::EventIndexer),
                BudgetMetric::Raw,
                5,
            ),
            entry(BudgetScope::Global, BudgetMetric::Raw, 0),
        ];

        let violations = evaluate(&refs, &entries);
        // The axis budget (limit 5, measured 2) passes; the global budget
        // only sees the one remaining SourceLevel finding, and 1 > 0 fails.
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].scope, "global");
        assert_eq!(violations[0].measured, 1);
    }

    #[test]
    fn rule_budget_overrides_axis_and_global_for_its_own_findings() {
        let findings = vec![
            reported(
                "Event Enum Case Added",
                vec![CompatibilityAxis::EventIndexer],
                false,
            ),
            reported(
                "Event Enum Case Added",
                vec![CompatibilityAxis::EventIndexer],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let entries = vec![
            entry(
                BudgetScope::Rule("event_enum_case_added".to_string()),
                BudgetMetric::Raw,
                2,
            ),
            entry(
                BudgetScope::Axis(CompatibilityAxis::EventIndexer),
                BudgetMetric::Raw,
                0,
            ),
        ];

        // Both findings are claimed by the rule budget (limit 2, measured 2:
        // passes) rather than the axis budget (limit 0), which would
        // otherwise fail on the very same findings.
        let violations = evaluate(&refs, &entries);
        assert!(violations.is_empty());
    }

    #[test]
    fn unsuppressed_metric_ignores_suppressed_findings() {
        let findings = vec![
            reported("Function Added", vec![CompatibilityAxis::SourceLevel], true),
            reported(
                "Function Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let entries = vec![entry(BudgetScope::Global, BudgetMetric::Unsuppressed, 1)];

        let violations = evaluate(&refs, &entries);
        assert!(violations.is_empty(), "1 unsuppressed <= limit of 1");
    }

    #[test]
    fn raw_metric_counts_suppressed_findings_too() {
        let findings = vec![
            reported("Function Added", vec![CompatibilityAxis::SourceLevel], true),
            reported(
                "Function Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let entries = vec![entry(BudgetScope::Global, BudgetMetric::Raw, 1)];

        let violations = evaluate(&refs, &entries);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 2);
    }

    #[test]
    fn severity_filter_narrows_the_scoped_pool() {
        let findings = vec![
            reported(
                "Struct Field Type Changed",
                vec![CompatibilityAxis::StorageLayout],
                false,
            ),
            reported(
                "Function Added",
                vec![CompatibilityAxis::SourceLevel],
                false,
            ),
        ];
        let refs: Vec<&ReportedFinding> = findings.iter().collect();
        let mut critical_only = entry(BudgetScope::Global, BudgetMetric::Raw, 0);
        critical_only.severity = Some(Severity::Critical);
        let entries = vec![critical_only];

        let violations = evaluate(&refs, &entries);
        // Only the StorageLayout (Critical) finding counts; the Info-severity
        // Function Added finding is filtered out by the severity filter.
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 1);
    }

    #[test]
    fn from_file_entries_rejects_unknown_scope() {
        let raw = vec![BudgetEntryFile {
            scope: "bogus".into(),
            limit: 0,
            ..Default::default()
        }];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_entries_rejects_negative_limit() {
        let raw = vec![BudgetEntryFile {
            scope: "global".into(),
            limit: -1,
            ..Default::default()
        }];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_entries_rejects_unknown_rule_id() {
        let raw = vec![BudgetEntryFile {
            scope: "rule".into(),
            rule_id: Some("not_a_real_rule".into()),
            limit: 0,
            ..Default::default()
        }];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_entries_rejects_axis_scope_without_axis() {
        let raw = vec![BudgetEntryFile {
            scope: "axis".into(),
            limit: 0,
            ..Default::default()
        }];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_entries_rejects_contradictory_duplicate_scope() {
        let raw = vec![
            BudgetEntryFile {
                scope: "global".into(),
                limit: 0,
                ..Default::default()
            },
            BudgetEntryFile {
                scope: "global".into(),
                limit: 5,
                ..Default::default()
            },
        ];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_entries_accepts_valid_rule_scope() {
        let raw = vec![BudgetEntryFile {
            scope: "rule".into(),
            rule_id: Some("function_added".into()),
            limit: 3,
            ..Default::default()
        }];
        let result = BudgetConfig::from_file_entries(raw);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().entries.len(), 1);
    }
}
