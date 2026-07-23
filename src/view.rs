//! The single view model that every output format renders from.
//!
//! Three formats — JSON, colored text, and Markdown — used to be produced by
//! three independent renderers reading the raw [`SafetyReport`] directly, and
//! batch mode reimplemented all three again inline (including string surgery
//! that stripped a heading out of a per-pair Markdown report before splicing it
//! in). The same information was expressed in six places, so every new field had
//! to be added six times and nothing structurally guaranteed the formats agreed.
//!
//! This module replaces that with one intermediate *view model*:
//!
//! - [`SingleReportView`] captures everything a single-pair report can express.
//! - [`BatchReportView`] captures a batch run as per-pair [`SingleReportView`]s
//!   plus the pairs that failed to compare at all.
//!
//! Serializing a view *is* the JSON output — the JSON path adds nothing of its
//! own. The text and Markdown renderers consume the same view and nothing else.
//! No renderer post-processes another renderer's output. Adding a field means
//! one change to the view plus per-format presentation, and the conformance
//! tests fail if a format is missed.
//!
//! ## Guarantees the shape enforces
//!
//! - **Ordering is identical in every format.** The view exposes categories in
//!   one canonical order (the `Environment` category first, then alphabetical),
//!   and [`OrderedCategories`] serializes JSON in that same order rather than the
//!   alphabetical order a `BTreeMap` would impose. Findings within a category
//!   keep their diff-time insertion order everywhere.
//! - **Verdict, counts, and suppression state come from one place.** The status
//!   headline is computed once ([`StatusLine`]) so text and Markdown cannot drift
//!   apart, and every count is read straight off the view.

use colored::Colorize;
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::diff::Severity;
use crate::report::{ReportedFinding, SafetyReport, SeverityCounts};

/// The pass/fail verdict plus the exact headline string all formats display.
///
/// Computing the headline once here is what keeps the verdict identical across
/// formats: text colors it, Markdown embeds it in a heading, and both use the
/// very same words. Presentation-only, so it is never serialized to JSON (JSON
/// exposes the machine-readable `is_safe` boolean instead).
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub is_safe: bool,
    pub headline: String,
}

/// Categories paired with their findings, in one canonical render order.
///
/// A `BTreeMap` would force alphabetical key order in JSON, diverging from the
/// `Environment`-first order text and Markdown use. This newtype instead
/// serializes its entries in exactly the order they are stored, so the JSON
/// object, the text sections, and the Markdown sections all agree.
pub struct OrderedCategories<'a> {
    entries: Vec<(&'a str, &'a Vec<ReportedFinding>)>,
}

impl<'a> OrderedCategories<'a> {
    /// The (category, findings) pairs in canonical render order.
    pub fn entries(&self) -> &[(&'a str, &'a Vec<ReportedFinding>)] {
        &self.entries
    }
}

impl Serialize for OrderedCategories<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Emit map entries in stored order. The streaming serializer writes keys
        // in `serialize_entry` call order regardless of serde_json's
        // `preserve_order` feature, so JSON key order matches the other formats.
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (key, findings) in &self.entries {
            map.serialize_entry(key, findings)?;
        }
        map.end()
    }
}

/// Everything a single-pair report can express, in one place.
///
/// The serialized fields (in declaration order) are exactly the single-pair JSON
/// document. Presentation-only fields are `#[serde(skip)]` so JSON is unchanged.
#[derive(Serialize)]
pub struct SingleReportView<'a> {
    pub is_safe: bool,
    pub strict: bool,
    pub counts: SeverityCounts,
    /// Findings (of any severity) acknowledged by the suppression config.
    pub suppressed_count: usize,
    pub total_findings: usize,
    pub recommended_bump: &'static str,
    /// Where the baseline (old) contract was sourced from ("RPC"/"Local File").
    pub baseline_source: Option<&'a str>,
    /// Verified SHA-256 hash of the baseline WASM bytecode (hex), if verified.
    pub verified_code_hash: Option<&'a str>,
    #[serde(rename = "findings_by_category")]
    pub categories: OrderedCategories<'a>,

    // ---- presentation-only: never serialized ----
    /// Precomputed pass/fail headline, shared by text and Markdown.
    #[serde(skip)]
    pub status: StatusLine,
    /// Whether per-finding remediation guidance should be rendered. Guidance is
    /// only ever *present* on findings when explain mode built the report, so
    /// this simply mirrors that request for the text/Markdown layers.
    #[serde(skip)]
    pub explain: bool,
}

/// One contract pair that compared successfully, inside a [`BatchReportView`].
pub struct BatchPair<'a> {
    pub name: &'a str,
    pub view: SingleReportView<'a>,
}

/// A batch pair that could not be compared at all (a load/parse error or a
/// resource-limit rejection). Passed in by the CLI so batch rendering has one
/// place to describe every pair, succeeded or failed.
pub struct PairFailureInfo {
    pub message: String,
    pub is_limit: bool,
}

/// A failed pair, as the batch renderers see it.
pub struct FailedPair<'a> {
    pub name: &'a str,
    pub message: &'a str,
    pub is_limit: bool,
}

/// A batch run: an overall verdict, the per-pair [`SingleReportView`]s, and the
/// pairs that failed to compare.
///
/// Rendering a batch reuses the single-pair renderers for the per-pair detail
/// sections, so batch and single-pair output share heading structure,
/// terminology, and severity vocabulary by construction.
pub struct BatchReportView<'a> {
    pub is_safe: bool,
    pub strict: bool,
    pub total_pairs: usize,
    /// True when any failed pair was rejected for exceeding a resource limit.
    pub limit_violation: bool,
    pub pairs: Vec<BatchPair<'a>>,
    pub failed: Vec<FailedPair<'a>>,
    /// Precomputed overall pass/fail headline, shared by text and Markdown.
    pub status: StatusLine,
}

impl<'a> BatchReportView<'a> {
    /// Build a batch view from the successful per-pair reports and the failures.
    ///
    /// `results` is keyed by contract name, `failed` records the pairs that could
    /// not be compared, `total_pairs` is the number of pairs the run attempted,
    /// and `explain` controls whether the per-pair detail sections render
    /// remediation guidance.
    pub fn new(
        results: &'a BTreeMap<String, SafetyReport>,
        failed: &'a BTreeMap<String, PairFailureInfo>,
        strict: bool,
        total_pairs: usize,
        explain: bool,
    ) -> Self {
        let is_safe = failed.is_empty() && results.values().all(|r| r.is_safe);
        let limit_violation = failed.values().any(|f| f.is_limit);
        let pairs = results
            .iter()
            .map(|(name, report)| BatchPair {
                name: name.as_str(),
                view: report.to_view(explain),
            })
            .collect();
        let failed = failed
            .iter()
            .map(|(name, failure)| FailedPair {
                name: name.as_str(),
                message: failure.message.as_str(),
                is_limit: failure.is_limit,
            })
            .collect();
        Self {
            is_safe,
            strict,
            total_pairs,
            limit_violation,
            pairs,
            failed,
            status: batch_status(is_safe),
        }
    }
}

/// Rank used to surface the `Environment` category first, then alphabetical.
fn category_rank(name: &str) -> u8 {
    if name == "Environment" {
        0
    } else {
        1
    }
}

/// Order category keys canonically: `Environment` first, then alphabetical. This
/// single ordering is what every format (JSON included) iterates.
pub fn ordered_categories(
    findings_by_category: &HashMap<String, Vec<ReportedFinding>>,
) -> OrderedCategories<'_> {
    let mut entries: Vec<(&str, &Vec<ReportedFinding>)> = findings_by_category
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    entries.sort_by(|(a, _), (b, _)| {
        category_rank(a)
            .cmp(&category_rank(b))
            .then_with(|| a.cmp(b))
    });
    OrderedCategories { entries }
}

/// The single-pair pass/fail headline, computed once for all formats.
pub fn single_status(is_safe: bool, strict: bool, critical_count: usize) -> StatusLine {
    let headline = if is_safe {
        "✅ PASSED (No breaking changes detected)"
    } else if strict && critical_count == 0 {
        "❌ FAILED (Warnings detected in strict mode)"
    } else {
        "❌ FAILED (Critical breaking changes detected)"
    };
    StatusLine {
        is_safe,
        headline: headline.to_string(),
    }
}

/// The batch pass/fail headline, computed once for all formats.
pub fn batch_status(is_safe: bool) -> StatusLine {
    let headline = if is_safe {
        "✅ PASSED (All contracts safe)"
    } else {
        "❌ FAILED (Some contracts have breaking changes)"
    };
    StatusLine {
        is_safe,
        headline: headline.to_string(),
    }
}

/// The emoji used to prefix a finding of the given severity in text/Markdown.
fn severity_emoji(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::Warning => "🟡",
        Severity::Info => "🔵",
    }
}

/// Escape a value destined for a Markdown *table cell*.
///
/// A raw `|` closes the cell and a newline ends the row, so a contract name
/// containing either would corrupt the table. Both are neutralized so the table
/// stays valid in common viewers; names without such characters are unchanged.
fn escape_md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

// ===========================================================================
// JSON
// ===========================================================================

/// Render a single-pair report as its pretty JSON document.
pub fn render_single_json(view: &SingleReportView<'_>) -> serde_json::Result<String> {
    serde_json::to_string_pretty(view)
}

/// One errored pair as it appears in batch JSON.
#[derive(Serialize)]
struct FailedJson<'a> {
    error: &'a str,
    limit_violation: bool,
}

/// The batch JSON document. Serializing this struct directly (rather than
/// round-tripping through `serde_json::Value`) keeps per-finding key order
/// identical to single-pair JSON.
#[derive(Serialize)]
struct BatchJson<'a> {
    is_safe: bool,
    strict: bool,
    total_pairs: usize,
    limit_violation: bool,
    results: BTreeMap<&'a str, &'a SingleReportView<'a>>,
    failed: BTreeMap<&'a str, FailedJson<'a>>,
}

/// Render a batch report as its pretty JSON document.
pub fn render_batch_json(view: &BatchReportView<'_>) -> serde_json::Result<String> {
    let results = view
        .pairs
        .iter()
        .map(|pair| (pair.name, &pair.view))
        .collect();
    let failed = view
        .failed
        .iter()
        .map(|f| {
            (
                f.name,
                FailedJson {
                    error: f.message,
                    limit_violation: f.is_limit,
                },
            )
        })
        .collect();
    let doc = BatchJson {
        is_safe: view.is_safe,
        strict: view.strict,
        total_pairs: view.total_pairs,
        limit_violation: view.limit_violation,
        results,
        failed,
    };
    serde_json::to_string_pretty(&doc)
}

// ===========================================================================
// Text
// ===========================================================================

/// Render a single-pair report as the colored, human-readable text report.
pub fn render_single_text(view: &SingleReportView<'_>) -> String {
    let mut output = String::new();
    output.push_str(
        &"\n========================================\n"
            .bold()
            .to_string(),
    );
    output.push_str(
        &"    SOROBAN UPGRADE SAFETY REPORT\n"
            .bold()
            .cyan()
            .to_string(),
    );
    if view.strict {
        output.push_str(&"    [STRICT MODE ACTIVE]\n".bold().yellow().to_string());
    }
    output.push_str(
        &"========================================\n"
            .bold()
            .to_string(),
    );

    let status = if view.status.is_safe {
        view.status.headline.green().bold()
    } else {
        view.status.headline.red().bold()
    };
    output.push_str(&format!("Status: {}\n", status));

    let crit_str = if view.counts.critical > 0 {
        view.counts.critical.to_string().red().bold()
    } else {
        view.counts.critical.to_string().green()
    };
    let warn_str = if view.counts.warning > 0 {
        view.counts.warning.to_string().yellow().bold()
    } else {
        view.counts.warning.to_string().normal()
    };
    let info_str = view.counts.info.to_string().blue();

    output.push_str(&format!("Critical: {}\n", crit_str));
    output.push_str(&format!("Warnings: {}\n", warn_str));
    output.push_str(&format!("Info:     {}\n", info_str));
    if view.suppressed_count > 0 {
        output.push_str(&format!(
            "Suppressed: {}\n",
            view.suppressed_count.to_string().magenta().bold()
        ));
    }
    let bump_str = match view.recommended_bump {
        "major" => "major".red().bold(),
        "minor" => "minor".yellow().bold(),
        "patch" => "patch".green().bold(),
        other => other.normal(),
    };
    output.push_str(&format!("Recommended Bump: {}\n", bump_str));

    if let Some(source) = view.baseline_source {
        output.push_str(&format!("Baseline Source: {}\n", source));
    }
    if let Some(hash) = view.verified_code_hash {
        output.push_str(&format!("Verified Code Hash: {}\n", hash.dimmed()));
    }

    output.push_str(
        &"----------------------------------------\n\n"
            .dimmed()
            .to_string(),
    );

    if view.total_findings == 0 {
        output.push_str(
            &"No relevant changes detected. The upgrade is identical in its exports and types.\n"
                .green()
                .to_string(),
        );
        return output;
    }

    for (category, group) in view.categories.entries() {
        output.push_str(
            &format!("--- [{}] ---\n", category.to_ascii_uppercase())
                .magenta()
                .bold()
                .to_string(),
        );
        for reported in *group {
            let finding = &reported.finding;

            if reported.suppressed {
                // Suppressed findings are still listed, but clearly marked and
                // dimmed so they read as acknowledged, not active.
                let label = format!("🔕 [SUPPRESSED] {}", finding.message)
                    .dimmed()
                    .to_string();
                output.push_str(&format!("{}\n", label));
                if let Some(reason) = &reported.suppression_reason {
                    output.push_str(&format!("    ↳ reason: {}\n", reason).dimmed().to_string());
                }
                if view.explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(
                            &format!("    ↳ guidance: {}\n", remediation)
                                .dimmed()
                                .to_string(),
                        );
                    }
                }
                continue;
            }

            let formatted = match finding.severity {
                Severity::Critical => format!("🔴 {}", finding.message).red(),
                Severity::Warning => format!("🟡 {}", finding.message).yellow(),
                Severity::Info => format!("🔵 {}", finding.message).cyan(),
            };
            output.push_str(&format!("{}\n", formatted));
            if view.explain {
                if let Some(remediation) = &reported.remediation {
                    output.push_str(
                        &format!("    ↳ guidance: {}\n", remediation)
                            .green()
                            .to_string(),
                    );
                }
            }
        }
        output.push('\n');
    }

    if !view.is_safe {
        if view.strict && view.counts.critical == 0 {
            output.push_str(
                &"⚠️  ACTION REQUIRED: Strict mode is active and warnings were detected.\n"
                    .yellow()
                    .bold()
                    .to_string(),
            );
            output.push_str(
                &"These warnings must be resolved or strict mode disabled to proceed.\n"
                    .yellow()
                    .to_string(),
            );
        } else {
            output.push_str(&"⚠️  ACTION REQUIRED: The new contract version modifies existing storage layouts or function interfaces.\n".red().bold().to_string());
            output.push_str(&"Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n".red().to_string());
        }
    }

    output
}

/// Render a batch report as the colored, human-readable text report.
pub fn render_batch_text(view: &BatchReportView<'_>) -> String {
    let mut output = String::new();
    output.push_str("========================================\n");
    output.push_str("    SOROBAN BATCH SAFETY REPORT\n");
    output.push_str("========================================\n");

    let status = if view.status.is_safe {
        view.status.headline.green().bold()
    } else {
        view.status.headline.red().bold()
    };
    output.push_str(&format!("Overall Status: {}\n\n", status));

    output.push_str("Summary of Contracts:\n");
    for pair in &view.pairs {
        let status_str = if pair.view.is_safe {
            "✅ PASSED".green()
        } else {
            "❌ FAILED".red().bold()
        };
        output.push_str(&format!(
            "  - {}: {} ({} critical, {} warnings, {} info, {} suppressed)\n",
            pair.name.bold(),
            status_str,
            pair.view.counts.critical,
            pair.view.counts.warning,
            pair.view.counts.info,
            pair.view.suppressed_count
        ));
    }
    for failure in &view.failed {
        let status_str = if failure.is_limit {
            "⛔ ERROR (resource limit)".red().bold()
        } else {
            "⛔ ERROR".red().bold()
        };
        output.push_str(&format!(
            "  - {}: {} — {}\n",
            failure.name.bold(),
            status_str,
            failure.message
        ));
    }

    output.push_str("\n========================================\n\n");

    for pair in &view.pairs {
        output.push_str(&format!(
            "=== Contract: {} ===\n",
            pair.name.bold().magenta()
        ));
        output.push_str(&render_single_text(&pair.view));
        output.push_str("\n========================================\n\n");
    }

    output
}

// ===========================================================================
// Markdown
// ===========================================================================

/// Render a single-pair report as a standalone Markdown document.
pub fn render_single_markdown(view: &SingleReportView<'_>) -> String {
    let mut output = String::from("# Soroban Upgrade Safety Report\n\n");
    output.push_str(&render_single_markdown_body(view));
    output
}

/// Render everything of a single-pair Markdown report *except* the top-level
/// `# Soroban Upgrade Safety Report` title.
///
/// Batch mode embeds each pair under its own `## Details: <name>` heading and so
/// needs the body without the document title. Exposing the body directly is what
/// lets batch mode drop the old string surgery that deleted the title after the
/// fact.
fn render_single_markdown_body(view: &SingleReportView<'_>) -> String {
    let mut output = String::new();

    output.push_str(&format!("## Status: {}\n\n", view.status.headline));

    output.push_str("### Summary Table\n\n");
    output.push_str("| Finding Severity | Count |\n");
    output.push_str("| :--- | :--- |\n");
    output.push_str(&format!("| **Critical** | {} |\n", view.counts.critical));
    output.push_str(&format!("| **Warning** | {} |\n", view.counts.warning));
    output.push_str(&format!("| **Info** | {} |\n", view.counts.info));
    if view.suppressed_count > 0 {
        output.push_str(&format!("| **Suppressed** | {} |\n", view.suppressed_count));
    }
    output.push_str(&format!(
        "\n**Recommended SemVer Bump**: `{}`\n\n",
        view.recommended_bump
    ));

    if let Some(source) = view.baseline_source {
        output.push_str(&format!("**Baseline Source**: `{}`\n\n", source));
    }
    if let Some(hash) = view.verified_code_hash {
        output.push_str(&format!("**Verified Code Hash**: `{}`\n\n", hash));
    }

    output.push_str("---\n\n");

    if view.total_findings == 0 {
        output.push_str(
            "No relevant changes detected. The upgrade is identical in its exports and types.\n",
        );
        return output;
    }

    for (category, group) in view.categories.entries() {
        output.push_str(&format!("### {}\n\n", category));
        for reported in *group {
            let finding = &reported.finding;

            if reported.suppressed {
                output.push_str(&format!("- 🔕 **[SUPPRESSED]** {}\n", finding.message));
                if let Some(reason) = &reported.suppression_reason {
                    output.push_str(&format!("  - ↳ reason: {}\n", reason));
                }
                if view.explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(&format!("  - ↳ guidance: {}\n", remediation));
                    }
                }
                continue;
            }

            output.push_str(&format!(
                "- {} {}\n",
                severity_emoji(&finding.severity),
                finding.message
            ));
            if view.explain {
                if let Some(remediation) = &reported.remediation {
                    output.push_str(&format!("  - ↳ guidance: {}\n", remediation));
                }
            }
        }
        output.push('\n');
    }

    if !view.is_safe {
        output.push_str("### ⚠️ Action Required\n\n");
        if view.strict && view.counts.critical == 0 {
            output.push_str("- Strict mode is active and warnings were detected.\n");
            output.push_str(
                "- These warnings must be resolved or strict mode disabled to proceed.\n",
            );
        } else {
            output.push_str("- The new contract version modifies existing storage layouts or function interfaces.\n");
            output.push_str("- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n");
        }
    }

    output
}

/// Render a batch report as a standalone Markdown document.
pub fn render_batch_markdown(view: &BatchReportView<'_>) -> String {
    let mut output = String::new();
    output.push_str("# Soroban Upgrade Safety Report (Batch Mode)\n\n");

    output.push_str(&format!("## Status: {}\n\n", view.status.headline));
    output.push_str("### Summary\n\n");
    output.push_str("| Contract | Status | Critical | Warning | Info | Suppressed |\n");
    output.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

    for pair in &view.pairs {
        let status_str = if pair.view.is_safe {
            "✅ PASSED"
        } else {
            "❌ FAILED"
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            escape_md_cell(pair.name),
            status_str,
            pair.view.counts.critical,
            pair.view.counts.warning,
            pair.view.counts.info,
            pair.view.suppressed_count
        ));
    }

    for failure in &view.failed {
        let status_str = if failure.is_limit {
            "⛔ ERROR (limit)"
        } else {
            "⛔ ERROR"
        };
        output.push_str(&format!(
            "| {} | {} | — | — | — | — |\n",
            escape_md_cell(failure.name),
            status_str
        ));
    }

    output.push_str("\n---\n\n");

    if !view.failed.is_empty() {
        output.push_str("### Errored Pairs\n\n");
        for failure in &view.failed {
            output.push_str(&format!("- **{}**: {}\n", failure.name, failure.message));
        }
        output.push_str("\n---\n\n");
    }

    for pair in &view.pairs {
        output.push_str(&format!("## Details: {}\n\n", pair.name));
        output.push_str(&render_single_markdown_body(&pair.view));
        output.push_str("\n---\n\n");
    }

    output
}
