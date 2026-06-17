use crate::diff::{DiffReport, Finding, Severity};
use colored::Colorize;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

/// A structured container for aggregated comparison findings.
pub struct SafetyReport {
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub total_findings: usize,
    pub is_safe: bool,
    pub findings_by_category: HashMap<String, Vec<Finding>>,
}

/// Severity counts, serialized as a nested `counts` object.
#[derive(Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

/// A machine-readable view of a [`SafetyReport`] for `--format json`.
///
/// Borrows from the owning report. Categories are stored in a [`BTreeMap`]
/// so the emitted JSON has a stable, diffable key order.
#[derive(Serialize)]
pub struct SafetyReportJson<'a> {
    pub is_safe: bool,
    pub counts: SeverityCounts,
    pub total_findings: usize,
    pub findings_by_category: BTreeMap<&'a str, &'a Vec<Finding>>,
}

impl SafetyReport {
    /// Compute a safety report from a raw DiffReport.
    pub fn new(diff: &DiffReport) -> Self {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut findings_by_category: HashMap<String, Vec<Finding>> = HashMap::new();

        for finding in &diff.findings {
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::Warning => warning_count += 1,
                Severity::Info => info_count += 1,
            }
            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(finding.clone());
        }

        Self {
            critical_count,
            warning_count,
            info_count,
            total_findings: diff.findings.len(),
            is_safe: critical_count == 0,
            findings_by_category,
        }
    }

    /// Build a serializable, machine-readable view of this report.
    pub fn to_json(&self) -> SafetyReportJson<'_> {
        SafetyReportJson {
            is_safe: self.is_safe,
            counts: SeverityCounts {
                critical: self.critical_count,
                warning: self.warning_count,
                info: self.info_count,
            },
            total_findings: self.total_findings,
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
        }
    }

    /// Generate a structured, human-readable text output for the CLI.
    pub fn generate_summary_text(&self, min_severity: Severity) -> String {
        let mut output = String::new();
        output.push_str(&"\n========================================\n".bold().to_string());
        output.push_str(&"    SOROBAN UPGRADE SAFETY REPORT\n".bold().cyan().to_string());
        output.push_str(&"========================================\n".bold().to_string());
        
        let status = if self.is_safe { 
            "✅ PASSED (No breaking changes detected)".green().bold()
        } else { 
            "❌ FAILED (Critical breaking changes detected)".red().bold()
        };
        output.push_str(&format!("Status: {}\n", status));

        let crit_str = if self.critical_count > 0 { self.critical_count.to_string().red().bold() } else { self.critical_count.to_string().green() };
        let warn_str = if self.warning_count > 0 { self.warning_count.to_string().yellow().bold() } else { self.warning_count.to_string().normal() };
        let info_str = self.info_count.to_string().blue();
        
        output.push_str(&format!("Critical: {}\n", crit_str));
        output.push_str(&format!("Warnings: {}\n", warn_str));
        output.push_str(&format!("Info:     {}\n", info_str));
        output.push_str(&"----------------------------------------\n\n".dimmed().to_string());

        if self.total_findings == 0 {
            output.push_str(&"No relevant changes detected. The upgrade is identical in its exports and types.\n".green().to_string());
            return output;
        }

        // Sort categories to have consistent output
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort();

        for category in categories {
            let group = self.findings_by_category.get(category).unwrap();
            let visible_findings: Vec<&Finding> = group
                .iter()
                .filter(|finding| severity_rank(&finding.severity) >= severity_rank(&min_severity))
                .collect();

            if visible_findings.is_empty() {
                continue;
            }

            output.push_str(&format!("--- [{}] ---\n", category.to_ascii_uppercase()).magenta().bold().to_string());
            for finding in visible_findings {
                let formatted = match finding.severity {
                    Severity::Critical => format!("🔴 {}", finding.message).red(),
                    Severity::Warning => format!("🟡 {}", finding.message).yellow(),
                    Severity::Info => format!("🔵 {}", finding.message).cyan(),
                };
                output.push_str(&format!("{}\n", formatted));
            }
            output.push('\n');
        }

        if !self.is_safe {
            output.push_str(&"⚠️  ACTION REQUIRED: The new contract version modifies existing storage layouts or function interfaces.\n".red().bold().to_string());
            output.push_str(&"Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n".red().to_string());
        }

        output
    }
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}
