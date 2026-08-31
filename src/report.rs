use crate::contract_migration::{FindingCoverage, MigrationDiagnostic, MigrationStatus};
use crate::diff::{DiffReport, Finding, Severity};
use crate::interface_hash::InterfaceHash;
use crate::render::{RenderableReport, REPORT_SCHEMA_VERSION};
use crate::suppression::SuppressionConfig;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub use crate::render::SeverityCounts;

/// The status of a compatibility axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AxisStatus {
    Passed,
    Warning,
    Failed,
}
/// A finding as it appears in the report, augmented with suppression state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedFinding {
    #[serde(default)]
    pub rule_id: String,
    #[serde(flatten)]
    #[cfg(feature = "unstable")]
    pub finding: Finding,
    #[serde(flatten)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) finding: Finding,

    /// The compatibility axes this finding was classified under.
    #[serde(default, skip)]
    #[cfg(feature = "unstable")]
    pub axes: Vec<crate::diff::CompatibilityAxis>,
    /// The compatibility axes this finding was classified under.
    #[serde(default, skip)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) axes: Vec<crate::diff::CompatibilityAxis>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg(feature = "unstable")]
    pub suppressed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "unstable")]
    pub suppression_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppression_reason: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "unstable")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) remediation: Option<String>,

    /// The verified migration that covers this finding, if one does. See
    /// [`crate::contract_migration`]. A suppression records that a human
    /// accepted a break; this records that a declared migration was checked
    /// to actually handle it — the two are kept visibly distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "unstable")]
    pub migrated_by: Option<FindingCoverage>,
    /// See the `unstable`-feature `migrated_by` field above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) migrated_by: Option<FindingCoverage>,
}

impl ReportedFinding {
    pub fn finding(&self) -> &Finding {
        &self.finding
    }

    pub fn axes(&self) -> &[crate::diff::CompatibilityAxis] {
        &self.axes
    }

    pub fn suppressed(&self) -> bool {
        self.suppressed
    }

    pub fn suppression_reason(&self) -> Option<&str> {
        self.suppression_reason.as_deref()
    }

    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }

    /// The verified migration that covers this finding, if one does.
    pub fn migrated_by(&self) -> Option<&FindingCoverage> {
        self.migrated_by.as_ref()
    }
}

/// A structured container for aggregated comparison findings.
#[derive(Debug, Default)]
pub struct SafetyReport {
    pub call_abi: crate::call_abi::CallAbiCompatibility,
    #[cfg(feature = "unstable")]
    pub critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) critical_count: usize,

    #[cfg(feature = "unstable")]
    pub warning_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) warning_count: usize,

    #[cfg(feature = "unstable")]
    pub info_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) info_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_critical_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_warning_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_warning_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_info_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_info_count: usize,

    /// Number of findings covered by a verified migration. See
    /// [`crate::contract_migration`].
    #[cfg(feature = "unstable")]
    pub migrated_count: usize,
    /// See the `unstable`-feature `migrated_count` field above.
    #[cfg(not(feature = "unstable"))]
    pub(crate) migrated_count: usize,

    /// Whether the upgrade is fully, partly, or not at all migrated.
    #[cfg(feature = "unstable")]
    pub migration_status: MigrationStatus,
    /// See the `unstable`-feature `migration_status` field above.
    #[cfg(not(feature = "unstable"))]
    pub(crate) migration_status: MigrationStatus,

    /// Declared migrations that did not verify, and coverage gaps.
    #[cfg(feature = "unstable")]
    pub migration_diagnostics: Vec<MigrationDiagnostic>,
    /// See the `unstable`-feature `migration_diagnostics` field above.
    #[cfg(not(feature = "unstable"))]
    pub(crate) migration_diagnostics: Vec<MigrationDiagnostic>,

    #[cfg(feature = "unstable")]
    pub total_findings: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) total_findings: usize,

    #[cfg(feature = "unstable")]
    pub is_safe: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) is_safe: bool,

    #[cfg(feature = "unstable")]
    pub findings_by_category: HashMap<String, Vec<ReportedFinding>>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) findings_by_category: HashMap<String, Vec<ReportedFinding>>,

    #[cfg(feature = "unstable")]
    pub strict: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) strict: bool,

    #[cfg(feature = "unstable")]
    pub critical_root_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) critical_root_count: usize,

    #[cfg(feature = "unstable")]
    pub cascade_critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) cascade_critical_count: usize,

    #[cfg(feature = "unstable")]
    pub old_interface_hash: Option<InterfaceHash>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) old_interface_hash: Option<InterfaceHash>,

    #[cfg(feature = "unstable")]
    pub new_interface_hash: Option<InterfaceHash>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) new_interface_hash: Option<InterfaceHash>,

    #[cfg(feature = "unstable")]
    pub no_timestamp: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) no_timestamp: bool,

    #[cfg(feature = "unstable")]
    pub old_spec_summary: Option<String>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) old_spec_summary: Option<String>,

    #[cfg(feature = "unstable")]
    pub new_spec_summary: Option<String>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) new_spec_summary: Option<String>,

    #[cfg(feature = "unstable")]
    pub scope: AnalysisScope,
    #[cfg(not(feature = "unstable"))]
    pub(crate) scope: AnalysisScope,

    #[cfg(feature = "unstable")]
    pub rpc_provenance: Option<crate::rpc::RpcProvenance>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) rpc_provenance: Option<crate::rpc::RpcProvenance>,

    /// Symlink resolution for the old build, if its input path was one. See
    /// [`crate::loader::SymlinkResolution`].
    #[cfg(feature = "unstable")]
    pub old_symlink: Option<crate::loader::SymlinkResolution>,
    /// Symlink resolution for the old build, if its input path was one.
    #[cfg(not(feature = "unstable"))]
    pub(crate) old_symlink: Option<crate::loader::SymlinkResolution>,

    /// Symlink resolution for the new build, if its input path was one.
    #[cfg(feature = "unstable")]
    pub new_symlink: Option<crate::loader::SymlinkResolution>,
    /// Symlink resolution for the new build, if its input path was one.
    #[cfg(not(feature = "unstable"))]
    pub(crate) new_symlink: Option<crate::loader::SymlinkResolution>,

    #[cfg(feature = "unstable")]
    pub metrics: Option<BuildMetrics>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) metrics: Option<BuildMetrics>,

    /// Per-axis pass/warning/fail verdict.
    #[cfg(feature = "unstable")]
    pub axis_verdicts: HashMap<crate::diff::CompatibilityAxis, AxisStatus>,
    /// Per-axis pass/warning/fail verdict.
    #[cfg(not(feature = "unstable"))]
    pub(crate) axis_verdicts: HashMap<crate::diff::CompatibilityAxis, AxisStatus>,

    /// Axes whose findings gate `is_safe` (per policy and `--strict`).
    #[cfg(feature = "unstable")]
    pub gated_axes: HashSet<crate::diff::CompatibilityAxis>,
    /// Axes whose findings gate `is_safe` (per policy and `--strict`).
    #[cfg(not(feature = "unstable"))]
    pub(crate) gated_axes: HashSet<crate::diff::CompatibilityAxis>,

    /// Whether empirical (storage-sample) validation was performed.
    #[cfg(feature = "unstable")]
    pub empirical: bool,
    /// Whether empirical (storage-sample) validation was performed.
    #[cfg(not(feature = "unstable"))]
    pub(crate) empirical: bool,

    /// Findings from empirical validation, if performed.
    #[cfg(feature = "unstable")]
    pub empirical_findings: Vec<crate::empirical::EmpiricalFinding>,
    /// Findings from empirical validation, if performed.
    #[cfg(not(feature = "unstable"))]
    pub(crate) empirical_findings: Vec<crate::empirical::EmpiricalFinding>,

    /// Configured compatibility budgets ([`crate::budget`]) that were
    /// exceeded. Always gates `is_safe`, independent of `--strict` and axis
    /// gate policy, since a budget is an explicit opt-in the team configured.
    #[cfg(feature = "unstable")]
    pub budget_violations: Vec<crate::budget::BudgetViolation>,
    /// Configured compatibility budgets ([`crate::budget`]) that were
    /// exceeded. Always gates `is_safe`, independent of `--strict` and axis
    /// gate policy, since a budget is an explicit opt-in the team configured.
    #[cfg(not(feature = "unstable"))]
    pub(crate) budget_violations: Vec<crate::budget::BudgetViolation>,

    #[cfg(feature = "unstable")]
    pub settings: ReportSettings,
    #[cfg(not(feature = "unstable"))]
    pub(crate) settings: ReportSettings,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ReportSettings {
    pub strict: bool,
    pub explain: bool,
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    pub max_xdr_depth: u32,
    pub max_xdr_len: usize,
    pub max_entries: usize,
    pub max_walk_depth: usize,
}

impl SafetyReport {
    pub fn apply_storage_schema_comparison(
        &mut self,
        comparison: &crate::storage_schema::StorageSchemaComparison,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
    ) {
        let key_types = comparison
            .old
            .observations
            .iter()
            .chain(comparison.new.observations.iter())
            .filter(|observation| observation.key_type.is_some())
            .count();
        let value_types = comparison
            .old
            .observations
            .iter()
            .chain(comparison.new.observations.iter())
            .filter(|observation| observation.value_type.is_some())
            .count();
        self.scope.storage_schema = StorageScopeState::Analyzed {
            key_types,
            value_types,
        };

        for (side, findings) in [
            ("old", &comparison.old.findings),
            ("new", &comparison.new.findings),
        ] {
            for mismatch in findings {
                let category = "Storage Schema Mismatch".to_string();
                let message = format!(
                    "{} storage schema mismatch: {}",
                    side,
                    serde_json::to_string(mismatch)
                        .unwrap_or_else(|_| "unserializable mismatch".to_string())
                );
                let finding = crate::diff::Finding {
                    severity: crate::diff::Severity::Critical,
                    axes: vec![crate::diff::CompatibilityAxis::StorageLayout],
                    category: category.clone(),
                    message,
                    type_name: None,
                    target: None,
                    change: None,
                    root_target: None,
                };
                let rule = suppressions.matching_rule(&finding);
                let suppressed = rule.is_some();
                self.critical_count += 1;
                self.total_findings += 1;
                if suppressed {
                    self.suppressed_count += 1;
                    self.suppressed_critical_count += 1;
                }
                if !suppressed {
                    let storage_gated = suppressions.policy.gate_storage_layout || strict;
                    if storage_gated {
                        self.is_safe = false;
                        self.axis_verdicts.insert(
                            crate::diff::CompatibilityAxis::StorageLayout,
                            AxisStatus::Failed,
                        );
                    }
                }
                self.findings_by_category
                    .entry(category)
                    .or_default()
                    .push(ReportedFinding {
                        rule_id: "storage_schema_mismatch".to_string(),
                        axes: finding.axes.clone(),
                        finding,
                        suppressed,
                        suppression_reason: rule.and_then(|rule| rule.reason.clone()),
                        remediation: explain.then(|| {
                            "Reconcile the declared schema with the compiled storage behavior."
                                .to_string()
                        }),
                        migrated_by: None,
                    });
            }
        }
    }

    pub fn apply_lineage_report(
        &mut self,
        lineage_report: &crate::lineage::LineageValidationReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
    ) {
        if !lineage_report.is_safe {
            self.is_safe = false;
        }

        for hist in &lineage_report.historical_findings {
            let category = format!("Historical Lineage Break ({})", hist.historical_version_id);
            let finding = hist.finding.clone();
            let rule = suppressions.matching_rule(&finding);
            let suppressed = rule.is_some();

            match finding.severity {
                crate::diff::Severity::Critical => {
                    self.critical_count += 1;
                    if suppressed {
                        self.suppressed_critical_count += 1;
                    }
                }
                crate::diff::Severity::Warning => {
                    self.warning_count += 1;
                    if suppressed {
                        self.suppressed_warning_count += 1;
                    }
                }
                crate::diff::Severity::Info => {
                    self.info_count += 1;
                    if suppressed {
                        self.suppressed_info_count += 1;
                    }
                }
            }

            self.total_findings += 1;
            if suppressed {
                self.suppressed_count += 1;
            } else {
                for axis in &finding.axes {
                    if self.gated_axes.contains(axis) || strict {
                        self.is_safe = false;
                        self.axis_verdicts.insert(*axis, AxisStatus::Failed);
                    }
                }
            }

            self.findings_by_category
                .entry(category)
                .or_default()
                .push(ReportedFinding {
                    rule_id: "historical_lineage_break".to_string(),
                    axes: finding.axes.clone(),
                    finding,
                    suppressed,
                    suppression_reason: rule.and_then(|r| r.reason.clone()),
                    remediation: explain.then(|| {
                        "Update candidate build to maintain backward compatibility with this historical version."
                            .to_string()
                    }),
                    migrated_by: None,
                });
        }
    }

    pub fn critical_count(&self) -> usize {
        self.critical_count
    }

    pub fn warning_count(&self) -> usize {
        self.warning_count
    }

    pub fn info_count(&self) -> usize {
        self.info_count
    }

    pub fn suppressed_count(&self) -> usize {
        self.suppressed_count
    }

    pub fn suppressed_critical_count(&self) -> usize {
        self.suppressed_critical_count
    }

    pub fn suppressed_warning_count(&self) -> usize {
        self.suppressed_warning_count
    }

    pub fn suppressed_info_count(&self) -> usize {
        self.suppressed_info_count
    }

    /// Number of findings covered by a verified migration.
    pub fn migrated_count(&self) -> usize {
        self.migrated_count
    }

    /// Whether the upgrade is fully, partly, or not at all migrated.
    pub fn migration_status(&self) -> MigrationStatus {
        self.migration_status
    }

    /// Declared migrations that did not verify, and coverage gaps.
    pub fn migration_diagnostics(&self) -> &[MigrationDiagnostic] {
        &self.migration_diagnostics
    }

    pub fn total_findings(&self) -> usize {
        self.total_findings
    }

    pub fn is_safe(&self) -> bool {
        self.is_safe
    }

    pub fn findings_by_category(&self) -> &HashMap<String, Vec<ReportedFinding>> {
        &self.findings_by_category
    }

    pub fn strict(&self) -> bool {
        self.strict
    }

    pub fn critical_root_count(&self) -> usize {
        self.critical_root_count
    }

    pub fn cascade_critical_count(&self) -> usize {
        self.cascade_critical_count
    }

    pub fn old_interface_hash(&self) -> Option<&InterfaceHash> {
        self.old_interface_hash.as_ref()
    }

    pub fn new_interface_hash(&self) -> Option<&InterfaceHash> {
        self.new_interface_hash.as_ref()
    }

    pub fn no_timestamp(&self) -> bool {
        self.no_timestamp
    }

    pub fn set_no_timestamp(&mut self, val: bool) {
        self.no_timestamp = val;
    }

    pub fn old_spec_summary(&self) -> Option<&str> {
        self.old_spec_summary.as_deref()
    }

    pub fn new_spec_summary(&self) -> Option<&str> {
        self.new_spec_summary.as_deref()
    }

    pub fn scope(&self) -> &AnalysisScope {
        &self.scope
    }

    pub fn metrics(&self) -> Option<&BuildMetrics> {
        self.metrics.as_ref()
    }

    pub fn axis_verdicts(&self) -> &HashMap<crate::diff::CompatibilityAxis, AxisStatus> {
        &self.axis_verdicts
    }

    pub fn call_abi(&self) -> &crate::call_abi::CallAbiCompatibility {
        &self.call_abi
    }

    pub fn gated_axes(&self) -> &HashSet<crate::diff::CompatibilityAxis> {
        &self.gated_axes
    }

    pub fn empirical(&self) -> bool {
        self.empirical
    }

    pub fn empirical_findings(&self) -> &[crate::empirical::EmpiricalFinding] {
        &self.empirical_findings
    }

    pub fn budget_violations(&self) -> &[crate::budget::BudgetViolation] {
        &self.budget_violations
    }
}

/// Track what was analyzed in the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisScope {
    pub exported_interface: bool,
    pub env_metadata: bool,
    pub storage_schema: StorageScopeState,
    pub old_spec_section_count: usize,
    pub new_spec_section_count: usize,
    pub old_duplicate_names: Vec<String>,
    pub new_duplicate_names: Vec<String>,
}

impl AnalysisScope {
    pub fn storage_analyzed(&self) -> bool {
        matches!(self.storage_schema, StorageScopeState::Analyzed { .. })
    }

    pub fn summary_line(&self) -> String {
        let mut parts = Vec::new();
        if self.exported_interface {
            parts.push("exported interface");
        }
        if self.env_metadata {
            parts.push("env metadata");
        }
        if self.storage_analyzed() {
            parts.push("storage schema");
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }

    pub fn storage_status_line(&self) -> String {
        match &self.storage_schema {
            StorageScopeState::Analyzed {
                key_types,
                value_types,
            } => {
                format!(
                    "Storage layout analyzed ({} key types, {} value types)",
                    key_types, value_types
                )
            }
            StorageScopeState::NotAnalyzed => {
                "Storage layout: NOT analyzed (use a storage schema manifest)".to_string()
            }
        }
    }
}

/// Whether storage schema analysis was performed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum StorageScopeState {
    #[default]
    NotAnalyzed,
    Analyzed {
        key_types: usize,
        value_types: usize,
    },
}

/// Build metrics for the report.
#[derive(Debug, Clone, Serialize)]
pub struct BuildMetrics {
    pub old_wasm_size: usize,
    pub new_wasm_size: usize,
    pub old_functions: usize,
    pub new_functions: usize,
    pub old_structs: usize,
    pub new_structs: usize,
    pub old_enums: usize,
    pub new_enums: usize,
    pub old_unions: usize,
    pub new_unions: usize,
    pub old_error_enums: usize,
    pub new_error_enums: usize,
}

impl BuildMetrics {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        old_wasm_size: usize,
        new_wasm_size: usize,
        old_functions: usize,
        new_functions: usize,
        old_structs: usize,
        new_structs: usize,
        old_enums: usize,
        new_enums: usize,
        old_unions: usize,
        new_unions: usize,
        old_error_enums: usize,
        new_error_enums: usize,
    ) -> Self {
        Self {
            old_wasm_size,
            new_wasm_size,
            old_functions,
            new_functions,
            old_structs,
            new_structs,
            old_enums,
            new_enums,
            old_unions,
            new_unions,
            old_error_enums,
            new_error_enums,
        }
    }
}

#[allow(dead_code)]
fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A machine-readable view of a SafetyReport for JSON output.
pub type SafetyReportJson = RenderableReport;

/// Format a contract identity label from optional name and version strings.
#[allow(dead_code)]
fn contract_identity_label(name: Option<&str>, version: Option<&str>) -> String {
    match (name, version) {
        (Some(n), Some(v)) => format!("{} v{}", n, v),
        (Some(n), None) => n.to_string(),
        (None, Some(v)) => format!("v{}", v),
        (None, None) => "<unknown>".to_string(),
    }
}

pub fn asciify_markers(text: &str) -> String {
    text.replace("🔕 ", "")
        .replace('🔕', "[SUPPRESSED]")
        .replace('🔴', "[CRITICAL]")
        .replace('🟡', "[WARN]")
        .replace('🔵', "[INFO]")
        .replace('✅', "[PASS]")
        .replace('❌', "[FAIL]")
        .replace("⚠️", "[WARNING]")
        .replace('⚠', "[WARNING]")
}

/// Strip the decorative Unicode `asciify_markers` intentionally leaves alone
/// (the `↳` guidance/reason arrow, and the `─` box-drawing separator around
/// the provenance block), for output that must be fully plain: no color, no
/// Unicode markers, no decorative separators. Callers combine this with
/// disabling color (see `--plain`); it does not touch color itself.
pub fn plainify(text: &str) -> String {
    asciify_markers(text).replace('↳', "->").replace('─', "-")
}

impl SafetyReport {
    pub fn new(diff: &DiffReport) -> Self {
        Self::with_suppressions(
            diff,
            &SuppressionConfig::default(),
            false,
            false,
            &crate::limits::ResourcePolicy::default(),
        )
    }

    pub fn new_with_specs(
        diff: &DiffReport,
        old_spec: &crate::spec::ContractSpec,
        new_spec: &crate::spec::ContractSpec,
    ) -> Self {
        Self::with_suppressions_with_specs(
            diff,
            &SuppressionConfig::default(),
            false,
            false,
            old_spec,
            new_spec,
            None,
        )
    }

    pub fn noop(old_wasm_size: usize, new_wasm_size: usize) -> Self {
        let mut axis_verdicts = HashMap::new();
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::StorageLayout,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(crate::diff::CompatibilityAxis::CallAbi, AxisStatus::Passed);
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::EventIndexer,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::SourceLevel,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::RuntimeSurface,
            AxisStatus::Passed,
        );

        let mut gated_axes = HashSet::new();
        gated_axes.insert(crate::diff::CompatibilityAxis::StorageLayout);
        gated_axes.insert(crate::diff::CompatibilityAxis::CallAbi);
        gated_axes.insert(crate::diff::CompatibilityAxis::RuntimeSurface);

        Self {
            call_abi: crate::call_abi::CallAbiCompatibility::default(),
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            migrated_count: 0,
            migration_status: MigrationStatus::NotApplicable,
            migration_diagnostics: Vec::new(),
            total_findings: 0,
            is_safe: true,
            findings_by_category: HashMap::new(),
            strict: false,
            critical_root_count: 0,
            cascade_critical_count: 0,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            scope: AnalysisScope::default(),
            metrics: Some(BuildMetrics::new(
                old_wasm_size,
                new_wasm_size,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )),
            axis_verdicts,
            gated_axes,
            empirical: false,
            empirical_findings: Vec::new(),
            budget_violations: Vec::new(),
            rpc_provenance: None,
            old_symlink: None,
            new_symlink: None,
            settings: ReportSettings::default(),
        }
    }

    /// Compute a safety report, applying a suppression config.
    pub fn with_suppressions(
        diff: &DiffReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
        policy: &crate::limits::ResourcePolicy,
    ) -> Self {
        let empty = crate::spec::ContractSpec::default();
        let mut report = Self::with_suppressions_with_specs(
            diff,
            suppressions,
            explain,
            strict,
            &empty,
            &empty,
            None,
        );
        report.settings = ReportSettings {
            strict,
            explain,
            max_suppressions: suppressions.max_suppressions,
            allow_targetless: suppressions.allow_targetless,
            max_xdr_depth: policy.max_xdr_depth,
            max_xdr_len: policy.max_xdr_len,
            max_entries: policy.max_entries,
            max_walk_depth: policy.max_walk_depth,
        };
        report
    }

    pub fn with_suppressions_with_specs(
        diff: &DiffReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
        old_spec: &crate::spec::ContractSpec,
        new_spec: &crate::spec::ContractSpec,
        contract: Option<&str>,
    ) -> Self {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut suppressed_count = 0;
        let mut suppressed_critical_count = 0;
        let mut suppressed_warning_count = 0;
        let mut suppressed_info_count = 0;
        let mut migrated_count = 0;
        // Denominator and numerator for the migration verdict: breaking
        // findings that need remediation, and those a migration actually
        // handles. Suppressed findings are excluded from both — an upgrade
        // that suppresses everything has migrated nothing.
        let mut needing_migration = 0;
        let mut migrated_breaking = 0;
        let mut findings_by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();
        let mut critical_root_count = 0;
        let mut cascade_critical_count = 0;
        let call_abi = crate::call_abi::compare(old_spec, new_spec);
        let mut unsuppressed_call_abi_finding = false;

        // Verify declared migrations against the findings up front. Coverage
        // (including cascade inheritance via `root_target`) is then looked up
        // per finding by index in the main loop below. See
        // [`crate::contract_migration`].
        let migration_audit =
            crate::contract_migration::audit(&diff.findings, &suppressions.migrations, contract);

        let mut axis_verdicts = HashMap::new();
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::StorageLayout,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(crate::diff::CompatibilityAxis::CallAbi, AxisStatus::Passed);
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::EventIndexer,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::SourceLevel,
            AxisStatus::Passed,
        );
        axis_verdicts.insert(
            crate::diff::CompatibilityAxis::RuntimeSurface,
            AxisStatus::Passed,
        );

        let mut gated_axes = HashSet::new();
        let axes_list = [
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
            crate::diff::CompatibilityAxis::RuntimeSurface,
        ];
        for axis in axes_list {
            let is_gated = strict
                || match axis {
                    crate::diff::CompatibilityAxis::StorageLayout => {
                        suppressions.policy.gate_storage_layout
                    }
                    crate::diff::CompatibilityAxis::CallAbi => suppressions.policy.gate_call_abi,
                    crate::diff::CompatibilityAxis::EventIndexer => {
                        suppressions.policy.gate_event_indexer
                    }
                    crate::diff::CompatibilityAxis::SourceLevel => {
                        suppressions.policy.gate_source_level
                    }
                    crate::diff::CompatibilityAxis::RuntimeSurface => {
                        suppressions.policy.gate_runtime_surface
                    }
                };
            if is_gated {
                gated_axes.insert(axis);
            }
        }

        let mut suppressed_root_types: HashSet<String> = HashSet::new();
        for finding in &diff.findings {
            if finding.root_target.is_none() && suppressions.matching_rule(finding).is_some() {
                if let Some(ref tn) = finding.type_name {
                    suppressed_root_types.insert(tn.clone());
                }
            }
        }

        for (index, finding) in diff.findings.iter().enumerate() {
            let is_cascade = finding.root_target.is_some();
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::Warning => warning_count += 1,
                Severity::Info => info_count += 1,
            }

            let rule = suppressions.matching_rule(finding);
            let suppressed = if is_cascade {
                let rt = finding.root_target.as_deref().unwrap();
                rule.is_some() || suppressed_root_types.contains(rt)
            } else {
                rule.is_some()
            };

            // A migration is a stronger claim than an acknowledgement: it says
            // code handles the break and was checked, not just that a human
            // accepted it. When a finding somehow has both, it reads as
            // migrated, and does not also count toward suppression totals.
            let migrated_by = migration_audit.coverage_of(index).cloned();
            let suppressed = suppressed && migrated_by.is_none();

            if is_cascade && finding.severity == Severity::Critical {
                cascade_critical_count += 1;
            } else if finding.severity == Severity::Critical {
                critical_root_count += 1;
            }

            if migrated_by.is_some() {
                migrated_count += 1;
            } else if suppressed {
                suppressed_count += 1;
                match finding.severity {
                    Severity::Critical => suppressed_critical_count += 1,
                    Severity::Warning => suppressed_warning_count += 1,
                    Severity::Info => suppressed_info_count += 1,
                }
            }

            let breaking = matches!(finding.severity, Severity::Critical | Severity::Warning);
            if breaking && !suppressed {
                needing_migration += 1;
                if migrated_by.is_some() {
                    migrated_breaking += 1;
                }
            }

            let remediation = if explain {
                get_remediation_guidance(&finding.category).map(String::from)
            } else {
                None
            };

            // Retrieve or inherit axes
            let axes = if let Some(ref rt) = finding.root_target {
                diff.findings
                    .iter()
                    .find(|f| f.target.as_deref() == Some(rt))
                    .map(|f| {
                        crate::diff::classify_finding_axes(
                            &f.category,
                            f.type_name.as_deref(),
                            old_spec,
                            new_spec,
                        )
                    })
                    .unwrap_or_else(|| {
                        crate::diff::classify_finding_axes(
                            &finding.category,
                            finding.type_name.as_deref(),
                            old_spec,
                            new_spec,
                        )
                    })
            } else {
                crate::diff::classify_finding_axes(
                    &finding.category,
                    finding.type_name.as_deref(),
                    old_spec,
                    new_spec,
                )
            };

            // Environment metadata is reported for visibility, but it is not a
            // contract compatibility finding and therefore cannot gate safety.
            //
            // `Info` findings describe backwards-compatible additions (a new
            // function, a new union case), so they are never allowed to move an
            // axis off `Passed`. `Warning` findings only fail under `--strict`;
            // a `Critical` fails whenever its axis is gated. A finding covered
            // by a verified migration is handled, not merely accepted, and so
            // is excluded here exactly like a suppressed one.
            if !suppressed
                && migrated_by.is_none()
                && finding.severity != Severity::Info
                && finding.category != "Environment"
            {
                if axes.contains(&crate::diff::CompatibilityAxis::CallAbi) {
                    unsuppressed_call_abi_finding = true;
                }
                for axis in &axes {
                    let is_gated = strict
                        || match axis {
                            crate::diff::CompatibilityAxis::StorageLayout => {
                                suppressions.policy.gate_storage_layout
                            }
                            crate::diff::CompatibilityAxis::CallAbi => {
                                suppressions.policy.gate_call_abi
                            }
                            crate::diff::CompatibilityAxis::EventIndexer => {
                                suppressions.policy.gate_event_indexer
                            }
                            crate::diff::CompatibilityAxis::SourceLevel => {
                                suppressions.policy.gate_source_level
                            }
                            crate::diff::CompatibilityAxis::RuntimeSurface => {
                                suppressions.policy.gate_runtime_surface
                            }
                        };

                    // A Warning only fails the run under `--strict`; a Critical
                    // fails wherever the policy gates its axis.
                    let fails = match finding.severity {
                        Severity::Critical => is_gated,
                        _ => strict,
                    };

                    let new_status = if fails {
                        AxisStatus::Failed
                    } else {
                        AxisStatus::Warning
                    };

                    let current = axis_verdicts.entry(*axis).or_insert(AxisStatus::Passed);
                    if *current == AxisStatus::Passed
                        || (*current == AxisStatus::Warning && new_status == AxisStatus::Failed)
                    {
                        *current = new_status;
                    }
                }
            }

            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(ReportedFinding {
                    rule_id: canonical_rule_id(&finding.category),
                    finding: finding.clone(),
                    axes,
                    suppressed,
                    suppression_reason: if suppressed {
                        rule.and_then(|r| r.reason.clone())
                    } else {
                        None
                    },
                    remediation,
                    migrated_by,
                });
        }

        // Directional ABI breaks are part of the aggregate CallAbi verdict.
        // They are derived from the wire value flow and therefore remain
        // visible even when no legacy source-level finding was emitted.
        if !call_abi.compatible() && (diff.findings.is_empty() || unsuppressed_call_abi_finding) {
            axis_verdicts.insert(
                crate::diff::CompatibilityAxis::CallAbi,
                if suppressions.policy.gate_call_abi || strict {
                    AxisStatus::Failed
                } else {
                    AxisStatus::Warning
                },
            );
        }
        let is_safe = !axis_verdicts
            .values()
            .any(|&status| status == AxisStatus::Failed);

        let reported_refs: Vec<&ReportedFinding> =
            findings_by_category.values().flatten().collect();
        let budget_violations =
            crate::budget::evaluate(&reported_refs, &suppressions.budgets().entries);
        // A configured budget is an explicit, deliberate policy the team
        // opted into -- unlike axis gating it does not depend on `--strict`
        // or the default gate policy, so any violation always fails the run.
        let is_safe = is_safe && budget_violations.is_empty();

        Self {
            call_abi,
            critical_count,
            warning_count,
            info_count,
            suppressed_count,
            suppressed_critical_count,
            suppressed_warning_count,
            suppressed_info_count,
            migrated_count,
            migration_status: MigrationStatus::classify(needing_migration, migrated_breaking),
            migration_diagnostics: migration_audit.diagnostics().to_vec(),
            total_findings: diff.findings.len(),
            is_safe,
            findings_by_category,
            strict,
            critical_root_count,
            cascade_critical_count,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            scope: AnalysisScope::default(),
            metrics: None,
            axis_verdicts,
            gated_axes,
            empirical: false,
            empirical_findings: Vec::new(),
            budget_violations,
            rpc_provenance: None,
            old_symlink: None,
            new_symlink: None,
            settings: ReportSettings {
                strict,
                explain,
                ..ReportSettings::default()
            },
        }
    }

    pub fn with_interface_hashes(mut self, old: InterfaceHash, new: InterfaceHash) -> Self {
        self.old_interface_hash = Some(old);
        self.new_interface_hash = Some(new);
        self
    }

    /// Attach symlink resolution recorded while loading the old/new inputs.
    /// Either or both may be `None` when that input was a direct file (or a
    /// non-local source).
    pub fn with_symlinks(
        mut self,
        old: Option<crate::loader::SymlinkResolution>,
        new: Option<crate::loader::SymlinkResolution>,
    ) -> Self {
        self.old_symlink = old;
        self.new_symlink = new;
        self
    }

    pub fn interface_unchanged(&self) -> Option<bool> {
        match (self.old_interface_hash, self.new_interface_hash) {
            (Some(old), Some(new)) => Some(old == new),
            _ => None,
        }
    }

    pub fn recommended_bump(&self) -> &'static str {
        if self.critical_count > 0 || !self.call_abi.compatible() {
            "major"
        } else if self.warning_count > 0 {
            "minor"
        } else if self.info_count > 0 {
            if self.has_non_documentation_info_findings() {
                "minor"
            } else {
                "patch"
            }
        } else {
            "patch"
        }
    }

    fn has_non_documentation_info_findings(&self) -> bool {
        const DOC_CATEGORIES: &[&str] = &[
            "Function Documentation Changed",
            "Struct Documentation Changed",
            "Enum Documentation Changed",
        ];

        for findings in self.findings_by_category.values() {
            for reported in findings {
                if reported.finding.severity == Severity::Info
                    && !DOC_CATEGORIES.contains(&reported.finding.category.as_str())
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn to_renderable(&self) -> RenderableReport {
        let timestamp = if self.no_timestamp {
            String::new()
        } else {
            chrono_now_rfc3339()
        };

        let mut findings_by_axis = BTreeMap::new();
        findings_by_axis.insert(crate::diff::CompatibilityAxis::StorageLayout, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::CallAbi, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::EventIndexer, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::SourceLevel, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::RuntimeSurface, Vec::new());

        for category_findings in self.findings_by_category.values() {
            for reported in category_findings {
                for axis in &reported.axes {
                    if let Some(list) = findings_by_axis.get_mut(axis) {
                        list.push(reported.clone());
                    }
                }
            }
        }

        for list in findings_by_axis.values_mut() {
            list.sort_by(|a, b| {
                a.finding
                    .category
                    .cmp(&b.finding.category)
                    .then_with(|| a.finding.target.cmp(&b.finding.target))
            });
        }

        RenderableReport {
            report_schema_version: REPORT_SCHEMA_VERSION,
            provenance: crate::render::Provenance {
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp,
                inputs: [self.old_interface_hash, self.new_interface_hash]
                    .into_iter()
                    .flatten()
                    .map(|hash| hash.to_hex())
                    .collect(),
                ledger_sequence: self.rpc_provenance.as_ref().map(|p| p.ledger_sequence),
                network: self.rpc_provenance.as_ref().map(|p| p.network.clone()),
                rpc_endpoint: self.rpc_provenance.as_ref().map(|p| p.rpc_endpoint.clone()),
                code_hash: self.rpc_provenance.as_ref().map(|p| p.code_hash.clone()),
                live_until_ledger_seq: self
                    .rpc_provenance
                    .as_ref()
                    .and_then(|p| p.live_until_ledger_seq),
                symlinks: [self.old_symlink.clone(), self.new_symlink.clone()]
                    .into_iter()
                    .flatten()
                    .collect(),
                git_commit: current_git_commit(),
            },
            is_safe: self.is_safe,
            strict: self.strict,
            counts: SeverityCounts {
                critical: self.critical_count,
                warning: self.warning_count,
                info: self.info_count,
            },
            suppressed_count: self.suppressed_count,
            total_findings: self.total_findings,
            recommended_bump: self.recommended_bump().to_string(),
            old_interface_hash: self.old_interface_hash.map(|h| h.to_hex()),
            new_interface_hash: self.new_interface_hash.map(|h| h.to_hex()),
            scope: self.scope.clone(),
            storage_coverage: if self.scope.storage_analyzed() {
                "schema-backed".to_string()
            } else {
                "interface-only".to_string()
            },
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            axis_verdicts: self.axis_verdicts.iter().map(|(k, v)| (*k, *v)).collect(),
            gated_axes: self.gated_axes.iter().copied().collect(),
            findings_by_axis,
            call_abi: self.call_abi.clone(),
            empirical: self.empirical,
            empirical_findings: self.empirical_findings.clone(),
            budget_violations: self.budget_violations.clone(),
            migration: None,
            migrated_count: self.migrated_count,
            migration_status: self.migration_status,
            migration_diagnostics: self.migration_diagnostics.clone(),
        }
    }

    pub fn to_json(&self) -> RenderableReport {
        self.to_renderable()
    }

    pub fn generate_summary_text(&self, explain: bool) -> String {
        self.to_renderable().to_text(explain)
    }

    /// Like [`Self::generate_summary_text`], with finding messages
    /// word-wrapped to `width` columns when given. See
    /// [`crate::render::RenderableReport::to_text_with_width`].
    pub fn generate_summary_text_with_width(&self, explain: bool, width: Option<usize>) -> String {
        self.to_renderable().to_text_with_width(explain, width)
    }

    pub fn generate_summary_markdown(&self) -> String {
        self.to_renderable().to_markdown()
    }
}

/// Returns remediation/explanation guidance for a given finding category.
///
/// Delegates to [`crate::category::FindingCategory`] which is the single source
/// of truth.
pub fn get_remediation_guidance(category: &str) -> Option<&'static str> {
    crate::category::FindingCategory::find_by_name(category).map(|c| c.remediation())
}

fn canonical_rule_id(category: &str) -> String {
    crate::suppression::canonical_rule_id(category)
}

/// Best-effort lookup of the Git commit (full SHA) the tool is being run
/// from, by shelling out to `git rev-parse HEAD` in the current working
/// directory.
///
/// Returns `None` — never an error — when `git` is not on `PATH`, the
/// working directory is not inside a Git repository (or is a shallow clone
/// with no HEAD), or the output isn't a well-formed commit hash. Capturing
/// the invoking commit is a convenience for tying a report back to the
/// source revision that produced it, not a requirement: CI checkouts,
/// tarball extractions, and other non-Git contexts must still produce a
/// complete report.
fn current_git_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    let is_valid_sha =
        !commit.is_empty() && commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit());
    is_valid_sha.then(|| commit.to_string())
}

/// Return the current UTC time as an RFC 3339 / ISO 8601 string.
fn chrono_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let mut days = secs / 86400;
    let time_secs = secs % 86400;

    let mut year: u64 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    let mut day = days;
    for (i, &md) in month_days.iter().enumerate() {
        if day < md {
            month = i as u64 + 1;
            break;
        }
        day -= md;
    }
    day += 1;

    let hour = time_secs / 3600;
    let minute = (time_secs % 3600) / 60;
    let second = time_secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that every documented category in the reference page can be
    /// resolved by `get_remediation_guidance`.  The true single-source-of-truth
    /// test lives in `category.rs` (`generated_markdown_matches_committed_file`);
    /// this just guards the delegation wrapper.
    #[test]
    fn test_remediation_guidance_resolves_known_categories() {
        for cat in crate::category::FindingCategory::all() {
            let guidance = get_remediation_guidance(cat.as_str());
            assert!(
                guidance.is_some(),
                "get_remediation_guidance('{}') returned None",
                cat.as_str()
            );
        }
    }

    #[test]
    fn test_recommended_semver_bump() {
        use crate::diff::Finding;

        fn make_finding(severity: Severity, category: &str) -> ReportedFinding {
            ReportedFinding {
                rule_id: canonical_rule_id(category),
                finding: Finding {
                    severity,
                    axes: Vec::new(),
                    category: category.to_string(),
                    message: String::new(),
                    type_name: None,
                    target: None,
                    change: None,
                    root_target: None,
                },
                axes: Vec::new(),
                suppressed: false,
                suppression_reason: None,
                remediation: None,
                migrated_by: None,
            }
        }

        let mut report = SafetyReport {
            call_abi: crate::call_abi::CallAbiCompatibility::default(),
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            migrated_count: 0,
            migration_status: MigrationStatus::NotApplicable,
            migration_diagnostics: Vec::new(),
            total_findings: 0,
            is_safe: true,
            findings_by_category: HashMap::new(),
            strict: false,
            critical_root_count: 0,
            cascade_critical_count: 0,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            rpc_provenance: None,
            old_symlink: None,
            new_symlink: None,
            scope: AnalysisScope::default(),
            metrics: None,
            axis_verdicts: HashMap::new(),
            gated_axes: HashSet::new(),
            empirical: false,
            empirical_findings: Vec::new(),
            budget_violations: Vec::new(),
            settings: ReportSettings::default(),
        };

        assert_eq!(report.recommended_bump(), "patch");

        report.info_count = 1;
        report.findings_by_category.insert(
            "Function Added".to_string(),
            vec![make_finding(Severity::Info, "Function Added")],
        );
        assert_eq!(report.recommended_bump(), "minor");

        report.info_count = 1;
        report.warning_count = 0;
        report.critical_count = 0;
        report.findings_by_category.clear();
        report.findings_by_category.insert(
            "Function Documentation Changed".to_string(),
            vec![make_finding(
                Severity::Info,
                "Function Documentation Changed",
            )],
        );
        assert_eq!(report.recommended_bump(), "patch");

        report.info_count = 0;
        report.warning_count = 1;
        report.findings_by_category.clear();
        assert_eq!(report.recommended_bump(), "minor");

        report.critical_count = 1;
        assert_eq!(report.recommended_bump(), "major");
    }

    #[test]
    fn test_cascade_counts_separated_from_root() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed from i64 to i128".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            change: None,
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken because it embeds modified type 'Data'"
                .to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            change: None,
            root_target: Some("Data".to_string()),
        });

        let report = SafetyReport::with_suppressions_with_specs(
            &diff,
            &SuppressionConfig::default(),
            false,
            false,
            &crate::spec::ContractSpec::default(),
            &crate::spec::ContractSpec::default(),
            None,
        );

        assert_eq!(report.critical_root_count, 1);
        assert_eq!(report.cascade_critical_count, 1);
        assert_eq!(report.critical_count, 2);
        assert!(!report.is_safe);
    }

    #[test]
    fn test_cascade_suppressed_when_root_suppressed() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            change: None,
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            change: None,
            root_target: Some("Data".to_string()),
        });

        let suppressions = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            reason   = "Acknowledged"
            "#,
        )
        .unwrap();

        let report = SafetyReport::with_suppressions_with_specs(
            &diff,
            &suppressions,
            false,
            false,
            &crate::spec::ContractSpec::default(),
            &crate::spec::ContractSpec::default(),
            None,
        );

        let root_finding = report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap();
        assert_eq!(root_finding.len(), 1);
        assert!(root_finding[0].suppressed);

        let cascade_findings = report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap();
        assert_eq!(cascade_findings.len(), 1);
        assert!(cascade_findings[0].suppressed);

        assert!(report.is_safe);
        assert_eq!(report.suppressed_count, 2);
    }

    #[test]
    fn test_cascade_not_suppressed_when_root_not_suppressed() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            change: None,
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            change: None,
            root_target: Some("Data".to_string()),
        });

        let suppressions = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.balance"
            "#,
        )
        .unwrap();

        let report = SafetyReport::with_suppressions_with_specs(
            &diff,
            &suppressions,
            false,
            false,
            &crate::spec::ContractSpec::default(),
            &crate::spec::ContractSpec::default(),
            None,
        );

        let root_finding = &report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap()[0];
        assert!(!root_finding.suppressed);

        let cascade_finding = &report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap()[0];
        assert!(!cascade_finding.suppressed);
    }
}
