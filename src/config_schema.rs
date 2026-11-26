// SPDX-License-Identifier: MIT

//! Canonical JSON Schema definitions, editor completion generators,
//! and schema-aware validation for safeguard configuration and batch manifests.
//!
//! Provides machine-readable Draft-7 JSON Schemas, editor completion/hover metadata,
//! and unified schema-aware diagnostics (file, line, column, field path) across
//! TOML and JSON configuration files.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use schemars::gen::SchemaGenerator;
use schemars::schema::{InstanceType, RootSchema, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current configuration schema format version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Current batch manifest schema format version.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Canonical schema URI for safeguard configuration.
pub const CONFIG_SCHEMA_ID: &str =
    "https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/safeguard-config.schema.json";

/// Canonical schema URI for batch manifests.
pub const MANIFEST_SCHEMA_ID: &str =
    "https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/batch-manifest.schema.json";

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Supported report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormatEnum {
    /// Human-readable terminal text output.
    #[default]
    Text,
    /// Machine-readable JSON output for CI pipelines and dashboards.
    Json,
    /// Markdown formatted report for pull request comments.
    Markdown,
    /// GitHub Actions workflow annotations.
    #[serde(rename = "github-actions")]
    GithubActions,
}

/// Compatibility evaluation axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityAxisEnum {
    /// Changes affecting ledger storage layout and serialization compatibility.
    StorageLayout,
    /// Changes affecting exported function signatures and parameter/return types.
    CallAbi,
    /// Changes affecting emitted event schemas consumed by off-chain indexers.
    EventIndexer,
    /// Changes affecting source-level bindings or client SDK compilation.
    SourceLevel,
    /// Changes affecting protocol capability levels or required host function imports.
    RuntimeSurface,
}

impl CompatibilityAxisEnum {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StorageLayout => "storage_layout",
            Self::CallAbi => "call_abi",
            Self::EventIndexer => "event_indexer",
            Self::SourceLevel => "source_level",
            Self::RuntimeSurface => "runtime_surface",
        }
    }
}

/// Evaluation metric for finding count budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetMetricEnum {
    /// Evaluates all findings matching the scope, whether suppressed or not.
    Raw,
    /// Evaluates only unsuppressed findings matching the scope.
    #[default]
    Unsuppressed,
}

/// Finding severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverityEnum {
    /// High-impact breaking change that corrupts data or breaks execution.
    Critical,
    /// Breaking change requiring migration or caller updates.
    Warning,
    /// Additive, backward-compatible modification.
    Info,
}

// Custom schema generation helpers for finding categories and rule IDs.
fn category_schema(_gen: &mut SchemaGenerator) -> Schema {
    let mut schema = SchemaObject {
        instance_type: Some(InstanceType::String.into()),
        enum_values: Some(
            crate::category::FindingCategory::all()
                .iter()
                .map(|c| serde_json::Value::String(c.as_str().to_string()))
                .collect(),
        ),
        ..Default::default()
    };
    schema.metadata().description =
        Some("Exact finding category string to match (e.g. 'Struct Field Removed').".to_string());
    Schema::Object(schema)
}

fn rule_id_schema(_gen: &mut SchemaGenerator) -> Schema {
    let mut schema = SchemaObject {
        instance_type: Some(InstanceType::String.into()),
        enum_values: Some(
            crate::category::FindingCategory::all()
                .iter()
                .map(|c| {
                    serde_json::Value::String(crate::suppression::canonical_rule_id(c.as_str()))
                })
                .collect(),
        ),
        ..Default::default()
    };
    schema.metadata().description =
        Some("Canonical snake_case rule identifier (e.g. 'struct_field_removed').".to_string());
    Schema::Object(schema)
}

fn complexity_metric_schema(_gen: &mut SchemaGenerator) -> Schema {
    let mut schema = SchemaObject {
        instance_type: Some(InstanceType::String.into()),
        enum_values: Some(vec![
            "total_instructions".into(),
            "defined_functions".into(),
            "control".into(),
            "calls".into(),
            "memory".into(),
            "numeric".into(),
            "const".into(),
            "parametric".into(),
            "variable".into(),
        ]),
        ..Default::default()
    };
    schema.metadata().description =
        Some("WASM code complexity metric or opcode family.".to_string());
    Schema::Object(schema)
}

fn default_manifest_version() -> u32 {
    1
}

// ── Sub-schemas ──────────────────────────────────────────────────────────────

/// Resource limit bounds to guard against adversarial WASM specs.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfigSchema {
    /// Maximum XDR recursion depth per decoded entry. Must be >= 1. Default: 64.
    #[serde(default)]
    pub max_xdr_depth: Option<u32>,
    /// Maximum bytes decoded per WASM custom section. Must be >= 1. Default: 33,554,432 (32 MiB).
    #[serde(default)]
    pub max_xdr_len: Option<usize>,
    /// Maximum decoded spec entries summed across sections. Must be >= 1. Default: 100,000.
    #[serde(default)]
    pub max_entries: Option<usize>,
    /// Maximum recursion depth for type traversal. Must be >= 1. Default: 128.
    #[serde(default)]
    pub max_walk_depth: Option<usize>,
}

/// Gating policy configuration for compatibility axes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigSchema {
    /// Gate on storage layout breaks. Default: true.
    #[serde(default)]
    pub gate_storage_layout: Option<bool>,
    /// Gate on call ABI breaks. Default: true.
    #[serde(default)]
    pub gate_call_abi: Option<bool>,
    /// Gate on event schema breaks. Default: false.
    #[serde(default)]
    pub gate_event_indexer: Option<bool>,
    /// Gate on source-level breaks. Default: false.
    #[serde(default)]
    pub gate_source_level: Option<bool>,
    /// Gate on runtime surface breaks (host imports, protocol capability). Default: true.
    #[serde(default)]
    pub gate_runtime_surface: Option<bool>,
}

/// Require-reason policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequireReasonPolicySchema {
    /// Canonical rule IDs (snake_case) requiring a non-blank justification when suppressed.
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Compatibility axes requiring a non-blank justification when suppressed.
    #[serde(default)]
    pub axes: Vec<CompatibilityAxisEnum>,
}

/// Explicit type classification configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationConfigSchema {
    /// Exact type names to treat as emitted events.
    #[serde(default)]
    pub events: Vec<String>,
    /// Exact type names to treat as ordinary storage (overrides events list and name heuristic).
    #[serde(default)]
    pub storage: Vec<String>,
    /// Opt-in: treat any type whose name contains "event" (case-insensitive) as an event.
    #[serde(default)]
    pub name_heuristic: Option<bool>,
}

/// Suppression rule acknowledging a specific finding.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppressionRuleSchema {
    /// Canonical snake_case rule identifier (e.g. 'struct_field_removed').
    #[serde(default)]
    #[schemars(schema_with = "rule_id_schema")]
    pub rule_id: Option<String>,
    /// Finding category string to match exactly (e.g. 'Struct Field Removed').
    #[serde(default)]
    #[schemars(schema_with = "category_schema")]
    pub category: Option<String>,
    /// Target entity name (e.g. 'transfer', 'Data.amount', 'Status.Active').
    #[serde(default)]
    pub target: Option<String>,
    /// Human-readable explanation of why this change was reviewed and accepted.
    #[serde(default)]
    pub reason: Option<String>,
    /// Author or reviewer who acknowledged the finding.
    #[serde(default)]
    pub author: Option<String>,
    /// Expiry date in ISO 8601 format (YYYY-MM-DD) after which this rule is invalid.
    #[serde(default)]
    pub expiry: Option<String>,
    /// SHA-256 fingerprint hex of the finding content to guard against message drift.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Declared data migration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MigrationDeclarationSchema {
    /// Stable identifier for this migration (e.g. 'v2-storage-cutover').
    pub id: String,
    /// Prose description of what the migration does.
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined types this migration rewrites.
    #[serde(default)]
    pub migrates: BTreeSet<String>,
    /// Attestation that the migration runs before any new-code read of old layout.
    #[serde(default)]
    pub runs_before_read: bool,
    /// Contract names this migration applies to (empty means all).
    #[serde(default)]
    pub contracts: BTreeSet<String>,
    /// Specific findings this migration resolves.
    #[serde(default)]
    pub covers: Vec<CoverageClaimSchema>,
}

/// A claim that a specific finding is covered by a migration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageClaimSchema {
    /// Finding category to match.
    pub category: String,
    /// Target entity to match.
    #[serde(default)]
    pub target: Option<String>,
    /// Change fingerprint this claim is pinned to.
    #[serde(default)]
    pub change: Option<String>,
}

/// A finding count budget entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetEntryFileSchema {
    /// Budget scope: "global", "axis", or "rule".
    pub scope: String,
    /// Axis when scope = "axis".
    #[serde(default)]
    pub axis: Option<CompatibilityAxisEnum>,
    /// Rule ID when scope = "rule".
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Optional severity filter: "critical", "warning", or "info".
    #[serde(default)]
    pub severity: Option<FindingSeverityEnum>,
    /// Metric to evaluate: "raw" or "unsuppressed". Default: "unsuppressed".
    #[serde(default)]
    pub metric: Option<BudgetMetricEnum>,
    /// Maximum allowed count for this scope (must be >= 0).
    pub limit: i64,
}

/// Static WASM complexity budget entry.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplexityBudgetEntryFileSchema {
    /// WASM complexity metric name or opcode family.
    #[schemars(schema_with = "complexity_metric_schema")]
    pub metric: String,
    /// Absolute ceiling limit (must be >= 0).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Maximum percentage increase ratio allowed (must be >= 0.0).
    #[serde(default)]
    pub pct_limit: Option<f64>,
}

/// Named policy profile configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfigSchema {
    /// Name of another profile this one inherits from (up to depth 8).
    #[serde(default)]
    pub inherits: Option<String>,
    /// Output format for this profile: "text", "json", "markdown", or "github-actions".
    #[serde(default)]
    pub format: Option<OutputFormatEnum>,
    /// Whether to include remediation explanations for findings.
    #[serde(default)]
    pub explain: Option<bool>,
    /// Whether to exit non-zero on Warnings as well as Critical findings.
    #[serde(default)]
    pub strict: Option<bool>,
    /// Whether to disable ANSI color codes.
    #[serde(default)]
    pub no_color: Option<bool>,
    /// Ceiling on the number of active suppressions allowed under this profile.
    #[serde(default)]
    pub max_suppressions: Option<usize>,
    /// Axis gating overrides under this profile.
    #[serde(default)]
    pub gating: Option<PolicyConfigSchema>,
    /// Axis gating overrides alias for `gating`.
    #[serde(default)]
    pub policy: Option<PolicyConfigSchema>,
    /// Resource limit overrides under this profile.
    #[serde(default)]
    pub limits: Option<LimitsConfigSchema>,
}

/// Default settings applied to every contract pair in a batch manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchDefaultsSchema {
    /// Base directory for resolving relative contract paths in this manifest.
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
    /// Path to a suppression config applied to each pair.
    #[serde(default)]
    pub config: Option<PathBuf>,
    /// Whether to fail on Warning findings.
    #[serde(default)]
    pub strict: Option<bool>,
    /// Whether to include remediation guidance.
    #[serde(default)]
    pub explain: Option<bool>,
    /// Whether to restrict output to ASCII characters.
    #[serde(default)]
    pub ascii: Option<bool>,
    /// Whether to omit timestamps for reproducible diffing.
    #[serde(default)]
    pub no_timestamp: Option<bool>,
    /// Axis gating overrides.
    #[serde(default)]
    pub policy: Option<PolicyConfigSchema>,
    /// Resource limit overrides.
    #[serde(default)]
    pub limits: Option<LimitsConfigSchema>,
}

/// A single contract upgrade pair in a batch manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchPairSchema {
    /// Path to the baseline (old) WASM artifact.
    pub old: PathBuf,
    /// Path to the candidate (new) WASM artifact.
    pub new: PathBuf,
    /// Human-readable name for this contract pair. Defaults to the filename of `new`.
    #[serde(default)]
    pub name: Option<String>,
    /// Stable identifier for CI annotations and filters (alphanumeric, -, _, .).
    #[serde(default)]
    pub id: Option<String>,
    /// Grouping tags for filtering (e.g. ["service:auth", "stage:prod"]).
    #[serde(default)]
    pub labels: Vec<String>,
    /// Declared storage schema manifest for the baseline build.
    #[serde(default, alias = "old-storage-schema")]
    pub old_storage_schema: Option<PathBuf>,
    /// Declared storage schema manifest for the candidate build.
    #[serde(default, alias = "new-storage-schema")]
    pub new_storage_schema: Option<PathBuf>,
    /// Base directory for resolving relative paths for this pair.
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
    /// Suppression config path for this pair.
    #[serde(default)]
    pub config: Option<PathBuf>,
    /// Pair-specific strict mode override.
    #[serde(default)]
    pub strict: Option<bool>,
    /// Pair-specific explain override.
    #[serde(default)]
    pub explain: Option<bool>,
    /// Pair-specific ASCII mode override.
    #[serde(default)]
    pub ascii: Option<bool>,
    /// Pair-specific timestamp omission override.
    #[serde(default)]
    pub no_timestamp: Option<bool>,
    /// Pair-specific policy overrides.
    #[serde(default)]
    pub policy: Option<PolicyConfigSchema>,
    /// Pair-specific resource limit overrides.
    #[serde(default)]
    pub limits: Option<LimitsConfigSchema>,
}

/// Contract dependency edge in a batch manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContractDependencySchema {
    /// The caller contract ID or name.
    pub caller: String,
    /// The callee contract ID or name.
    pub callee: String,
    /// Specific functions the caller relies on. Empty means all functions.
    #[serde(default)]
    pub functions: Vec<String>,
    /// Whether the caller requires this dependency to be valid.
    #[serde(default)]
    pub required: Option<bool>,
}

// ── Root Configuration Documents ─────────────────────────────────────────────

/// Root configuration document for `.safeguard.toml` and `.safeguard.json`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafeguardConfigDocument {
    /// Schema reference for editor autocompletion and hover validation.
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,

    /// Output format for the safety report: "text", "json", "markdown", or "github-actions".
    #[serde(default)]
    pub format: Option<OutputFormatEnum>,

    /// Print a concise remediation explanation for each finding.
    #[serde(default)]
    pub explain: Option<bool>,

    /// Exit with a non-zero code if any Warnings or Critical findings are found.
    #[serde(default)]
    pub strict: Option<bool>,

    /// Do not color terminal output.
    #[serde(default)]
    pub no_color: Option<bool>,

    /// Ceiling on the number of active suppressions allowed before the run fails.
    #[serde(default)]
    pub max_suppressions: Option<usize>,

    /// Allow targetless suppression rules that match findings without a specific target entity.
    #[serde(default)]
    pub allow_targetless: Option<bool>,

    /// Stellar contract ID to fetch on-chain baseline WASM from.
    #[serde(default)]
    pub contract_id: Option<String>,

    /// Stellar RPC endpoint URL.
    #[serde(default)]
    pub rpc_url: Option<String>,

    /// Path to a batch manifest file containing contract pairs.
    #[serde(default)]
    pub manifest: Option<PathBuf>,

    /// Directory containing baseline WASM artifacts for directory comparison.
    #[serde(default)]
    pub old_dir: Option<PathBuf>,

    /// Directory containing candidate WASM artifacts for directory comparison.
    #[serde(default)]
    pub new_dir: Option<PathBuf>,

    /// Positional WASM paths: [old.wasm, new.wasm].
    #[serde(default)]
    pub wasm_paths: Option<Vec<PathBuf>>,

    /// Path to a persistent lineage store tracking historical versions.
    #[serde(default)]
    pub lineage_store: Option<PathBuf>,

    /// Record candidate build in lineage store with this tag.
    #[serde(default)]
    pub record_version: Option<String>,

    /// Mark an existing historical version as retired in the lineage store.
    #[serde(default)]
    pub retire_version: Option<String>,

    /// Maximum live historical versions to validate candidate against.
    #[serde(default)]
    pub max_live_versions: Option<usize>,

    /// Default named profile to activate when `--profile` and `SAFEGUARD_PROFILE` are absent.
    #[serde(default)]
    pub default_profile: Option<String>,

    /// Expected SHA-256 hash (hex) of the on-chain WASM baseline.
    #[serde(default)]
    pub expected_wasm_hash: Option<String>,

    /// Resource bounds for XDR decoding and recursive type traversal.
    #[serde(default)]
    pub limits: Option<LimitsConfigSchema>,

    /// Gating policy for compatibility axes at the base level.
    #[serde(default)]
    pub gating: Option<PolicyConfigSchema>,

    /// Gating policy alias for `gating`.
    #[serde(default)]
    pub policy: Option<PolicyConfigSchema>,

    /// Rules requiring a non-blank justification when suppressed.
    #[serde(default)]
    pub require_reason: Option<RequireReasonPolicySchema>,

    /// Explicit classification of user-defined types as events vs storage types.
    #[serde(default)]
    pub classification: Option<ClassificationConfigSchema>,

    /// Named policy profiles sharing this file's suppressions and classification data.
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfigSchema>,

    /// Acknowledged findings that should no longer fail the run.
    #[serde(default, rename = "suppress")]
    pub suppress: Vec<SuppressionRuleSchema>,

    /// Declared data migrations covering schema changes.
    #[serde(default, rename = "migration")]
    pub migration: Vec<MigrationDeclarationSchema>,

    /// Per-axis and per-rule finding count budgets.
    #[serde(default, rename = "budget")]
    pub budget: Vec<BudgetEntryFileSchema>,

    /// Static complexity budgets for the WASM code section.
    #[serde(default, rename = "complexity_budget")]
    pub complexity_budget: Vec<ComplexityBudgetEntryFileSchema>,

    /// Contract pairs when this config file is also used as a batch manifest.
    #[serde(default, rename = "pairs")]
    pub pairs: Vec<BatchPairSchema>,

    /// Other manifest files to compose in when used as a batch manifest.
    #[serde(default)]
    pub include: Vec<PathBuf>,

    /// Default settings applied to every pair when used as a batch manifest.
    #[serde(default)]
    pub defaults: Option<BatchDefaultsSchema>,

    /// Declared dependency edges when used as a batch manifest.
    #[serde(default)]
    pub dependencies: Vec<ContractDependencySchema>,
}

/// Root batch manifest document for `manifest.toml` and `manifest.json`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchManifestDocument {
    /// Schema reference for editor autocompletion and validation.
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,

    /// Manifest format version. Only version 1 is currently supported.
    #[serde(default = "default_manifest_version")]
    pub version: u32,

    /// Other manifest files to compose in, depth-first, in order.
    #[serde(default)]
    pub include: Vec<PathBuf>,

    /// Default settings applied to every pair declared in this manifest or included fragments.
    #[serde(default)]
    pub defaults: Option<BatchDefaultsSchema>,

    /// The contract upgrade pairs to compare.
    #[serde(default)]
    pub pairs: Vec<BatchPairSchema>,

    /// Declared caller -> callee dependency relationships.
    #[serde(default)]
    pub dependencies: Vec<ContractDependencySchema>,
}

// ── Schema Construction ──────────────────────────────────────────────────────

/// Build the canonical JSON Schema document describing `.safeguard.toml` and `.safeguard.json`.
pub fn config_schema() -> RootSchema {
    let mut schema = schemars::schema_for!(SafeguardConfigDocument);
    schema.schema.metadata().title = Some("Soroban Safeguard Configuration".to_string());
    schema.schema.metadata().description = Some(
        "Machine-readable configuration schema for soroban-upgrade-safeguard (.safeguard.toml / .safeguard.json)."
            .to_string(),
    );
    schema.schema.metadata().id = Some(CONFIG_SCHEMA_ID.to_string());
    schema
}

/// Build the canonical JSON Schema document describing batch manifests.
pub fn manifest_schema() -> RootSchema {
    let mut schema = schemars::schema_for!(BatchManifestDocument);
    schema.schema.metadata().title = Some("Soroban Safeguard Batch Manifest".to_string());
    schema.schema.metadata().description = Some(
        "Machine-readable schema for soroban-upgrade-safeguard batch manifests (manifest.toml / manifest.json)."
            .to_string(),
    );
    schema.schema.metadata().id = Some(MANIFEST_SCHEMA_ID.to_string());
    schema
}

/// Serialize [`config_schema`] to a `serde_json::Value`.
pub fn config_schema_value() -> serde_json::Value {
    serde_json::to_value(config_schema()).expect("config schema serialization is infallible")
}

/// Serialize [`manifest_schema`] to a `serde_json::Value`.
pub fn manifest_schema_value() -> serde_json::Value {
    serde_json::to_value(manifest_schema()).expect("manifest schema serialization is infallible")
}

// ── Editor Completion and Hover Metadata ─────────────────────────────────────

/// A completion item for editor integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditorCompletionItem {
    /// Completion trigger label (e.g. "strict", "max_xdr_depth").
    pub key: String,
    /// Path hierarchy in config (e.g. "limits.max_xdr_depth").
    pub field_path: String,
    /// Value type description (e.g. "boolean", "integer (>= 1)").
    pub value_type: String,
    /// Documentation description for hover tooltip.
    pub description: String,
    /// Allowed enum values if applicable.
    pub enum_values: Vec<String>,
    /// Snippet for editor autocompletion insertion.
    pub snippet: Option<String>,
    /// Default value representation.
    pub default: Option<String>,
}

/// Hover documentation metadata for an editor tooltip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditorHoverMetadata {
    /// Field path in configuration.
    pub field_path: String,
    /// Tooltip header title.
    pub title: String,
    /// Type signature.
    pub type_info: String,
    /// Detailed description.
    pub description: String,
    /// Practical usage example.
    pub examples: Vec<String>,
}

/// Full editor completion and hover catalog generated from canonical schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigEditorCatalog {
    /// Schema version of the catalog.
    pub schema_version: u32,
    /// List of completion items.
    pub completions: Vec<EditorCompletionItem>,
    /// List of hover entries.
    pub hovers: Vec<EditorHoverMetadata>,
}

/// Generate editor completion and hover metadata from the canonical safeguard config schema.
pub fn generate_config_completion() -> ConfigEditorCatalog {
    let mut completions = Vec::new();
    let mut hovers = Vec::new();

    macro_rules! item {
        ($key:expr, $path:expr, $vtype:expr, $desc:expr, $enums:expr, $snip:expr, $def:expr, $ex:expr) => {
            completions.push(EditorCompletionItem {
                key: $key.to_string(),
                field_path: $path.to_string(),
                value_type: $vtype.to_string(),
                description: $desc.to_string(),
                enum_values: $enums.iter().map(|s: &&str| s.to_string()).collect(),
                snippet: Some($snip.to_string()),
                default: $def.map(|s: &str| s.to_string()),
            });
            hovers.push(EditorHoverMetadata {
                field_path: $path.to_string(),
                title: format!("{} ({})", $key, $vtype),
                type_info: $vtype.to_string(),
                description: $desc.to_string(),
                examples: $ex.iter().map(|s: &&str| s.to_string()).collect(),
            });
        };
    }

    // Root fields
    item!(
        "format",
        "format",
        "string (enum)",
        "Output format for safety report: 'text', 'json', 'markdown', or 'github-actions'.",
        &["text", "json", "markdown", "github-actions"],
        "format = \"${1|text,json,markdown,github-actions|}\"",
        Some("text"),
        &["format = \"json\""]
    );
    item!(
        "strict",
        "strict",
        "boolean",
        "Exit with non-zero exit code if any Warning or Critical findings are present.",
        &[],
        "strict = ${1|true,false|}",
        Some("false"),
        &["strict = true"]
    );
    item!(
        "explain",
        "explain",
        "boolean",
        "Print remediation guidance explanations alongside findings.",
        &[],
        "explain = ${1|true,false|}",
        Some("false"),
        &["explain = true"]
    );
    item!(
        "no_color",
        "no_color",
        "boolean",
        "Disable colored terminal output.",
        &[],
        "no_color = ${1|true,false|}",
        Some("false"),
        &["no_color = true"]
    );
    item!(
        "default_profile",
        "default_profile",
        "string",
        "Default named policy profile to activate when --profile is omitted.",
        &[],
        "default_profile = \"${1:dev}\"",
        None,
        &["default_profile = \"dev\""]
    );
    item!(
        "max_suppressions",
        "max_suppressions",
        "integer (>= 0)",
        "Ceiling on active suppressions before the run fails.",
        &[],
        "max_suppressions = ${1:10}",
        Some("10"),
        &["max_suppressions = 10"]
    );
    item!(
        "allow_targetless",
        "allow_targetless",
        "boolean",
        "Allow targetless suppression rules (matching findings without a target entity).",
        &[],
        "allow_targetless = ${1|true,false|}",
        Some("false"),
        &["allow_targetless = true"]
    );

    // Limits
    item!(
        "limits",
        "limits",
        "table",
        "Resource bounds bounding XDR decode depth, byte length, and traversal complexity.",
        &[],
        "[limits]\nmax_xdr_depth = ${1:64}\nmax_xdr_len = ${2:33554432}\n",
        None,
        &["[limits]\nmax_xdr_depth = 64"]
    );
    item!(
        "max_xdr_depth",
        "limits.max_xdr_depth",
        "integer (>= 1)",
        "Maximum XDR recursion depth per entry. Must be >= 1. Default: 64.",
        &[],
        "max_xdr_depth = ${1:64}",
        Some("64"),
        &["max_xdr_depth = 64"]
    );
    item!(
        "max_xdr_len",
        "limits.max_xdr_len",
        "integer (>= 1)",
        "Maximum bytes decoded per custom section. Must be >= 1. Default: 33,554,432 (32 MiB).",
        &[],
        "max_xdr_len = ${1:33554432}",
        Some("33554432"),
        &["max_xdr_len = 33554432"]
    );
    item!(
        "max_entries",
        "limits.max_entries",
        "integer (>= 1)",
        "Maximum decoded spec entries across sections. Must be >= 1. Default: 100,000.",
        &[],
        "max_entries = ${1:100000}",
        Some("100000"),
        &["max_entries = 100000"]
    );
    item!(
        "max_walk_depth",
        "limits.max_walk_depth",
        "integer (>= 1)",
        "Maximum recursion depth for type traversal. Must be >= 1. Default: 128.",
        &[],
        "max_walk_depth = ${1:128}",
        Some("128"),
        &["max_walk_depth = 128"]
    );

    // Policy / Gating
    item!(
        "gating",
        "gating",
        "table",
        "Gating policy configuration for compatibility axes.",
        &[],
        "[gating]\ngate_storage_layout = ${1:true}\ngate_call_abi = ${2:true}\n",
        None,
        &["[gating]\ngate_storage_layout = true"]
    );
    item!(
        "gate_storage_layout",
        "gating.gate_storage_layout",
        "boolean",
        "Whether storage layout changes fail the run. Default: true.",
        &[],
        "gate_storage_layout = ${1|true,false|}",
        Some("true"),
        &["gate_storage_layout = true"]
    );
    item!(
        "gate_call_abi",
        "gating.gate_call_abi",
        "boolean",
        "Whether call ABI signature/type changes fail the run. Default: true.",
        &[],
        "gate_call_abi = ${1|true,false|}",
        Some("true"),
        &["gate_call_abi = true"]
    );
    item!(
        "gate_event_indexer",
        "gating.gate_event_indexer",
        "boolean",
        "Whether event schema changes fail the run. Default: false.",
        &[],
        "gate_event_indexer = ${1|true,false|}",
        Some("false"),
        &["gate_event_indexer = true"]
    );
    item!(
        "gate_source_level",
        "gating.gate_source_level",
        "boolean",
        "Whether source-level SDK breaking changes fail the run. Default: false.",
        &[],
        "gate_source_level = ${1|true,false|}",
        Some("false"),
        &["gate_source_level = false"]
    );
    item!(
        "gate_runtime_surface",
        "gating.gate_runtime_surface",
        "boolean",
        "Whether protocol capabilities or host import changes fail the run. Default: true.",
        &[],
        "gate_runtime_surface = ${1|true,false|}",
        Some("true"),
        &["gate_runtime_surface = true"]
    );

    // Classification
    item!(
        "classification",
        "classification",
        "table",
        "Explicit classification of user-defined types as events vs storage types.",
        &[],
        "[classification]\nevents = [\"${1:TransferEvent}\"]\nstorage = [\"${2:ConfigData}\"]\n",
        None,
        &["[classification]\nevents = [\"Transfer\"]"]
    );
    item!(
        "events",
        "classification.events",
        "array of strings",
        "Exact type names to treat as events.",
        &[],
        "events = [\"${1:EventName}\"]",
        None,
        &["events = [\"Transfer\", \"Approval\"]"]
    );
    item!(
        "storage",
        "classification.storage",
        "array of strings",
        "Exact type names to treat as ordinary storage, overriding event classification.",
        &[],
        "storage = [\"${1:StorageName}\"]",
        None,
        &["storage = [\"PreventList\"]"]
    );
    item!(
        "name_heuristic",
        "classification.name_heuristic",
        "boolean",
        "Opt-in: treat any type whose name contains 'event' as an event.",
        &[],
        "name_heuristic = ${1|true,false|}",
        Some("false"),
        &["name_heuristic = true"]
    );

    // Require reason
    item!(
        "require_reason",
        "require_reason",
        "table",
        "Enforces non-blank justifications for specified rule IDs and compatibility axes.",
        &[],
        "[require_reason]\nrule_ids = [\"${1:struct_field_removed}\"]\naxes = [\"${2:storage_layout}\"]\n",
        None,
        &["[require_reason]\naxes = [\"storage_layout\"]"]
    );

    // Profiles
    item!(
        "profiles",
        "profiles.<name>",
        "table",
        "Named policy profile variant.",
        &[],
        "[profiles.${1:pr}]\ninherits = \"${2:dev}\"\nstrict = true\n",
        None,
        &["[profiles.pr]\ninherits = \"dev\"\nstrict = true"]
    );

    // Suppress
    let categories: Vec<&str> = crate::category::FindingCategory::all()
        .iter()
        .map(|c| c.as_str())
        .collect();
    item!(
        "suppress",
        "suppress",
        "array of tables",
        "Acknowledges reviewed breaking changes so they no longer fail the run.",
        &categories,
        "[[suppress]]\ncategory = \"${1:Struct Field Removed}\"\ntarget = \"${2:Type.field}\"\nreason = \"${3:Justification}\"\n",
        None,
        &["[[suppress]]\ncategory = \"Struct Field Removed\"\ntarget = \"Data.amount\"\nreason = \"Planned migration.\""]
    );

    ConfigEditorCatalog {
        schema_version: CONFIG_SCHEMA_VERSION,
        completions,
        hovers,
    }
}

/// Generate editor completion and hover metadata from the canonical batch manifest schema.
pub fn generate_manifest_completion() -> ConfigEditorCatalog {
    let mut completions = Vec::new();
    let mut hovers = Vec::new();

    macro_rules! item {
        ($key:expr, $path:expr, $vtype:expr, $desc:expr, $enums:expr, $snip:expr, $def:expr, $ex:expr) => {
            completions.push(EditorCompletionItem {
                key: $key.to_string(),
                field_path: $path.to_string(),
                value_type: $vtype.to_string(),
                description: $desc.to_string(),
                enum_values: $enums.iter().map(|s: &&str| s.to_string()).collect(),
                snippet: Some($snip.to_string()),
                default: $def.map(|s: &str| s.to_string()),
            });
            hovers.push(EditorHoverMetadata {
                field_path: $path.to_string(),
                title: format!("{} ({})", $key, $vtype),
                type_info: $vtype.to_string(),
                description: $desc.to_string(),
                examples: $ex.iter().map(|s: &&str| s.to_string()).collect(),
            });
        };
    }

    item!(
        "version",
        "version",
        "integer",
        "Manifest schema version. Supported version: 1.",
        &[],
        "version = 1",
        Some("1"),
        &["version = 1"]
    );
    item!(
        "include",
        "include",
        "array of strings",
        "Other manifest files to compose in, depth-first, in order.",
        &[],
        "include = [\"${1:path/to/fragment.toml}\"]",
        None,
        &["include = [\"common/base.toml\"]"]
    );
    item!(
        "defaults",
        "defaults",
        "table",
        "Settings contributed to every contract pair in the composition.",
        &[],
        "[defaults]\nstrict = ${1:false}\n",
        None,
        &["[defaults]\nbase_dir = \"artifacts\"\nstrict = true"]
    );
    item!(
        "pairs",
        "pairs",
        "array of tables",
        "The contract pairs to compare (baseline build vs candidate build).",
        &[],
        "[[pairs]]\nname = \"${1:contract}\"\nold = \"${2:old.wasm}\"\nnew = \"${3:new.wasm}\"\n",
        None,
        &["[[pairs]]\nname = \"token\"\nold = \"token_v1.wasm\"\nnew = \"token_v2.wasm\""]
    );
    item!(
        "dependencies",
        "dependencies",
        "array of tables",
        "Declared caller -> callee contract dependencies in the batch composition.",
        &[],
        "[[dependencies]]\ncaller = \"${1:caller_contract}\"\ncallee = \"${2:callee_contract}\"\n",
        None,
        &["[[dependencies]]\ncaller = \"vault\"\ncallee = \"token\""]
    );

    ConfigEditorCatalog {
        schema_version: MANIFEST_SCHEMA_VERSION,
        completions,
        hovers,
    }
}

/// Generate canonical Markdown documentation for the safeguard configuration schema.
pub fn generate_config_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Soroban Upgrade Safeguard Configuration Reference\n\n");
    out.push_str("Schema version: `1.0.0` (Draft-07 JSON Schema)\n\n");
    out.push_str("The `.safeguard.toml` file configures upgrade compatibility analysis, gating policies, profiles, suppressions, budgets, and migrations.\n\n");
    out.push_str("## Top-Level Configuration Options\n\n");
    out.push_str("| Key | Type | Default | Description |\n");
    out.push_str("|---|---|---|---|\n");
    out.push_str(
        "| `$schema` | String | `none` | Schema URI for editor validation and autocomplete |\n",
    );
    out.push_str("| `format` | String | `\"text\"` | Output format: `\"text\"`, `\"json\"`, `\"markdown\"`, `\"github-actions\"` |\n");
    out.push_str("| `strict` | Boolean | `false` | Treat warnings and critical findings as errors (exit code 1) |\n");
    out.push_str("| `explain` | Boolean | `false` | Print actionable remediation instructions for findings |\n");
    out.push_str("| `no_color` | Boolean | `false` | Disable ANSI terminal styling |\n");
    out.push_str("| `max_suppressions` | Integer | `none` | Budget cap on total active suppression rules |\n");
    out.push_str(
        "| `allow_targetless` | Boolean | `false` | Allow suppressions without a target field |\n",
    );
    out.push_str("| `default_profile` | String | `none` | Default profile when `--profile` and `SAFEGUARD_PROFILE` are absent |\n");
    out.push_str("| `lineage_store` | String | `none` | Path to contract lineage store |\n");
    out.push_str(
        "| `record_version` | String | `none` | Version tag to record for the candidate build |\n",
    );
    out.push_str(
        "| `retire_version` | String | `none` | Version tag to mark retired in lineage |\n",
    );
    out.push_str("| `max_live_versions` | Integer | `none` | Maximum historical builds to validate against |\n");
    out.push_str(
        "| `wasm_paths` | Array<String> | `none` | Explicit paths `[old_wasm, new_wasm]` |\n",
    );
    out.push_str(
        "| `contract_id` | String | `none` | Stellar contract address for RPC retrieval |\n",
    );
    out.push_str("| `rpc_url` | String | `none` | Stellar RPC endpoint URL |\n");
    out.push_str("| `manifest` | String | `none` | Path to batch manifest file |\n");
    out.push_str(
        "| `old_dir` | String | `none` | Directory of baseline builds (requires `new_dir`) |\n",
    );
    out.push_str(
        "| `new_dir` | String | `none` | Directory of candidate builds (requires `old_dir`) |\n",
    );
    out.push_str("\n## Subsections\n\n");
    out.push_str("### `[limits]`\n");
    out.push_str("Limits resource consumption during XDR and WASM decoding:\n");
    out.push_str(
        "- `max_xdr_depth` (u32, default 32): Maximum recursion depth for XDR decoders.\n",
    );
    out.push_str("- `max_xdr_len` (usize, default 2097152): Maximum decoded byte length per custom section.\n");
    out.push_str("- `max_entries` (usize, default 1024): Maximum decoded spec entries.\n");
    out.push_str(
        "- `max_walk_depth` (usize, default 32): Maximum type traversal recursion depth.\n\n",
    );
    out.push_str("### `[policy]`\n");
    out.push_str("Compatibility axis gating:\n");
    out.push_str("- `gate_storage_layout` (bool, default true): Storage key/type compatibility.\n");
    out.push_str("- `gate_call_abi` (bool, default true): Invocation interface compatibility.\n");
    out.push_str("- `gate_event_indexer` (bool, default false): Event schema stability.\n");
    out.push_str("- `gate_source_level` (bool, default false): Source code AST compatibility.\n");
    out.push_str(
        "- `gate_runtime_surface` (bool, default false): Runtime host import stability.\n\n",
    );
    out.push_str("### `[require_reason]`\n");
    out.push_str("Enforces non-empty justification reasons on suppressions matching specific rules or axes:\n");
    out.push_str("- `rule_ids`: list of rule ID strings requiring a `reason`.\n");
    out.push_str("- `axes`: list of axis names requiring a `reason` (`storage_layout`, `call_abi`, etc.).\n\n");
    out.push_str("### `[classification]`\n");
    out.push_str("Custom severity overrides (`critical`, `warning`, `info`):\n");
    out.push_str("- `overrides`: Map of category or rule ID to severity level.\n\n");
    out.push_str("### `[profiles.<name>]`\n");
    out.push_str("Reusable named environment profiles supporting single inheritance (`inherits = \"base\"`).\n\n");
    out.push_str("### `[[suppress]]`\n");
    out.push_str("Acknowledge known breaking changes:\n");
    out.push_str("- `category` (string, optional): Display name of finding category.\n");
    out.push_str("- `rule_id` (string, optional): Canonical snake_case finding ID.\n");
    out.push_str("- `target` (string, optional): Target entity identifier.\n");
    out.push_str("- `reason` (string, optional): Human explanation.\n");
    out.push_str("- `author` (string, optional): Acknowledging person.\n");
    out.push_str("- `expiry` (string, optional): Expiration date (YYYY-MM-DD).\n");
    out.push_str("- `fingerprint` (string, optional): SHA-256 finding fingerprint.\n\n");
    out.push_str("### `[[migration]]`\n");
    out.push_str("Declares state migrations:\n");
    out.push_str("- `version` (u32): Target schema migration version.\n");
    out.push_str("- `description` (string, optional): Migration summary.\n\n");
    out.push_str("### `[[budget]]`\n");
    out.push_str("Compatibility finding count budgets per axis or rule.\n\n");
    out.push_str("### `[[complexity_budget]]`\n");
    out.push_str(
        "WASM complexity budgets (`instructions`, `functions`, `globals`, `tables`, etc.).\n",
    );
    out
}

/// Generate canonical Markdown documentation for the batch manifest schema.
pub fn generate_manifest_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Soroban Upgrade Safeguard Batch Manifest Reference\n\n");
    out.push_str("Schema version: `1.0.0` (Draft-07 JSON Schema)\n\n");
    out.push_str("A batch manifest coordinates comparison across multiple contract pairs with composable fragments, shared defaults, and per-pair overrides.\n\n");
    out.push_str("## Top-Level Fields\n\n");
    out.push_str("| Key | Type | Default | Description |\n");
    out.push_str("|---|---|---|---|\n");
    out.push_str(
        "| `$schema` | String | `none` | Schema URI for editor validation and autocomplete |\n",
    );
    out.push_str(
        "| `version` | Integer | `1` | Manifest format version. Only `1` is supported |\n",
    );
    out.push_str(
        "| `include` | Array<String> | `[]` | Included manifest fragment paths (depth <= 8) |\n",
    );
    out.push_str("| `defaults` | Table | `{}` | Default settings applied to every pair |\n");
    out.push_str("| `pairs` | Array<Table> | `[]` | Contract pairs to compare |\n");
    out.push_str(
        "| `dependencies` | Array<Table> | `[]` | Contract caller -> callee dependency edges |\n\n",
    );
    out.push_str("## Pair Fields (`[[pairs]]`)\n\n");
    out.push_str("- `old` (string, required): Baseline WASM path.\n");
    out.push_str("- `new` (string, required): Candidate WASM path.\n");
    out.push_str("- `name` (string, optional): Friendly name for reports.\n");
    out.push_str("- `id` (string, optional): Stable identifier for CI and filtering.\n");
    out.push_str(
        "- `labels` (array of strings, optional): Grouping tags (e.g. `\"service:payments\"`).\n",
    );
    out.push_str("- `old_storage_schema` / `new_storage_schema` (string, optional): Paired storage schemas.\n");
    out.push_str("- `base_dir` (string, optional): Base directory resolving relative paths.\n");
    out.push_str("- `config` (string, optional): Pair-specific suppression config.\n");
    out.push_str(
        "- `strict`, `explain`, `ascii`, `no_timestamp` (boolean, optional): Flag overrides.\n",
    );
    out.push_str("- `policy` (table, optional): Axis gating overrides.\n");
    out.push_str("- `limits` (table, optional): Resource limit overrides.\n");
    out
}

// ── Schema-Aware Diagnostics & Validation Engine ─────────────────────────────

/// A structured validation error or diagnostic with source code location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiagnostic {
    /// File path where diagnostic was identified.
    pub file: PathBuf,
    /// 1-based line number if source location could be determined.
    pub line: Option<usize>,
    /// 1-based column number if source location could be determined.
    pub column: Option<usize>,
    /// Hierarchical field path (e.g. `limits.max_xdr_depth` or `profiles.dev.strct`).
    pub field_path: Option<String>,
    /// Descriptive error message explaining the problem and remediation.
    pub message: String,
}

impl fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let loc = match (self.line, self.column) {
            (Some(l), Some(c)) => format!("{}:{l}:{c}", self.file.display()),
            (Some(l), None) => format!("{}:{l}", self.file.display()),
            _ => format!("{}", self.file.display()),
        };
        if let Some(ref path) = self.field_path {
            write!(f, "{loc}: error at `{path}`: {}", self.message)
        } else {
            write!(f, "{loc}: error: {}", self.message)
        }
    }
}

/// The outcome of schema validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigValidationResult {
    /// Diagnostics identifying invalid schema or policy violations.
    pub diagnostics: Vec<ConfigDiagnostic>,
}

impl ConfigValidationResult {
    pub fn is_valid(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

/// Map byte range span to 1-based (line, column).
pub fn span_to_line_col(content: &str, span: std::ops::Range<usize>) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, b) in content.bytes().enumerate() {
        if i >= span.start {
            break;
        }
        if b == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Locate line and column of a field or section key in TOML or JSON source content.
pub fn find_field_location(content: &str, field_path: &str) -> (Option<usize>, Option<usize>) {
    let segments: Vec<&str> = field_path.split('.').collect();
    if segments.is_empty() {
        return (Some(1), Some(1));
    }

    let last_key = segments.last().copied().unwrap_or(field_path);
    // Remove array indices like [0] from key search
    let clean_key = last_key.split('[').next().unwrap_or(last_key);

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Check for table header [section] or [[array]]
        if (trimmed.starts_with('[') && trimmed.contains(clean_key))
            // Check for key = value in TOML
            || (trimmed.starts_with(clean_key) && trimmed.contains('='))
            // Check for "key": in JSON
            || trimmed.contains(&format!("\"{clean_key}\""))
            || trimmed.contains(&format!("'{clean_key}'"))
        {
            let col = line.find(clean_key).map(|c| c + 1).unwrap_or(1);
            return (Some(line_idx + 1), Some(col));
        }
    }

    (Some(1), Some(1))
}

/// Extract clean field path and message from serde/toml error messages.
fn parse_serde_diagnostic(err_str: &str, content: &str, file: &Path) -> ConfigDiagnostic {
    let mut field_path = None;

    // Check for "unknown field `xyz`"
    if let Some(start) = err_str.find("unknown field `") {
        let rest = &err_str[start + "unknown field `".len()..];
        if let Some(end) = rest.find('`') {
            let field = &rest[..end];
            field_path = Some(field.to_string());
        }
    } else if let Some(start) = err_str.find("missing field `") {
        let rest = &err_str[start + "missing field `".len()..];
        if let Some(end) = rest.find('`') {
            let field = &rest[..end];
            field_path = Some(field.to_string());
        }
    }

    // Extract the most descriptive line (usually the last non-empty line of TOML error)
    let last_line = err_str
        .lines()
        .map(|l| l.trim())
        .rfind(|l| !l.is_empty() && !l.starts_with('|') && !l.starts_with("TOML parse error"))
        .unwrap_or(err_str);

    let mut clean_msg = last_line.to_string();
    if let Some(idx) = clean_msg.rfind(" at line ") {
        clean_msg = clean_msg[..idx].trim().to_string();
    }

    let (line, col) = if let Some(ref path) = field_path {
        find_field_location(content, path)
    } else {
        (Some(1), Some(1))
    };

    ConfigDiagnostic {
        file: file.to_path_buf(),
        line,
        column: col,
        field_path,
        message: clean_msg,
    }
}

/// Validate a safeguard configuration document (.safeguard.toml or .safeguard.json)
/// against both structural schema requirements and domain semantic rules.
pub fn validate_safeguard_config(
    content: &str,
    file: &Path,
) -> Result<SafeguardConfigDocument, Vec<ConfigDiagnostic>> {
    let mut diagnostics = Vec::new();
    let raw = content.strip_prefix('\u{feff}').unwrap_or(content);

    let is_json =
        file.extension().map(|e| e == "json").unwrap_or(false) || raw.trim_start().starts_with('{');

    let doc: SafeguardConfigDocument = if is_json {
        match serde_json::from_str(raw) {
            Ok(d) => d,
            Err(e) => {
                let diag = ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line: Some(e.line()),
                    column: Some(e.column()),
                    field_path: None,
                    message: e.to_string(),
                };
                return Err(vec![diag]);
            }
        }
    } else {
        match toml::from_str(raw) {
            Ok(d) => d,
            Err(e) => {
                let (line, col) = if let Some(span) = e.span() {
                    let (l, c) = span_to_line_col(raw, span);
                    (Some(l), Some(c))
                } else {
                    (None, None)
                };
                let mut diag = parse_serde_diagnostic(&e.to_string(), raw, file);
                if line.is_some() {
                    diag.line = line;
                    diag.column = col;
                }
                return Err(vec![diag]);
            }
        }
    };

    // ── Semantic Validations ─────────────────────────────────────────────────

    // 1. Validate limits ranges (must be >= 1)
    let validate_limits =
        |limits: &LimitsConfigSchema, prefix: &str, diags: &mut Vec<ConfigDiagnostic>| {
            if let Some(0) = limits.max_xdr_depth {
                let path = format!("{prefix}max_xdr_depth");
                let (line, col) = find_field_location(raw, &path);
                diags.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: "max_xdr_depth must be >= 1, found 0".to_string(),
                });
            }
            if let Some(0) = limits.max_xdr_len {
                let path = format!("{prefix}max_xdr_len");
                let (line, col) = find_field_location(raw, &path);
                diags.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: "max_xdr_len must be >= 1, found 0".to_string(),
                });
            }
            if let Some(0) = limits.max_entries {
                let path = format!("{prefix}max_entries");
                let (line, col) = find_field_location(raw, &path);
                diags.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: "max_entries must be >= 1, found 0".to_string(),
                });
            }
            if let Some(0) = limits.max_walk_depth {
                let path = format!("{prefix}max_walk_depth");
                let (line, col) = find_field_location(raw, &path);
                diags.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: "max_walk_depth must be >= 1, found 0".to_string(),
                });
            }
        };

    if let Some(ref limits) = doc.limits {
        validate_limits(limits, "limits.", &mut diagnostics);
    }

    // 2. Validate profiles (limits, cycles, depths, existence)
    for (name, profile) in &doc.profiles {
        let prefix = format!("profiles.{name}.limits.");
        if let Some(ref limits) = profile.limits {
            validate_limits(limits, &prefix, &mut diagnostics);
        }

        // Inheritance validation
        if let Some(ref parent) = profile.inherits {
            if !doc.profiles.contains_key(parent) {
                let path = format!("profiles.{name}.inherits");
                let (line, col) = find_field_location(raw, &path);
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: format!(
                        "profile '{name}' inherits from undeclared profile '{parent}'"
                    ),
                });
            } else {
                // Cycle and depth check
                let mut current = parent.as_str();
                let mut depth = 1;
                let mut visited = BTreeSet::new();
                visited.insert(name.as_str());

                while let Some(parent_profile) = doc.profiles.get(current) {
                    if visited.contains(current) {
                        let path = format!("profiles.{name}.inherits");
                        let (line, col) = find_field_location(raw, &path);
                        diagnostics.push(ConfigDiagnostic {
                            file: file.to_path_buf(),
                            line,
                            column: col,
                            field_path: Some(path),
                            message: format!("inheritance cycle detected involving profile '{name}' and '{current}'"),
                        });
                        break;
                    }
                    visited.insert(current);
                    depth += 1;
                    if depth > 8 {
                        let path = format!("profiles.{name}.inherits");
                        let (line, col) = find_field_location(raw, &path);
                        diagnostics.push(ConfigDiagnostic {
                            file: file.to_path_buf(),
                            line,
                            column: col,
                            field_path: Some(path),
                            message: format!(
                                "inheritance chain for profile '{name}' exceeds maximum depth of 8"
                            ),
                        });
                        break;
                    }
                    if let Some(ref next_parent) = parent_profile.inherits {
                        current = next_parent.as_str();
                    } else {
                        break;
                    }
                }
            }
        }
    }

    // 3. Default profile existence
    if let Some(ref def) = doc.default_profile {
        if !doc.profiles.contains_key(def) {
            let path = "default_profile";
            let (line, col) = find_field_location(raw, path);
            diagnostics.push(ConfigDiagnostic {
                file: file.to_path_buf(),
                line,
                column: col,
                field_path: Some(path.to_string()),
                message: format!("default_profile '{def}' is not declared in [profiles]"),
            });
        }
    }

    // 4. Mutually exclusive / conflicting rule fields
    for (i, rule) in doc.suppress.iter().enumerate() {
        if let (Some(cat), Some(rule_id)) = (&rule.category, &rule.rule_id) {
            let canonical = crate::suppression::canonical_rule_id(cat);
            if canonical != *rule_id {
                let path = format!("suppress[{i}]");
                let (line, col) = find_field_location(raw, &path);
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(format!("{path}.category")),
                    message: format!(
                        "mutually exclusive / conflicting fields: category '{cat}' (rule id '{canonical}') cannot be combined with conflicting rule_id '{rule_id}'"
                    ),
                });
            }
        }
    }

    // 5. Suppressions validation
    let known_categories: BTreeSet<&'static str> = crate::category::FindingCategory::all()
        .iter()
        .map(|c| c.as_str())
        .collect();

    let mut targetless_count = 0;
    for (i, rule) in doc.suppress.iter().enumerate() {
        let path = format!("suppress[{i}]");
        if rule.target.is_none() {
            targetless_count += 1;
        }

        let cat_known = rule
            .category
            .as_deref()
            .map(|c| known_categories.contains(c))
            .unwrap_or(false);
        let rule_id_known = rule
            .rule_id
            .as_deref()
            .map(|r| {
                crate::category::FindingCategory::all()
                    .iter()
                    .any(|c| crate::suppression::canonical_rule_id(c.as_str()) == r)
            })
            .unwrap_or(false);

        if !cat_known && !rule_id_known {
            let cat_str = rule.category.as_deref().unwrap_or("");
            let rule_str = rule.rule_id.as_deref().unwrap_or("");
            let name = if !cat_str.is_empty() {
                cat_str
            } else {
                rule_str
            };
            let (line, col) = find_field_location(raw, &format!("{path}.category"));
            diagnostics.push(ConfigDiagnostic {
                file: file.to_path_buf(),
                line,
                column: col,
                field_path: Some(format!("{path}.category")),
                message: format!(
                    "unknown finding category '{name}' — the tool never emits this category"
                ),
            });
        }
    }

    let allow_targetless = doc.allow_targetless.unwrap_or(false);
    if targetless_count > 0 && !allow_targetless {
        let path = "allow_targetless";
        let (line, col) = find_field_location(raw, path);
        diagnostics.push(ConfigDiagnostic {
            file: file.to_path_buf(),
            line,
            column: col,
            field_path: Some(path.to_string()),
            message: "targetless suppressions are present but 'allow_targetless' is false"
                .to_string(),
        });
    }
    if targetless_count > 3 {
        let path = "suppress";
        let (line, col) = find_field_location(raw, path);
        diagnostics.push(ConfigDiagnostic {
            file: file.to_path_buf(),
            line,
            column: col,
            field_path: Some(path.to_string()),
            message: format!("targetless suppressions ({targetless_count}) exceed ceiling of 3"),
        });
    }

    if let Some(max) = doc.max_suppressions {
        if doc.suppress.len() > max {
            let path = "max_suppressions";
            let (line, col) = find_field_location(raw, path);
            diagnostics.push(ConfigDiagnostic {
                file: file.to_path_buf(),
                line,
                column: col,
                field_path: Some(path.to_string()),
                message: format!(
                    "configured suppressions ({}) exceed maximum limit of {max}",
                    doc.suppress.len()
                ),
            });
        }
    }

    // 6. Require-reason policy validation
    if let Some(ref policy) = doc.require_reason {
        for (i, rule) in doc.suppress.iter().enumerate() {
            let has_reason = rule
                .reason
                .as_deref()
                .map(|r| !r.trim().is_empty())
                .unwrap_or(false);
            if has_reason {
                continue;
            }

            let effective_rule_id = rule.rule_id.clone().unwrap_or_else(|| {
                rule.category
                    .as_deref()
                    .map(crate::suppression::canonical_rule_id)
                    .unwrap_or_default()
            });
            let requires_by_id = policy.rule_ids.contains(&effective_rule_id);

            let empty_spec = crate::spec::ContractSpec::default();
            let requires_by_axis = rule.category.as_deref().is_some_and(|cat| {
                crate::diff::classify_finding_axes(cat, None, &empty_spec, &empty_spec)
                    .into_iter()
                    .any(|a| policy.axes.iter().any(|req| req.as_str() == a.as_str()))
            });

            if requires_by_id || requires_by_axis {
                let path = format!("suppress[{i}].reason");
                let (line, col) = find_field_location(raw, &format!("suppress[{i}]"));
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: format!(
                        "require_reason: rule #{} for '{}' requires a non-empty reason",
                        i + 1,
                        rule.category.as_deref().unwrap_or(&effective_rule_id)
                    ),
                });
            }
        }
    }

    // 7. Complexity budget validation
    for (i, budget) in doc.complexity_budget.iter().enumerate() {
        if crate::wasm_complexity::ComplexityMetric::parse(&budget.metric).is_err() {
            let path = format!("complexity_budget[{i}].metric");
            let (line, col) = find_field_location(raw, &path);
            diagnostics.push(ConfigDiagnostic {
                file: file.to_path_buf(),
                line,
                column: col,
                field_path: Some(path),
                message: format!("unknown complexity metric '{}'", budget.metric),
            });
        }
        if let Some(pct) = budget.pct_limit {
            if pct < 0.0 {
                let path = format!("complexity_budget[{i}].pct_limit");
                let (line, col) = find_field_location(raw, &path);
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(path),
                    message: "pct_limit must be >= 0.0".to_string(),
                });
            }
        }
    }

    if diagnostics.is_empty() {
        Ok(doc)
    } else {
        Err(diagnostics)
    }
}

/// Validate a batch manifest document (.manifest.toml or manifest.json)
/// against both structural schema requirements and domain semantic rules.
pub fn validate_batch_manifest(
    content: &str,
    file: &Path,
) -> Result<BatchManifestDocument, Vec<ConfigDiagnostic>> {
    let mut diagnostics = Vec::new();
    let raw = content.strip_prefix('\u{feff}').unwrap_or(content);

    let is_json =
        file.extension().map(|e| e == "json").unwrap_or(false) || raw.trim_start().starts_with('{');

    let manifest: BatchManifestDocument = if is_json {
        match serde_json::from_str(raw) {
            Ok(m) => m,
            Err(e) => {
                let diag = ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line: Some(e.line()),
                    column: Some(e.column()),
                    field_path: None,
                    message: e.to_string(),
                };
                return Err(vec![diag]);
            }
        }
    } else {
        match toml::from_str(raw) {
            Ok(m) => m,
            Err(e) => {
                let (line, col) = if let Some(span) = e.span() {
                    let (l, c) = span_to_line_col(raw, span);
                    (Some(l), Some(c))
                } else {
                    (None, None)
                };
                let mut diag = parse_serde_diagnostic(&e.to_string(), raw, file);
                if line.is_some() {
                    diag.line = line;
                    diag.column = col;
                }
                return Err(vec![diag]);
            }
        }
    };

    // ── Semantic Validations for Manifest ────────────────────────────────────

    // Version must be 1
    if manifest.version != 1 {
        let path = "version";
        let (line, col) = find_field_location(raw, path);
        diagnostics.push(ConfigDiagnostic {
            file: file.to_path_buf(),
            line,
            column: col,
            field_path: Some(path.to_string()),
            message: format!(
                "unsupported manifest version {}, expected 1",
                manifest.version
            ),
        });
    }

    // Pairs validation: pair IDs
    let mut seen_ids = BTreeSet::new();
    for (i, pair) in manifest.pairs.iter().enumerate() {
        let path = format!("pairs[{i}]");

        if let Some(ref id) = pair.id {
            if id.is_empty()
                || !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                let (line, col) = find_field_location(raw, &format!("{path}.id"));
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(format!("{path}.id")),
                    message: format!(
                        "Invalid pair id '{id}': must be non-empty and contain only [a-zA-Z0-9_.-]"
                    ),
                });
            } else if !seen_ids.insert(id.clone()) {
                let (line, col) = find_field_location(raw, &format!("{path}.id"));
                diagnostics.push(ConfigDiagnostic {
                    file: file.to_path_buf(),
                    line,
                    column: col,
                    field_path: Some(format!("{path}.id")),
                    message: format!("Duplicate pair identifier '{id}'"),
                });
            }
        }
    }

    if diagnostics.is_empty() {
        Ok(manifest)
    } else {
        Err(diagnostics)
    }
}

/// Automatically detect configuration kind and validate from file path.
pub fn validate_config_file(path: &Path) -> Result<(), Vec<ConfigDiagnostic>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        vec![ConfigDiagnostic {
            file: path.to_path_buf(),
            line: None,
            column: None,
            field_path: None,
            message: format!("Failed to read file: {e}"),
        }]
    })?;

    // Determine if it looks like a manifest or a safeguard config
    let trimmed = raw.trim();
    let is_manifest = trimmed.contains("[defaults]")
        || (trimmed.contains("[[pairs]]")
            && !trimmed.contains("[[suppress]]")
            && !trimmed.contains("default_profile"));

    if is_manifest {
        validate_batch_manifest(&raw, path)?;
    } else {
        validate_safeguard_config(&raw, path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_schema_is_valid_json_schema() {
        let schema_val = config_schema_value();
        let obj = schema_val.as_object().expect("schema must be an object");
        assert_eq!(
            obj.get("$schema").and_then(|v| v.as_str()),
            Some("http://json-schema.org/draft-07/schema#")
        );
        let props = obj.get("properties").and_then(|v| v.as_object()).unwrap();
        assert!(props.contains_key("strict"));
        assert!(props.contains_key("format"));
        assert!(props.contains_key("limits"));
        assert!(props.contains_key("gating"));
        assert!(props.contains_key("profiles"));
        assert!(props.contains_key("suppress"));
        assert!(props.contains_key("require_reason"));
        assert!(props.contains_key("classification"));
    }

    #[test]
    fn manifest_schema_is_valid_json_schema() {
        let schema_val = manifest_schema_value();
        let obj = schema_val.as_object().expect("schema must be an object");
        assert_eq!(
            obj.get("$schema").and_then(|v| v.as_str()),
            Some("http://json-schema.org/draft-07/schema#")
        );
        let props = obj.get("properties").and_then(|v| v.as_object()).unwrap();
        assert!(props.contains_key("version"));
        assert!(props.contains_key("defaults"));
        assert!(props.contains_key("pairs"));
    }

    #[test]
    fn completion_catalog_generates_valid_items() {
        let catalog = generate_config_completion();
        assert_eq!(catalog.schema_version, CONFIG_SCHEMA_VERSION);
        assert!(!catalog.completions.is_empty());
        assert!(!catalog.hovers.is_empty());

        let strict_item = catalog
            .completions
            .iter()
            .find(|c| c.key == "strict")
            .unwrap();
        assert_eq!(strict_item.value_type, "boolean");

        let format_item = catalog
            .completions
            .iter()
            .find(|c| c.key == "format")
            .unwrap();
        assert!(format_item.enum_values.contains(&"json".to_string()));
    }

    #[test]
    fn validation_accepts_valid_toml() {
        let toml_str = r#"
strict = false
explain = true
format = "text"

[limits]
max_xdr_depth = 32

[profiles.dev]
format = "text"

[[suppress]]
category = "Struct Field Removed"
target = "Data.amount"
reason = "Intentional"
"#;
        let res = validate_safeguard_config(toml_str, Path::new(".safeguard.toml"));
        assert!(res.is_ok());
    }

    #[test]
    fn validation_rejects_unknown_field_with_location() {
        let toml_str = r#"
strict = false
strct_typo = true
"#;
        let errs = validate_safeguard_config(toml_str, Path::new(".safeguard.toml")).unwrap_err();
        assert!(!errs.is_empty());
        let diag = &errs[0];
        assert_eq!(diag.line, Some(3));
        assert!(diag.field_path.as_deref().unwrap().contains("strct_typo"));
    }

    #[test]
    fn validation_rejects_invalid_type_with_location() {
        let toml_str = r#"
strict = "not_a_bool"
"#;
        let errs = validate_safeguard_config(toml_str, Path::new(".safeguard.toml")).unwrap_err();
        assert!(!errs.is_empty());
        let diag = &errs[0];
        assert_eq!(diag.line, Some(2));
    }

    #[test]
    fn validation_rejects_out_of_range_limits() {
        let toml_str = r#"
[limits]
max_xdr_depth = 0
"#;
        let errs = validate_safeguard_config(toml_str, Path::new(".safeguard.toml")).unwrap_err();
        assert!(!errs.is_empty());
        assert!(errs[0].message.contains("max_xdr_depth must be >= 1"));
    }

    #[test]
    fn validation_rejects_profile_cycle() {
        let toml_str = r#"
[profiles.a]
inherits = "b"

[profiles.b]
inherits = "a"
"#;
        let errs = validate_safeguard_config(toml_str, Path::new(".safeguard.toml")).unwrap_err();
        assert!(!errs.is_empty());
        assert!(errs.iter().any(|d| d.message.contains("cycle")));
    }
}
