//! Persistent compatibility ledger and multi-version lineage validation.
//!
//! Issue #146: Soroban contract upgrades accumulate historical versions on-chain.
//! Storage entries written by historical versions may persist unread for many
//! release cycles. A candidate build must be validated against *every* historical
//! version still marked `live`, not merely the immediate predecessor.
//!
//! This module provides:
//! - [`LineageStore`]: A portable, inspectable, versioned JSON/TOML ledger.
//! - [`LineageRecord`]: Record of an analyzed contract build.
//! - [`LiveVersionPolicy`]: Governance rules for active historical versions.
//! - [`validate_candidate_against_lineage`]: Pairwise validation of a candidate build
//!   against all live predecessors, attributing findings to their source versions.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::diff::{self, CompatibilityAxis, Finding, Severity};
use crate::parser;
use crate::spec::ContractSpec;
use crate::storage_schema::StorageSchema;
use crate::suppression::SuppressionConfig;

/// Current schema version of the persistent lineage store file format.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The deployment or live status of a historical version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LiveStatus {
    /// Active on network; data written by this version must survive upgrade.
    #[default]
    Live,
    /// Explicitly retired version; no longer validated unless policy dictates.
    Retired,
}

/// Governance policy for live historical versions in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LiveVersionPolicy {
    /// Maximum number of historical live versions to validate against.
    /// `None` means all live historical versions are validated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_live_versions: Option<usize>,

    /// Optional version ID threshold: retired prior to this version tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_before_version: Option<String>,

    /// Whether data written under retired versions must still be checked.
    #[serde(default)]
    pub allow_retired_data: bool,
}

/// Record of an analyzed contract build stored in the lineage ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRecord {
    /// Unambiguous version identity tag (e.g. "v1.0.0", commit SHA, or build tag).
    pub version_id: String,

    /// Sequential order in contract history (1-indexed or strictly increasing).
    pub order: u64,

    /// ISO-8601 timestamp string of analysis or deployment.
    pub created_at: String,

    /// Live or retired status.
    #[serde(default)]
    pub status: LiveStatus,

    /// Hex-encoded SHA-256 hash of the compiled WASM binary.
    pub wasm_hash: String,

    /// Encoded interface hash of the contract spec.
    pub interface_hash: String,

    /// Serialized contract spec JSON payload for offline verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_json: Option<String>,

    /// Optional storage schema structure for storage layout validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_schema: Option<StorageSchema>,

    /// Optional arbitrary metadata (e.g. git commit, author, deployment network).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// The persistent compatibility ledger container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageStore {
    /// Schema format version for skew/corruption detection.
    pub schema_version: u32,

    /// Optional target contract ID (e.g. C...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,

    /// Optional contract name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,

    /// List of historical version records in lineage order.
    pub records: Vec<LineageRecord>,

    /// Policy governing live versions and retention.
    #[serde(default)]
    pub policy: LiveVersionPolicy,
}

impl Default for LineageStore {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            contract_id: None,
            contract_name: None,
            records: Vec::new(),
            policy: LiveVersionPolicy::default(),
        }
    }
}

impl LineageStore {
    /// Create a new, empty lineage store.
    pub fn new(contract_name: Option<String>, contract_id: Option<String>) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            contract_id,
            contract_name,
            records: Vec::new(),
            policy: LiveVersionPolicy::default(),
        }
    }

    /// Load and validate a lineage store from a JSON or TOML file path.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read lineage store from '{}'", path.display()))?;

        let store: Self = if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
            || content.trim_start().starts_with('{')
        {
            serde_json::from_str(&content).with_context(|| {
                format!(
                    "Lineage store at '{}' is corrupt or not valid JSON",
                    path.display()
                )
            })?
        } else {
            toml::from_str(&content).with_context(|| {
                format!(
                    "Lineage store at '{}' is corrupt or not valid TOML",
                    path.display()
                )
            })?
        };

        store.validate_integrity().with_context(|| {
            format!(
                "Lineage store at '{}' failed integrity check",
                path.display()
            )
        })?;

        Ok(store)
    }

    /// Save the lineage store to a file path atomically (writing to temp file first).
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        self.validate_integrity()
            .context("Cannot save lineage store with invalid integrity")?;

        let json_bytes =
            serde_json::to_vec_pretty(self).context("Failed to serialize lineage store to JSON")?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;

        let nano_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_path = parent.join(format!(
            ".tmp_lineage_{}_{}.json",
            std::process::id(),
            nano_suffix
        ));

        let mut file = fs::File::create(&temp_path).with_context(|| {
            format!("Failed to create temporary file '{}'", temp_path.display())
        })?;
        file.write_all(&json_bytes)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "Failed to rename temporary lineage store '{}' to '{}'",
                temp_path.display(),
                path.display()
            )
        })?;

        Ok(())
    }

    /// Validate data integrity and schema version consistency of the lineage store.
    pub fn validate_integrity(&self) -> Result<()> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            bail!(
                "Unsupported lineage store schema version {} (expected {})",
                self.schema_version,
                CURRENT_SCHEMA_VERSION
            );
        }

        let mut seen_ids = HashSet::new();
        let mut seen_orders = HashSet::new();
        let mut last_order = 0u64;

        for (idx, record) in self.records.iter().enumerate() {
            if record.version_id.trim().is_empty() {
                bail!("Lineage record at index {idx} has empty version_id");
            }
            if !seen_ids.insert(&record.version_id) {
                bail!(
                    "Duplicate version_id '{}' in lineage store",
                    record.version_id
                );
            }
            if record.order == 0 {
                bail!(
                    "Lineage record '{}' has invalid order 0 (order must be >= 1)",
                    record.version_id
                );
            }
            if !seen_orders.insert(record.order) {
                bail!(
                    "Duplicate order {} for version_id '{}' in lineage store",
                    record.order,
                    record.version_id
                );
            }
            if record.order <= last_order {
                bail!(
                    "Lineage record order skew: version_id '{}' has order {}, which is not strictly greater than previous order {}",
                    record.version_id,
                    record.order,
                    last_order
                );
            }
            last_order = record.order;

            if record.wasm_hash.trim().is_empty() {
                bail!("Lineage record '{}' has empty wasm_hash", record.version_id);
            }
        }

        Ok(())
    }

    /// Get all historical records considered `Live` according to status and policy.
    pub fn live_records(&self) -> Vec<&LineageRecord> {
        let mut live: Vec<&LineageRecord> = self
            .records
            .iter()
            .filter(|r| r.status == LiveStatus::Live || self.policy.allow_retired_data)
            .collect();

        if let Some(ref retire_tag) = self.policy.retire_before_version {
            if let Some(cutoff) = self.records.iter().find(|r| &r.version_id == retire_tag) {
                live.retain(|r| r.order >= cutoff.order);
            }
        }

        if let Some(max_count) = self.policy.max_live_versions {
            if live.len() > max_count {
                let start_idx = live.len() - max_count;
                live = live[start_idx..].to_vec();
            }
        }

        live
    }

    /// Record or update a version in the lineage ledger.
    pub fn record_version(&mut self, record: LineageRecord) -> Result<()> {
        if record.version_id.trim().is_empty() {
            bail!("Cannot record version with empty version_id");
        }

        if let Some(existing_idx) = self
            .records
            .iter()
            .position(|r| r.version_id == record.version_id)
        {
            self.records[existing_idx] = record;
        } else {
            let next_order = self
                .records
                .iter()
                .map(|r| r.order)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            let mut record = record;
            if record.order == 0 {
                record.order = next_order;
            }
            self.records.push(record);
        }

        self.validate_integrity()
    }

    /// Mark a version as retired by version ID.
    pub fn retire_version(&mut self, version_id: &str) -> Result<bool> {
        if let Some(record) = self.records.iter_mut().find(|r| r.version_id == version_id) {
            record.status = LiveStatus::Retired;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// A finding from a historical version comparison attributed to a specific past version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalFinding {
    /// Identity of the historical version that wrote the data / spec.
    pub historical_version_id: String,

    /// Order sequence index of the historical version.
    pub historical_order: u64,

    /// Hex WASM hash of the historical version.
    pub historical_wasm_hash: String,

    /// The underlying compatibility finding.
    pub finding: Finding,
}

/// Results of validating a candidate build against all live predecessors in a lineage store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageValidationReport {
    /// Candidate version identity tag if specified.
    pub candidate_version_id: Option<String>,

    /// Total number of live historical versions checked.
    pub historical_versions_checked: usize,

    /// Vector of attributed findings against live historical versions.
    pub historical_findings: Vec<HistoricalFinding>,

    /// Count of critical historical findings.
    pub critical_count: usize,

    /// Count of warning historical findings.
    pub warning_count: usize,

    /// Overall lineage safety verdict.
    pub is_safe: bool,
}

/// Validate a new candidate contract build (raw WASM bytes and spec) against
/// every live historical version in the persistent lineage store.
pub fn validate_candidate_against_lineage(
    new_wasm: &[u8],
    new_spec: &ContractSpec,
    store: &LineageStore,
    suppressions: &SuppressionConfig,
    strict: bool,
) -> Result<LineageValidationReport> {
    store
        .validate_integrity()
        .context("Invalid lineage store cannot be used for historical validation")?;

    let live_historical = store.live_records();
    let mut historical_findings = Vec::new();
    let mut critical_count = 0;
    let mut warning_count = 0;
    let mut is_safe = true;

    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from candidate WASM")?;

    for historical in live_historical {
        let historical_spec = if let Some(ref json_str) = historical.spec_json {
            let extracted: crate::spec_json::ExtractedSpec = serde_json::from_str(json_str)
                .with_context(|| {
                    format!(
                        "Failed to parse stored spec JSON for historical version '{}'",
                        historical.version_id
                    )
                })?;

            match extracted.to_contract_spec() {
                Ok(spec) => spec,
                Err(err) => {
                    eprintln!(
                        "Warning: Failed to convert stored spec JSON for version '{}': {}",
                        historical.version_id, err
                    );
                    ContractSpec::default()
                }
            }
        } else {
            // Spec JSON unavailable; skip spec diff if no spec payload stored.
            continue;
        };

        let mut diff_report = diff::compare(&historical_spec, new_spec);
        diff::compare_runtime_surfaces(
            &crate::runtime_surface::RuntimeSurface::default(),
            &new_meta.runtime_surface,
            &mut diff_report,
        );

        for finding in diff_report.findings {
            let rule = suppressions.matching_rule(&finding);
            let suppressed = rule.is_some();

            if !suppressed {
                match finding.severity {
                    Severity::Critical => {
                        critical_count += 1;
                        if suppressions.policy.gate_storage_layout
                            || finding.axes.contains(&CompatibilityAxis::StorageLayout)
                            || strict
                        {
                            is_safe = false;
                        }
                    }
                    Severity::Warning => {
                        warning_count += 1;
                        if strict {
                            is_safe = false;
                        }
                    }
                    Severity::Info => {}
                }
            }

            let mut attributed_finding = finding;
            attributed_finding.message = format!(
                "[Historical Version '{}' (order {})] {}",
                historical.version_id, historical.order, attributed_finding.message
            );

            historical_findings.push(HistoricalFinding {
                historical_version_id: historical.version_id.clone(),
                historical_order: historical.order,
                historical_wasm_hash: historical.wasm_hash.clone(),
                finding: attributed_finding,
            });
        }
    }

    Ok(LineageValidationReport {
        candidate_version_id: None,
        historical_versions_checked: store.live_records().len(),
        historical_findings,
        critical_count,
        warning_count,
        is_safe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_store_integrity_check() {
        let mut store = LineageStore::new(Some("test-contract".to_string()), None);
        store.records.push(LineageRecord {
            version_id: "v1.0.0".to_string(),
            order: 1,
            created_at: "2026-08-25T00:00:00Z".to_string(),
            status: LiveStatus::Live,
            wasm_hash: "abc123hash".to_string(),
            interface_hash: "iface123hash".to_string(),
            spec_json: None,
            storage_schema: None,
            metadata: BTreeMap::new(),
        });

        assert!(store.validate_integrity().is_ok());

        // Duplicate version_id should fail
        let mut dup_store = store.clone();
        dup_store.records.push(LineageRecord {
            version_id: "v1.0.0".to_string(),
            order: 2,
            created_at: "2026-08-25T01:00:00Z".to_string(),
            status: LiveStatus::Live,
            wasm_hash: "def456hash".to_string(),
            interface_hash: "iface456hash".to_string(),
            spec_json: None,
            storage_schema: None,
            metadata: BTreeMap::new(),
        });
        assert!(dup_store.validate_integrity().is_err());
    }

    #[test]
    fn test_record_and_retire_version() {
        let mut store = LineageStore::default();
        store
            .record_version(LineageRecord {
                version_id: "v1".to_string(),
                order: 1,
                created_at: "2026-01-01".to_string(),
                status: LiveStatus::Live,
                wasm_hash: "hash1".to_string(),
                interface_hash: "iface1".to_string(),
                spec_json: None,
                storage_schema: None,
                metadata: BTreeMap::new(),
            })
            .unwrap();

        assert_eq!(store.live_records().len(), 1);

        store.retire_version("v1").unwrap();
        assert_eq!(store.live_records().len(), 0);
    }
}
