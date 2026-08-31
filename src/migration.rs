//! Migration framework for saved JSON reports.
//!
//! [`crate::render::RenderableReport`] is what `--format json` writes and what
//! gets stored as a CI or audit artifact — sometimes for a long time. Without
//! an explicit migration path, supporting an old report as the schema evolves
//! means adding another `#[serde(default)]` to the live struct, which quietly
//! reinterprets old data as if it always meant what the field means today.
//! That works for genuinely additive changes, but breaks down the moment a
//! field's *meaning* changes rather than just its presence.
//!
//! This module gives each schema transition its own named, tested step:
//!
//! ```text
//! saved JSON ──probe version──► apply steps 0→1→…→N ──► RenderableReport (version N)
//!                                        │
//!                                        └─► MigrationRecord (what happened, and why)
//! ```
//!
//! - [`LEGACY_SCHEMA_VERSION`] (`0`) names documents written before
//!   `report_schema_version` existed at all — the field is simply absent.
//!   Before this module, [`RenderableReport`]'s `#[serde(default =
//!   "default_schema_version")]` silently treated an absent field as the
//!   *current* version, which is only correct as long as the shape has never
//!   changed. [`upgrade_to_latest`] makes that assumption explicit and
//!   testable instead: a document with no version field is version 0, full
//!   stop, and is migrated forward like any other old document.
//! - [`MIGRATIONS`] is the ordered registry: one [`MigrationStep`] per
//!   transition, applied left to right starting from the document's declared
//!   version. Adding support for a future schema break means adding one step
//!   here, not touching the live struct's defaulting.
//! - A document already at [`REPORT_SCHEMA_VERSION`] takes zero steps —
//!   running [`upgrade_to_latest`] on an already-current (or already-upgraded)
//!   report is a no-op, byte-for-byte, which is what makes re-running it in a
//!   CI pipeline safe.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::render::{RenderableReport, REPORT_SCHEMA_VERSION};

/// The implicit version of any report written before `report_schema_version`
/// existed — recognized by the field's absence, never written explicitly by
/// this tool itself.
pub const LEGACY_SCHEMA_VERSION: u32 = 0;

/// One step's record in a document's migration history, as embedded in the
/// upgraded artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStepRecord {
    pub from: u32,
    pub to: u32,
    pub description: String,
}

/// Migration provenance embedded in an upgraded report: where it started,
/// what happened to get it to [`REPORT_SCHEMA_VERSION`], and which build of
/// the tool did it.
///
/// Absent (`None` on [`RenderableReport::migration`]) for a report written
/// directly by a live run — this field only appears once a document has
/// actually been through [`upgrade_to_latest`]. Re-running the upgrade on an
/// already-upgraded document leaves an existing record untouched, since no
/// new steps apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// The schema version the document declared (or [`LEGACY_SCHEMA_VERSION`]
    /// if the field was absent) before any step ran.
    pub original_schema_version: u32,
    /// Every step actually applied, in order. Empty when the document was
    /// already at [`REPORT_SCHEMA_VERSION`].
    pub steps: Vec<MigrationStepRecord>,
    /// The schema version the document was upgraded to.
    pub migrated_to: u32,
    /// `CARGO_PKG_VERSION` of the binary that performed the migration.
    pub migration_tool_version: String,
}

/// Errors from upgrading a saved report to the latest schema.
#[derive(Debug)]
pub enum MigrationError {
    /// The bytes were not valid JSON, or the (possibly migrated) document
    /// does not match any known report shape.
    Malformed(serde_json::Error),
    /// The document is a JSON object, but not one this tool can read at all
    /// — for example `report_schema_version` present but not a plain
    /// non-negative integer.
    NotAReport { reason: String },
    /// The document declares a schema version newer than this build
    /// supports.
    UnsupportedFutureVersion { found: u32, supported: u32 },
    /// The registry has no contiguous path from the document's version to
    /// [`REPORT_SCHEMA_VERSION`] — a gap in [`MIGRATIONS`]. This is a defect
    /// in the tool's own migration coverage, not a problem with the
    /// document, but it must fail loudly rather than guess at a
    /// reinterpretation the registry never actually defined.
    NoMigrationPath { from: u32, to: u32 },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::Malformed(err) => write!(
                f,
                "not a valid Soroban Upgrade Safeguard JSON report: {err}. \
                 Expected a document produced by `--format json` or a previous \
                 `upgrade-report` run."
            ),
            MigrationError::NotAReport { reason } => {
                write!(f, "not a recognizable saved report: {reason}")
            }
            MigrationError::UnsupportedFutureVersion { found, supported } => write!(
                f,
                "report uses schema version {found}, but this build of \
                 soroban-upgrade-safeguard {} only understands up to version \
                 {supported}. Use a newer build to upgrade this report.",
                env!("CARGO_PKG_VERSION"),
            ),
            MigrationError::NoMigrationPath { from, to } => write!(
                f,
                "no migration path from schema version {from} to {to} is \
                 registered in this build of soroban-upgrade-safeguard {}. \
                 This is a gap in the tool's own migration coverage.",
                env!("CARGO_PKG_VERSION"),
            ),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MigrationError::Malformed(err) => Some(err),
            _ => None,
        }
    }
}

/// One registered transformation from schema version `from` to `to`.
///
/// `apply` operates on the raw [`Value`] rather than a typed struct, because
/// the whole point is to transform data whose *old* shape this build's live
/// types no longer represent — by the time a document reaches version `to`,
/// it must deserialize cleanly as that version's shape, but its `from` shape
/// is data, not a Rust type.
struct MigrationStep {
    from: u32,
    to: u32,
    description: &'static str,
    apply: fn(Value) -> Result<Value, MigrationError>,
}

/// The ordered migration registry: every supported schema transition, one
/// step per transition, applied left to right.
///
/// Currently a single step, since [`REPORT_SCHEMA_VERSION`] has only ever
/// been `1`. Adding schema version 2 means appending one more
/// [`MigrationStep`] here — not adding another `#[serde(default)]` to
/// [`RenderableReport`].
static MIGRATIONS: &[MigrationStep] = &[MigrationStep {
    from: LEGACY_SCHEMA_VERSION,
    to: 1,
    description: "Stamp the implicit pre-versioning shape as schema version 1. \
                   No field changed meaning or moved; version 0 is exactly \
                   version 1 with the `report_schema_version` tag itself \
                   absent.",
    apply: stamp_version_1,
}];

fn stamp_version_1(mut value: Value) -> Result<Value, MigrationError> {
    let obj = value
        .as_object_mut()
        .ok_or_else(|| MigrationError::NotAReport {
            reason: "expected a JSON object".to_string(),
        })?;
    obj.insert("report_schema_version".to_string(), Value::from(1u32));
    Ok(value)
}

/// Read `report_schema_version` from a parsed document, treating an absent
/// field as [`LEGACY_SCHEMA_VERSION`] rather than the current version — the
/// distinction [`upgrade_to_latest`] exists to make explicit.
fn declared_version(value: &Value) -> Result<u32, MigrationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| MigrationError::NotAReport {
            reason: "expected a JSON object at the top level".to_string(),
        })?;
    match obj.get("report_schema_version") {
        None => Ok(LEGACY_SCHEMA_VERSION),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| MigrationError::NotAReport {
                reason: format!(
                    "`report_schema_version` must be a non-negative integer, found {n}"
                ),
            }),
        Some(other) => Err(MigrationError::NotAReport {
            reason: format!(
                "`report_schema_version` must be a non-negative integer, found {other}"
            ),
        }),
    }
}

/// Upgrade a saved report — of any supported schema version — to
/// [`REPORT_SCHEMA_VERSION`], returning the upgraded report and a record of
/// what migration (if any) was performed.
///
/// Deterministic and idempotent: the same input always produces the same
/// output, and a document already at [`REPORT_SCHEMA_VERSION`] (including one
/// this function already upgraded) comes back with zero new steps applied and
/// its existing `migration` history, if any, preserved untouched.
///
/// Fails on malformed JSON, a document that isn't recognizably a report, a
/// schema version newer than this build supports, or a gap in the migration
/// registry — never by silently reinterpreting a field.
pub fn upgrade_to_latest(
    json: &str,
) -> Result<(RenderableReport, MigrationRecord), MigrationError> {
    let mut value: Value = serde_json::from_str(json).map_err(MigrationError::Malformed)?;

    let original_version = declared_version(&value)?;
    if original_version > REPORT_SCHEMA_VERSION {
        return Err(MigrationError::UnsupportedFutureVersion {
            found: original_version,
            supported: REPORT_SCHEMA_VERSION,
        });
    }

    let mut current_version = original_version;
    let mut steps = Vec::new();
    while current_version < REPORT_SCHEMA_VERSION {
        let step = MIGRATIONS
            .iter()
            .find(|s| s.from == current_version)
            .ok_or(MigrationError::NoMigrationPath {
                from: current_version,
                to: REPORT_SCHEMA_VERSION,
            })?;
        value = (step.apply)(value)?;
        steps.push(MigrationStepRecord {
            from: step.from,
            to: step.to,
            description: step.description.to_string(),
        });
        current_version = step.to;
    }

    let mut report: RenderableReport =
        serde_json::from_value(value).map_err(MigrationError::Malformed)?;

    let record = MigrationRecord {
        original_schema_version: original_version,
        steps,
        migrated_to: REPORT_SCHEMA_VERSION,
        migration_tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Only stamp a new record when this run actually did something — an
    // already-current document keeps whatever `migration` history (if any)
    // it already carried, which is what makes re-running this idempotent
    // rather than merely no-op-but-destructive-of-history.
    if !record.steps.is_empty() {
        report.migration = Some(record.clone());
    }

    Ok((report, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::CompatibilityAxis;
    use crate::diff::Severity;
    use crate::report::AxisStatus;

    fn minimal_current_value() -> Value {
        serde_json::json!({
            "report_schema_version": 1,
            "provenance": {"tool_version": "0.1.0", "timestamp": ""},
            "is_safe": true,
            "strict": false,
            "counts": {"critical": 0, "warning": 0, "info": 0},
            "suppressed_count": 0,
            "total_findings": 0,
            "recommended_bump": "Patch",
            "storage_coverage": "",
            "findings_by_category": {},
        })
    }

    fn legacy_value_without_version_field() -> Value {
        let mut v = minimal_current_value();
        v.as_object_mut().unwrap().remove("report_schema_version");
        v
    }

    #[test]
    fn legacy_document_without_version_field_migrates_to_current() {
        let json = legacy_value_without_version_field().to_string();
        let (report, record) = upgrade_to_latest(&json).unwrap();

        assert_eq!(report.report_schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(record.original_schema_version, LEGACY_SCHEMA_VERSION);
        assert_eq!(record.migrated_to, REPORT_SCHEMA_VERSION);
        assert_eq!(record.steps.len(), 1);
        assert_eq!(record.steps[0].from, 0);
        assert_eq!(record.steps[0].to, 1);
        assert_eq!(report.migration, Some(record));
    }

    #[test]
    fn a_document_already_current_takes_no_steps() {
        let json = minimal_current_value().to_string();
        let (report, record) = upgrade_to_latest(&json).unwrap();

        assert_eq!(report.report_schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(record.original_schema_version, REPORT_SCHEMA_VERSION);
        assert!(record.steps.is_empty());
        assert_eq!(report.migration, None);
    }

    #[test]
    fn re_running_on_an_upgraded_document_is_idempotent() {
        let json = legacy_value_without_version_field().to_string();
        let (first, first_record) = upgrade_to_latest(&json).unwrap();

        let first_json = serde_json::to_string(&first).unwrap();
        let (second, second_record) = upgrade_to_latest(&first_json).unwrap();

        // No new steps: the history from the first run is preserved exactly.
        assert!(second_record.steps.is_empty());
        assert_eq!(second.migration, first.migration);
        assert_eq!(
            second_record.original_schema_version,
            first_record.migrated_to
        );

        let second_json = serde_json::to_string(&second).unwrap();
        assert_eq!(
            first_json, second_json,
            "a second upgrade must be a byte-for-byte no-op"
        );
    }

    #[test]
    fn an_unsupported_future_version_is_rejected() {
        let mut v = minimal_current_value();
        v["report_schema_version"] = serde_json::json!(REPORT_SCHEMA_VERSION + 5);
        let err = upgrade_to_latest(&v.to_string()).unwrap_err();
        match err {
            MigrationError::UnsupportedFutureVersion { found, supported } => {
                assert_eq!(found, REPORT_SCHEMA_VERSION + 5);
                assert_eq!(supported, REPORT_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedFutureVersion, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = upgrade_to_latest("{ not json").unwrap_err();
        assert!(matches!(err, MigrationError::Malformed(_)));
    }

    #[test]
    fn a_non_object_top_level_is_rejected_as_not_a_report() {
        let err = upgrade_to_latest("[1, 2, 3]").unwrap_err();
        assert!(matches!(err, MigrationError::NotAReport { .. }));
    }

    #[test]
    fn a_non_integer_version_field_is_rejected() {
        let mut v = minimal_current_value();
        v["report_schema_version"] = serde_json::json!("not-a-number");
        let err = upgrade_to_latest(&v.to_string()).unwrap_err();
        assert!(matches!(err, MigrationError::NotAReport { .. }));
    }

    #[test]
    fn migration_preserves_findings_rule_ids_targets_and_suppressions() {
        let mut v = legacy_value_without_version_field();
        v["findings_by_category"] = serde_json::json!({
            "Function Removed": [{
                "rule_id": "fn-removed-transfer",
                "category": "Function Removed",
                "message": "Function 'transfer' was removed.",
                "target": "transfer",
                "root_target": null,
                "axes": ["call_abi"],
                "severity": "critical",
                "suppressed": true,
                "suppression_reason": "Deprecated, replaced by transfer_v2.",
            }]
        });
        v["axis_verdicts"] = serde_json::json!({"call_abi": "failed"});
        v["old_interface_hash"] = serde_json::json!("a".repeat(64));
        v["new_interface_hash"] = serde_json::json!("b".repeat(64));

        let (report, _record) = upgrade_to_latest(&v.to_string()).unwrap();

        let findings = &report.findings_by_category["Function Removed"];
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "fn-removed-transfer");
        assert_eq!(findings[0].finding.target.as_deref(), Some("transfer"));
        assert_eq!(findings[0].finding.severity, Severity::Critical);
        assert!(findings[0].suppressed);
        assert_eq!(
            findings[0].suppression_reason.as_deref(),
            Some("Deprecated, replaced by transfer_v2.")
        );
        assert_eq!(
            report.axis_verdicts.get(&CompatibilityAxis::CallAbi),
            Some(&AxisStatus::Failed)
        );
        assert_eq!(
            report.old_interface_hash.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            report.new_interface_hash.as_deref(),
            Some("b".repeat(64).as_str())
        );
    }

    #[test]
    fn migration_provenance_is_recorded_with_tool_version() {
        let json = legacy_value_without_version_field().to_string();
        let (_report, record) = upgrade_to_latest(&json).unwrap();
        assert_eq!(record.migration_tool_version, env!("CARGO_PKG_VERSION"));
        assert!(record.steps[0].description.contains("version 1"));
    }
}
