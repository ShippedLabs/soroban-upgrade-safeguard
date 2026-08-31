//! Suppression configuration for known, intentional breaking changes.
//!
//! Some breaking changes are deliberate and accepted as-is. A suppression
//! config lets a team whitelist specific, reviewed findings so they no longer
//! fail the run — while keeping them visible in the report as explicitly
//! acknowledged.
//!
//! ## Suppression is not the answer for a break you fixed
//!
//! A suppression asserts that a human looked at a finding. It does not assert
//! that anything was done about it, and nothing here verifies that anything
//! was. When the real answer is "we ship a migration that reads the old layout
//! and rewrites it", declare that instead: [`crate::contract_migration`] associates a
//! migration with the findings it resolves and *checks* that it covers every
//! affected type. Reach for suppression when no migration applies — an
//! interface break a caller must absorb, an environment change, a removal
//! nothing stored — not as the routine response to a breaking change.
//!
//! ## File format (`.safeguard.toml`)
//!
//! ```toml
//! # Each [[suppress]] entry acknowledges exactly one reviewed finding.
//! [[suppress]]
//! category = "Struct Field Type Changed"
//! target   = "Data.amount"          # `Type.field` for fields
//! reason   = "Planned migration in v3 widens the balance to i128."
//!
//! [[suppress]]
//! category = "Function Removed"
//! target   = "legacy_init"          # bare name for functions
//! reason   = "Deprecated initializer dropped after the v2 cutover."
//! ```
//!
//! Matching is **exact**: a rule applies only when both its `category` and its
//! `target` equal the finding's own [`Finding::category`] and [`Finding::target`].
//! A rule that omits `target` matches only findings that themselves have no
//! target (e.g. environment-metadata changes). This deliberate strictness keeps
//! a suppression from over-applying to sibling fields, cases, or parameters.
//!
//! The `target` convention mirrors [`Finding::target`]:
//!
//! - functions: the function name (e.g. `transfer`)
//! - function parameters: `function.param` (e.g. `transfer.to`)
//! - types: the type name (e.g. `Data`)
//! - struct fields: `Type.field` (e.g. `Data.amount`)
//! - enum cases: `Enum.case` (e.g. `Status.Active`)
//!
//! ## Requiring a reason for risky suppressions
//!
//! `reason` is optional by default: a rule may suppress a finding with no
//! justification at all. For findings risky enough that an unexplained
//! suppression is not reviewable, an optional `[require_reason]` table
//! names the rule IDs and/or compatibility axes that must carry a non-blank
//! `reason`:
//!
//! ```toml
//! [require_reason]
//! rule_ids = ["struct_field_removed"]
//! axes     = ["storage_layout"]
//!
//! [[suppress]]
//! category = "Struct Field Removed"
//! target   = "Data.amount"
//! reason   = "Planned migration in v3; old data backfilled on read."
//! ```
//!
//! A config that omits `[require_reason]` (or leaves both lists empty)
//! behaves exactly as it did before this policy existed. When present, a
//! rule matching by `rule_id` (or the canonical ID derived from `category`)
//! or by classified axis, whose `reason` is missing or whitespace-only, is a
//! hard load error — [`SuppressionConfig::from_toml_str`] rejects it, so this
//! is enforced on every normal run, not only under `--validate-config`.
//! See [`RequireReasonPolicy`] for the exact axis-matching semantics.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diff::{classify_finding_axes, CompatibilityAxis, Finding};
use crate::error::Error;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// Gating policy configuration for compatibility axes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub gate_storage_layout: bool,
    #[serde(default = "default_true")]
    pub gate_call_abi: bool,
    #[serde(default = "default_false")]
    pub gate_event_indexer: bool,
    #[serde(default = "default_false")]
    pub gate_source_level: bool,
    #[serde(default = "default_true")]
    pub gate_runtime_surface: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            gate_storage_layout: true,
            gate_call_abi: true,
            gate_event_indexer: false,
            gate_source_level: false,
            gate_runtime_surface: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// Compatibility axes and/or rule IDs for which a matching `[[suppress]]`
/// rule's `reason` must be present and non-blank.
///
/// Optional: a config that omits `[require_reason]` (or sets both lists
/// empty) behaves exactly as it did before this policy existed. Configured
/// via:
///
/// ```toml
/// [require_reason]
/// rule_ids = ["struct_field_removed"]
/// axes     = ["storage_layout"]
/// ```
///
/// Rule-ID matching is exact: it compares against the rule's own `rule_id`
/// (or, if unset, the canonical ID derived from its `category`). Axis
/// matching is evaluated statically, the same classification the analyzer
/// itself uses but without diff context (no old/new spec, no type-usage
/// information): for most categories this is exact, since their axis is
/// fixed regardless of context; for struct/enum/union field- and case-level
/// categories, only the always-guaranteed `storage_layout` axis is
/// considered, since whether they also touch `call_abi`/`event_indexer`
/// depends on how the type is actually used in a given contract pair. Use
/// `rule_ids` when a specific category must always require a reason
/// regardless of that ambiguity.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequireReasonPolicy {
    /// Canonical rule IDs (snake_case) that must carry a reason when suppressed.
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Compatibility axes that must carry a reason when suppressed.
    #[serde(default)]
    pub axes: Vec<CompatibilityAxis>,
}

impl RequireReasonPolicy {
    fn is_empty(&self) -> bool {
        self.rule_ids.is_empty() && self.axes.is_empty()
    }
}

/// A parsed suppression config: a flat list of reviewed acknowledgements.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SuppressionConfig {
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    #[cfg(feature = "unstable")]
    pub rules: Vec<SuppressionRule>,
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) rules: Vec<SuppressionRule>,

    /// The declared data migrations, one `[[migration]]` table per entry.
    ///
    /// Suppression and migration are separate axes and never substitute for
    /// each other: a suppression says a human accepted a break, a migration
    /// says code handles it and is verified against the findings. See
    /// [`crate::contract_migration`].
    #[serde(default, rename = "migration")]
    #[cfg(feature = "unstable")]
    pub migrations: Vec<crate::contract_migration::MigrationDeclaration>,
    /// The declared data migrations, one `[[migration]]` table per entry. See
    /// [`crate::contract_migration`].
    #[serde(default, rename = "migration")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) migrations: Vec<crate::contract_migration::MigrationDeclaration>,

    /// Gating policy for compatibility axes.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub policy: PolicyConfig,
    /// Gating policy for compatibility axes.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) policy: PolicyConfig,

    /// Per-axis and per-rule compatibility budgets. Parsed from raw
    /// `[[budget]]` tables and validated by [`Self::load_from_path`] /
    /// [`Self::from_toml_str`] via [`crate::budget::BudgetConfig::from_file_entries`].
    #[serde(default, rename = "budget")]
    raw_budget: Vec<crate::budget::BudgetEntryFile>,
    /// The validated form of `raw_budget`. Always `Some` on a config that
    /// successfully parsed via [`Self::from_toml_str`] / [`Self::load_from_path`];
    /// `None` only for a config built directly with [`SuppressionConfig::default`]
    /// (which has no budgets to validate).
    #[serde(skip)]
    #[cfg(feature = "unstable")]
    pub budgets: crate::budget::BudgetConfig,
    #[serde(skip)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) budgets: crate::budget::BudgetConfig,
    /// Rule IDs / axes for which a matching suppression must carry a
    /// non-blank reason. See [`RequireReasonPolicy`].
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub require_reason: RequireReasonPolicy,
    /// Rule IDs / axes for which a matching suppression must carry a
    /// non-blank reason. See [`RequireReasonPolicy`].
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) require_reason: RequireReasonPolicy,
}

impl SuppressionConfig {
    /// Get reference to raw slice of rules.
    pub fn rules(&self) -> &[SuppressionRule] {
        &self.rules
    }

    /// Get the gating policy configuration.
    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Get the validated compatibility budgets.
    pub fn budgets(&self) -> &crate::budget::BudgetConfig {
        &self.budgets
    }

    /// Get the require-reason policy.
    pub fn require_reason(&self) -> &RequireReasonPolicy {
        &self.require_reason
    }
}

/// A single whitelisted finding, keyed by category and (optionally) target.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuppressionRule {
    #[serde(default)]
    pub rule_id: Option<String>,
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub category: String,
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) category: String,

    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub target: Option<String>,
    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) target: Option<String>,

    /// An optional human-readable justification, surfaced in the report.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub reason: Option<String>,
    /// An optional human-readable justification, surfaced in the report.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) reason: Option<String>,

    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub author: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) author: Option<String>,
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub expiry: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) expiry: Option<String>,
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) fingerprint: Option<String>,
}

impl SuppressionRule {
    /// Create a new suppression rule.
    pub fn new(
        category: impl Into<String>,
        target: Option<impl Into<String>>,
        reason: Option<impl Into<String>>,
    ) -> Self {
        SuppressionRule {
            rule_id: None,
            category: category.into(),
            target: target.map(|s| s.into()),
            reason: reason.map(|s| s.into()),
            author: None,
            expiry: None,
            fingerprint: None,
        }
    }

    /// Get the category to match.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Get the target entity name if specified.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Get the human-readable reason/justification.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl SuppressionRule {
    /// Whether this rule matches `finding` exactly on both category and target.
    fn matches(&self, finding: &Finding) -> bool {
        let category_matches = self.category == finding.category
            || self
                .rule_id
                .as_deref()
                .map(|id| id == canonical_rule_id(&finding.category))
                .unwrap_or(false);
        if !category_matches || self.target.as_deref() != finding.target.as_deref() {
            return false;
        }
        match &self.fingerprint {
            Some(expected) => {
                let input = format!(
                    "category:{}\ntarget:{}\nmessage:{}",
                    finding.category,
                    finding.target.as_deref().unwrap_or(""),
                    finding
                        .message
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                let digest = Sha256::digest(input.as_bytes());
                expected.eq_ignore_ascii_case(&hex::encode(digest))
            }
            None => true,
        }
    }
}

/// Normalize a finding category string into the stable, snake_case rule ID
/// used by [`crate::report::ReportedFinding::rule_id`] and by
/// [`crate::budget`]'s `rule`-scoped budgets, so both name a rule the same
/// way.
pub(crate) fn canonical_rule_id(category: &str) -> String {
    category
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// The category string a rule effectively targets: its own `category` field
/// if set (used as-is, even if unrecognized — `classify_finding_axes` has a
/// sensible fallback for that), else the category derived from `rule_id` by
/// reversing [`canonical_rule_id`] against the known category list. `None`
/// when neither is set.
fn effective_category(rule: &SuppressionRule) -> Option<&str> {
    if !rule.category.is_empty() {
        return Some(rule.category.as_str());
    }
    let rule_id = rule.rule_id.as_deref()?;
    crate::category::FindingCategory::all()
        .iter()
        .find(|c| canonical_rule_id(c.as_str()) == rule_id)
        .map(|c| c.as_str())
}

/// Rules in `rules` that fall under `policy` (by rule ID or classified axis)
/// but whose `reason` is missing or whitespace-only. One description string
/// per offending rule, giving its 1-based position in the config plus
/// whatever identifies it (category/rule_id and target) as a stand-in
/// "source location" — the TOML parser this crate uses does not preserve
/// spans, so a precise line/column is not available.
fn missing_required_reasons(
    rules: &[SuppressionRule],
    policy: &RequireReasonPolicy,
) -> Vec<String> {
    if policy.is_empty() {
        return Vec::new();
    }
    let empty_spec = crate::spec::ContractSpec::default();

    rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            let has_reason = rule.reason.as_deref().is_some_and(|r| !r.trim().is_empty());
            if has_reason {
                return None;
            }

            let effective_rule_id = rule
                .rule_id
                .clone()
                .unwrap_or_else(|| canonical_rule_id(&rule.category));
            let requires_by_id = policy.rule_ids.contains(&effective_rule_id);

            let requires_by_axis = effective_category(rule).is_some_and(|category| {
                classify_finding_axes(category, None, &empty_spec, &empty_spec)
                    .into_iter()
                    .any(|axis| policy.axes.contains(&axis))
            });

            if !requires_by_id && !requires_by_axis {
                return None;
            }

            let identity = if !rule.category.is_empty() {
                rule.category.clone()
            } else {
                effective_rule_id
            };
            let target_desc = rule
                .target
                .as_deref()
                .map(|t| format!(" (target '{t}')"))
                .unwrap_or_default();
            Some(format!(
                "require_reason: rule #{} for '{identity}'{target_desc} requires a non-empty reason",
                index + 1,
            ))
        })
        .collect()
}

impl SuppressionConfig {
    /// Parse a config from a TOML string.
    ///
    /// Enforces the `[require_reason]` policy (if any) as a hard error here,
    /// rather than only in [`Self::validate`], so every loading path —
    /// `--config`, `SOROBAN_SAFEGUARD_CONFIG`, the auto-discovered default,
    /// and batch/manifest mode alike — rejects an unreasoned suppression on
    /// a normal run, not only under `--validate-config`.
    pub fn from_toml_str(contents: &str) -> Result<Self, Error> {
        let mut config: SuppressionConfig =
            toml::from_str(contents).map_err(|e| Error::SuppressionConfig {
                path: None,
                details: "Failed to parse suppression config as TOML".to_string(),
                source: Some(Box::new(e)),
            })?;

        config.budgets =
            crate::budget::BudgetConfig::from_file_entries(std::mem::take(&mut config.raw_budget))
                .map_err(|errors| Error::SuppressionConfig {
                    path: None,
                    details: format!("Invalid [[budget]] configuration: {}", errors.join("; ")),
                    source: None,
                })?;

        let missing_reasons = missing_required_reasons(&config.rules, &config.require_reason);
        if !missing_reasons.is_empty() {
            return Err(Error::SuppressionConfig {
                path: None,
                details: missing_reasons.join("; "),
                source: None,
            });
        }

        Ok(config)
    }

    /// Load a config from an explicit path. Errors if the file is missing or
    /// malformed — callers that pass a path are asserting it should exist.
    pub fn load_from_path(path: &Path) -> Result<Self, Error> {
        let raw = fs::read_to_string(path).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Failed to read suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })?;
        // Strip a leading UTF-8 BOM (common from Windows tooling); TOML has
        // no syntax for it and would otherwise fail on the first character.
        let contents = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
        Self::from_toml_str(contents).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Invalid suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })
    }

    /// Load the default config file if it exists, returning `None` when it is
    /// absent. A present-but-malformed file is still an error, so typos are not
    /// silently ignored. This preserves today's behavior when no config is set.
    pub fn load_optional(path: &Path) -> Result<Option<Self>, Error> {
        if path.exists() {
            Ok(Some(Self::load_from_path(path)?))
        } else {
            Ok(None)
        }
    }

    /// Return the first rule that matches `finding`, if any.
    pub fn matching_rule(&self, finding: &Finding) -> Option<&SuppressionRule> {
        self.rules.iter().find(|rule| rule.matches(finding))
    }

    /// Whether any rule matches `finding`.
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.matching_rule(finding).is_some()
    }

    /// Validate the config on its own, without running a comparison.
    ///
    /// Parsing problems already surface at load time (see
    /// [`Self::load_from_path`]); this second pass catches rules that parse but
    /// can never match anything — most usefully a rule naming a `category` the
    /// tool never emits, which would otherwise silently never fire. It needs no
    /// WASM inputs, so a team can check a `.safeguard.toml` in isolation.
    pub fn validate(&self) -> ConfigValidation {
        let unknown_categories = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                !is_known_category(&rule.category)
                    && !rule
                        .rule_id
                        .as_deref()
                        .map(is_known_rule_id)
                        .unwrap_or(false)
            })
            .map(|(i, rule)| (i + 1, rule.category.clone()))
            .collect();
        let mut errors = Vec::new();
        let max_allowed = self.max_suppressions.unwrap_or(10);
        if self.rules.len() > max_allowed {
            errors.push(format!(
                "configured suppressions ({}) exceed the maximum limit of {}",
                self.rules.len(),
                max_allowed
            ));
        }

        let targetless_count = self
            .rules
            .iter()
            .filter(|rule| rule.target.is_none())
            .count();
        if targetless_count > 0 && !self.allow_targetless.unwrap_or(false) {
            errors.push("targetless suppressions are disabled".to_string());
        }
        if targetless_count > 3 {
            errors.push(format!(
                "targetless suppressions ({targetless_count}) exceed the ceiling of 3"
            ));
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if let Some(expiry) = &rule.expiry {
                match expiry_is_past(expiry) {
                    Ok(true) => errors.push(format!(
                        "rule #{} for '{}' expired on {}",
                        index + 1,
                        rule.category,
                        expiry
                    )),
                    Ok(false) => {}
                    Err(error) => errors.push(format!("rule #{}: {error}", index + 1)),
                }
            }
        }

        errors.extend(missing_required_reasons(&self.rules, &self.require_reason));

        ConfigValidation {
            unknown_categories,
            errors,
        }
    }
}

/// Whether `category` is one the tool can actually emit as a finding category.
///
/// The valid set is shared with the report layer rather than duplicated: a
/// category is recognized exactly when the report has remediation guidance for
/// it, which by construction covers every category the diff stage emits. A rule
/// naming anything outside this set can never match a real finding.
pub fn is_known_category(category: &str) -> bool {
    crate::report::get_remediation_guidance(category).is_some()
}

fn is_known_rule_id(rule_id: &str) -> bool {
    crate::category::FindingCategory::all()
        .iter()
        .any(|category| canonical_rule_id(category.as_str()) == rule_id)
}

/// The outcome of [`SuppressionConfig::validate`].
///
/// A config is valid when this carries no problems. Today the only class of
/// problem detected is a rule naming an unknown category, but the type leaves
/// room to grow (e.g. rules that match nothing during a run).
#[derive(Debug, Default)]
pub struct ConfigValidation {
    /// `(1-based rule number, category)` for every rule whose `category` the
    /// tool never emits.
    pub unknown_categories: Vec<(usize, String)>,
    pub errors: Vec<String>,
}

impl ConfigValidation {
    /// Whether the config is free of detected problems.
    pub fn is_valid(&self) -> bool {
        self.unknown_categories.is_empty() && self.errors.is_empty()
    }
}

fn expiry_is_past(expiry: &str) -> Result<bool, String> {
    let mut parts = expiry.split('-');
    let year: i32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    let month: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    let day: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    if parts.next().is_some() || !valid_date(year, month, day) {
        return Err(format!("invalid expiry '{expiry}', expected YYYY-MM-DD"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(days_from_civil(year, month, day) < (now / 86_400) as i64)
}

fn valid_date(year: i32, month: u32, day: u32) -> bool {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Severity;

    /// Build a finding with the given category and target for matching tests.
    fn finding(category: &str, target: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: category.to_string(),
            message: "irrelevant to matching".to_string(),
            type_name: target.map(|t| t.split('.').next().unwrap().to_string()),
            target: target.map(|t| t.to_string()),
            root_target: None,
            change: None,
        }
    }

    #[test]
    fn empty_config_suppresses_nothing() {
        let config = SuppressionConfig::default();
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.amount"))));
    }

    #[test]
    fn exact_match_on_category_and_target_suppresses() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            reason   = "Planned migration"
            "#,
        )
        .unwrap();

        let f = finding("Struct Field Type Changed", Some("Data.amount"));
        let rule = config.matching_rule(&f).expect("should match exactly");
        assert_eq!(rule.reason.as_deref(), Some("Planned migration"));
    }

    #[test]
    fn different_target_in_same_category_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same category, sibling field -> must NOT over-apply.
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.balance"))));
    }

    #[test]
    fn different_category_same_target_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same target, different category -> must NOT match.
        assert!(!config.is_suppressed(&finding("Struct Field Removed", Some("Data.amount"))));
    }

    #[test]
    fn rule_without_target_matches_only_targetless_findings() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Environment"
            "#,
        )
        .unwrap();

        // A targetless finding in that category matches.
        assert!(config.is_suppressed(&finding("Environment", None)));
        // A finding that *has* a target in the same category does not.
        assert!(!config.is_suppressed(&finding("Environment", Some("Whatever"))));
    }

    #[test]
    fn function_target_matches_bare_name() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            reason   = "Dropped after v2 cutover"
            "#,
        )
        .unwrap();

        assert!(config.is_suppressed(&finding("Function Removed", Some("legacy_init"))));
        assert!(!config.is_suppressed(&finding("Function Removed", Some("transfer"))));
    }

    #[test]
    fn validate_accepts_a_config_of_known_categories() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"

            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(validation.is_valid());
        assert!(validation.unknown_categories.is_empty());
    }

    #[test]
    fn validates_expired_and_future_rules_with_fixed_dates() {
        let expired = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            expiry   = "2000-01-01"
            "#,
        )
        .unwrap();
        let future = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            expiry   = "2100-01-01"
            "#,
        )
        .unwrap();

        let expired_validation = expired.validate();
        let future_validation = future.validate();

        assert!(
            expired_validation
                .errors
                .iter()
                .any(|message| message.contains("expired")),
            "an expired rule must be rejected during validation"
        );
        assert!(
            future_validation.errors.is_empty(),
            "a future-dated rule must remain valid: {:?}",
            future_validation.errors
        );
    }

    #[test]
    fn validate_flags_a_rule_with_an_unknown_category() {
        // "Struct Field Reordded" is a misspelling of "Struct Field Reordered";
        // the tool never emits it, so the rule could never match.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"

            [[suppress]]
            category = "Struct Field Reordded"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(!validation.is_valid());
        assert_eq!(validation.unknown_categories.len(), 1);
        // Reported as the 2nd rule, with the offending category.
        assert_eq!(validation.unknown_categories[0].0, 2);
        assert_eq!(validation.unknown_categories[0].1, "Struct Field Reordded");
    }

    #[test]
    fn is_known_category_matches_the_emitted_set() {
        assert!(is_known_category("Struct Field Removed"));
        assert!(is_known_category("Environment"));
        assert!(!is_known_category("Totally Made Up Category"));
    }

    #[test]
    fn malformed_config_is_a_clear_specific_error() {
        // A key with spaces is not valid TOML.
        let err = SuppressionConfig::from_toml_str("this is not = valid").unwrap_err();
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("suppression config"),
            "error should name the suppression config, got: {message}"
        );
    }

    // ── require_reason policy ──────────────────────────────────────────────

    #[test]
    fn require_reason_policy_disabled_by_default_allows_empty_reason() {
        // No [require_reason] table at all: existing configs must keep working.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            "#,
        )
        .expect("a config with no require_reason policy must still load");
        assert!(config.require_reason.is_empty());
    }

    #[test]
    fn require_reason_policy_present_but_empty_allows_empty_reason() {
        // An explicit but empty [require_reason] table is equivalent to
        // omitting it entirely.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            "#,
        )
        .expect("an empty require_reason table must not require anything");
        assert!(config.require_reason.rule_ids.is_empty());
        assert!(config.require_reason.axes.is_empty());
    }

    #[test]
    fn require_reason_by_rule_id_rejects_missing_reason() {
        let err = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            rule_ids = ["struct_field_removed"]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            "#,
        )
        .expect_err("a gated rule_id with no reason must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("require_reason"),
            "error should name the policy, got: {message}"
        );
    }

    #[test]
    fn require_reason_rejects_whitespace_only_reason_with_newlines_and_tabs() {
        // Not just spaces: a reason made entirely of newlines/tabs (e.g. an
        // accidentally-pasted blank multi-line string) must be rejected the
        // same way, and the error must still identify which suppression rule
        // is affected — not just that *some* rule is missing a reason.
        let err = SuppressionConfig::from_toml_str(
            "
            [require_reason]
            rule_ids = [\"struct_field_removed\"]

            [[suppress]]
            category = \"Struct Field Removed\"
            target   = \"Data.amount\"
            reason   = \"  \\n\\t \\n  \"
            ",
        )
        .expect_err("a reason of only spaces, tabs, and newlines must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("require_reason"),
            "error should name the policy, got: {message}"
        );
        assert!(
            message.contains("Struct Field Removed"),
            "error should identify the affected rule's category, got: {message}"
        );
        assert!(
            message.contains("Data.amount"),
            "error should identify the affected rule's target, got: {message}"
        );
        assert!(
            message.contains("rule #1"),
            "error should identify the affected rule's position, got: {message}"
        );
    }

    #[test]
    fn require_reason_accepts_visible_text_padded_with_whitespace() {
        // A reason with leading/trailing whitespace around real content is
        // not whitespace-only and must be accepted — only entirely-blank
        // reasons are rejected.
        let config = SuppressionConfig::from_toml_str(
            "
            [require_reason]
            rule_ids = [\"struct_field_removed\"]

            [[suppress]]
            category = \"Struct Field Removed\"
            target   = \"Data.amount\"
            reason   = \"  \\n  Planned migration, reviewed in #123.  \\n  \"
            ",
        )
        .expect("a reason with visible text must be accepted even with surrounding whitespace");
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn require_reason_by_rule_id_accepts_present_reason() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            rule_ids = ["struct_field_removed"]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            reason   = "Planned migration, reviewed in #123."
            "#,
        )
        .expect("a gated rule_id with a real reason must load");
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn require_reason_matches_explicit_rule_id_field_too() {
        // The policy's rule_ids list should match a rule's explicit `rule_id`
        // field, not only the id derived from `category`.
        let err = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            rule_ids = ["struct_field_removed"]

            [[suppress]]
            rule_id = "struct_field_removed"
            target  = "Data.amount"
            "#,
        )
        .expect_err("matching via the explicit rule_id field must still be enforced");
        assert!(err.to_string().contains("require_reason"));
    }

    #[test]
    fn require_reason_by_axis_rejects_missing_reason() {
        // "Struct Field Removed" is a storage-layout break (see
        // classify_finding_axes), so gating on the storage_layout axis must
        // catch it even though the policy never names it by rule_id.
        let err = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            axes = ["storage_layout"]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            "#,
        )
        .expect_err("a rule under a gated axis with no reason must be rejected");
        assert!(err.to_string().contains("require_reason"));
    }

    #[test]
    fn require_reason_by_axis_does_not_affect_unrelated_categories() {
        // "Function Removed" is call_abi only, never storage_layout.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            axes = ["storage_layout"]

            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            "#,
        )
        .expect("a rule outside every gated axis must not require a reason");
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn require_reason_mixed_config_only_enforces_configured_rules() {
        // One rule is gated by rule_id and has a reason (ok), one is gated by
        // axis and has none (must fail), one is entirely ungated (ok either way).
        let err = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            rule_ids = ["struct_field_removed"]
            axes     = ["call_abi"]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            reason   = "Planned migration, reviewed in #123."

            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"

            [[suppress]]
            category = "Parameter Renamed"
            target   = "transfer.to"
            "#,
        )
        .expect_err("the call_abi-gated 'Function Removed' rule has no reason");
        let message = err.to_string();
        assert!(message.contains("require_reason"));
        // Source location: the offending rule is #2 (1-based), not #1 or #3.
        assert!(
            message.contains("rule #2"),
            "error should point at rule #2, got: {message}"
        );
        assert!(!message.contains("rule #1"));
        assert!(!message.contains("rule #3"));
    }

    #[test]
    fn require_reason_error_names_category_and_target() {
        let err = SuppressionConfig::from_toml_str(
            r#"
            [require_reason]
            rule_ids = ["struct_field_removed"]

            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"
            "#,
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Struct Field Removed"), "got: {message}");
        assert!(message.contains("Data.amount"), "got: {message}");
        assert!(message.contains("rule #1"), "got: {message}");
    }

    #[test]
    fn require_reason_also_surfaces_through_validate_for_hand_built_configs() {
        // Defense-in-depth: a config assembled programmatically (not via
        // from_toml_str) should still be catchable via .validate().
        let mut config = SuppressionConfig::default();
        config
            .require_reason
            .rule_ids
            .push("struct_field_removed".to_string());
        config.rules.push(SuppressionRule::new(
            "Struct Field Removed",
            Some("Data.amount"),
            None::<String>,
        ));

        let validation = config.validate();
        assert!(!validation.is_valid());
        assert!(validation
            .errors
            .iter()
            .any(|e| e.contains("require_reason")));
    }
}
