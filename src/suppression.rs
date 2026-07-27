//! Suppression configuration for known, intentional breaking changes.
//!
//! Some breaking changes are deliberate and already accounted for (for example
//! a planned storage migration). A suppression config lets a team whitelist
//! specific, reviewed findings so they no longer fail the run — while keeping
//! them visible in the report as explicitly acknowledged.
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
//! Matching is **exact**: a rule applies only when both its stable rule id and
//! its `target` equal the finding's own rule id and [`Finding::target`]. The
//! parser still accepts legacy `category = "..."` entries and maps them to the
//! corresponding rule id for compatibility. A rule that omits `target` matches
//! only findings that themselves have no target (e.g. environment-metadata
//! changes). This deliberate strictness keeps a suppression from over-applying
//! to sibling fields, cases, or parameters.
//!
//! The `target` convention mirrors [`Finding::target`]:
//!
//! - functions: the function name (e.g. `transfer`)
//! - function parameters: `function.param` (e.g. `transfer.to`)
//! - types: the type name (e.g. `Data`)
//! - struct fields: `Type.field` (e.g. `Data.amount`)
//! - enum cases: `Enum.case` (e.g. `Status.Active`)
//!
//! ## Stable category keys
//!
//! Categories describe **structure only** — `"Enum Case Value Changed"`, never
//! `"Event Enum Case Value Changed"`. Whether a type is an event is reported
//! separately in the finding's `classification` field and affects only wording
//! and remediation. That separation is deliberate: a suppression key can never
//! shift because the event classification changed, so a reclassification cannot
//! silently un-suppress (or newly suppress) a real breaking change.
//!
//! Configs written against the older event-flavored names keep working —
//! [`stable_category`] maps each one onto its structural replacement — but new
//! rules should use the structural keys.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::diff::Finding;
use crate::rules::canonical_rule_id;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// A parsed suppression config: a flat list of reviewed acknowledgements.
///
/// `deny_unknown_fields` is deliberate: this is the one config file that can
/// turn the safety gate off, so a mistyped key (`targets`, `[[suppression]]`)
/// must be a loud parse error rather than a silently dropped rule.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionConfig {
    /// Configurable maximum number of suppressions. Enforced globally.
    pub max_suppressions: Option<usize>,
    /// Explicit opt-in for targetless (wildcard) rules.
    pub allow_targetless: Option<bool>,
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    pub rules: Vec<SuppressionRule>,
    /// Explicit event/storage classification (the `[classification]` table).
    ///
    /// Classification only affects a finding's wording, remediation, and
    /// `classification` metadata — never the structural `category` used for
    /// suppression matching — so changing it can never silently move a finding
    /// out from under an existing suppression rule.
    #[serde(default)]
    pub classification: crate::classification::ClassificationConfig,
    /// The `[limits]` table is parsed independently by [`crate::limits`]. We
    /// still declare it here so `deny_unknown_fields` accepts a combined config
    /// carrying both `[[suppress]]` rules and `[limits]`; its contents are
    /// ignored by this parser.
    #[serde(default)]
    #[allow(dead_code)] // Present only so deny_unknown_fields accepts `[limits]`.
    limits: Option<toml::Value>,
}

/// A single whitelisted finding, keyed by category and (optionally) target.
///
/// `deny_unknown_fields` guards against a typo (e.g. `targets` for `target`)
/// silently changing what the rule matches.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionRule {
    /// The stable rule id to match exactly (e.g. `"struct_field_type_changed"`).
    /// Legacy suppression files may still use `category = "Struct Field Type Changed"`.
    #[serde(default, alias = "category")]
    pub rule_id: String,
    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    pub target: Option<String>,
    /// The author of the rule, required for security accountability in the new format.
    #[serde(default)]
    pub author: Option<String>,
    /// The human-readable justification, surfaced in the report.
    #[serde(default)]
    pub reason: Option<String>,
    /// Expiry date for the suppression rule in YYYY-MM-DD format.
    #[serde(default)]
    pub expiry: Option<String>,
    /// Content fingerprint of the finding (SHA-256 hex).
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Map a pre-1.0 event-flavored category onto the structural category that
/// replaced it.
///
/// Categories used to encode the event/storage guess in the string itself
/// (`"Event Enum Case Value Changed"`), which meant a change to the
/// classification heuristic silently moved a finding out from under an
/// existing suppression. Categories are now purely structural and event-ness
/// lives in the separate `classification` field, so these names are no longer
/// emitted — but configs in the wild still reference them. Translating them
/// here keeps those configs working; the docs list the mapping so teams can
/// migrate to the stable keys at their own pace.
pub fn stable_category(category: &str) -> &str {
    match category {
        "Event Definition Removed" => "Struct Removed",
        "Event Field Removed" => "Struct Field Removed",
        "Event Field Reordered" => "Struct Field Reordered",
        "Event Field Type Changed" => "Struct Field Type Changed",
        "Event Enum Removed" => "Enum Removed",
        "Event Enum Case Removed" => "Enum Case Removed",
        "Event Enum Case Value Changed" => "Enum Case Value Changed",
        "Event Enum Case Added" => "Enum Case Added",
        other => other,
    }
}

impl SuppressionRule {
    /// Whether this rule matches `finding` exactly on both rule id and target.
    fn matches(&self, finding: &Finding) -> bool {
        self.canonical_rule_id().is_some_and(|rule_id| {
            canonical_rule_id(stable_category(&finding.category))
                .is_some_and(|finding_rule_id| rule_id == finding_rule_id)
                && self.target.as_deref() == finding.target.as_deref()
                && self
                    .fingerprint
                    .as_ref()
                    .map_or(true, |fp| fp.eq_ignore_ascii_case(&compute_fingerprint(finding)))
        })
    }

    fn canonical_rule_id(&self) -> Option<&'static str> {
        canonical_rule_id(stable_category(&self.rule_id))
    }
}

/// Compute the SHA-256 fingerprint for a finding based on category, target, and message.
pub fn compute_fingerprint(finding: &Finding) -> String {
    let normalized_message = normalize_whitespace(&finding.message);
    let fingerprint_input = format!(
        "category:{}\ntarget:{}\nmessage:{}",
        finding.category,
        finding.target.as_deref().unwrap_or(""),
        normalized_message
    );
    let hash = sha256(fingerprint_input.as_bytes());
    hex::encode(hash)
}

impl SuppressionConfig {
    /// Validate the configuration for security limits, format correctness, and expiration.
    pub fn validate(&self) -> Result<()> {
        let max_allowed = self.max_suppressions.unwrap_or(10);
        if self.rules.len() > max_allowed {
            anyhow::bail!(
                "Configured suppressions ({}) exceed the maximum limit of {}.",
                self.rules.len(),
                max_allowed
            );
        }

        let mut targetless_count = 0;
        for rule in &self.rules {
            if rule.target.is_none() {
                targetless_count += 1;
            }
        }

        if targetless_count > 0 {
            if !self.allow_targetless.unwrap_or(false) {
                anyhow::bail!(
                    "Targetless wildcard suppressions are disabled. Set 'allow_targetless = true' in config to enable."
                );
            }
            if targetless_count > 3 {
                anyhow::bail!(
                    "Number of targetless wildcard suppressions ({}) exceeds the ceiling of 3.",
                    targetless_count
                );
            }
        }

        let mut has_old_format = false;
        for rule in &self.rules {
            if let Some(expiry_str) = &rule.expiry {
                if is_expired(expiry_str)? {
                    anyhow::bail!(
                        "Suppression rule for category '{}' has expired on {}.",
                        rule.rule_id,
                        expiry_str
                    );
                }
            }

            let is_new_format =
                rule.fingerprint.is_some() || rule.author.is_some() || rule.expiry.is_some();
            if is_new_format {
                if rule.author.is_none() {
                    anyhow::bail!(
                        "Missing 'author' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
                if rule.expiry.is_none() {
                    anyhow::bail!(
                        "Missing 'expiry' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
                if rule.fingerprint.is_none() {
                    anyhow::bail!(
                        "Missing 'fingerprint' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
            } else {
                has_old_format = true;
            }
        }
        if has_old_format {
            eprintln!(
                "Warning: Deprecated old-format suppression rule detected. Please update config to use the new secure format."
            );
        }
        Ok(())
    }

    /// Parse a config from a TOML string.
    pub fn from_toml_str(contents: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(contents).context("Failed to parse suppression config as TOML")?;
        config.validate()?;
        Ok(config)
    }

    /// Load a config from an explicit path. Errors if the file is missing or
    /// malformed — callers that pass a path are asserting it should exist.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read suppression config '{}'", path.display()))?;
        Self::from_toml_str(&contents)
            .with_context(|| format!("Invalid suppression config '{}'", path.display()))
    }

    /// Load the default config file if it exists, returning `None` when it is
    /// absent. A present-but-malformed file is still an error, so typos are not
    /// silently ignored. This preserves today's behavior when no config is set.
    pub fn load_optional(path: &Path) -> Result<Option<Self>> {
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

    /// Return the first rule that matches `finding` together with its index, if any.
    /// The index is used by the report layer to track which rules were used.
    pub fn matching_rule_with_index(
        &self,
        finding: &Finding,
    ) -> Option<(usize, &SuppressionRule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches(finding))
    }

    /// Whether any rule matches `finding`.
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.matching_rule(finding).is_some()
    }
}

/// Helper to convert Unix timestamp seconds to UTC (year, month, day).
pub fn seconds_to_ymd(secs: u64) -> (i32, u32, u32) {
    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1444 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + (if m <= 2 { 1 } else { 0 });
    (year as i32, m, d)
}

/// Parses a date in YYYY-MM-DD format.
pub fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y = parts[0].parse().ok()?;
    let m = parts[1].parse().ok()?;
    let d = parts[2].parse().ok()?;
    Some((y, m, d))
}

/// Checks if an expiry date string is in the past.
pub fn is_expired(expiry: &str) -> Result<bool> {
    let (exp_year, exp_month, exp_day) = parse_date(expiry)
        .ok_or_else(|| anyhow::anyhow!("Invalid date format: '{}', expected YYYY-MM-DD", expiry))?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (cur_year, cur_month, cur_day) = seconds_to_ymd(now_secs);

    if cur_year > exp_year {
        Ok(true)
    } else if cur_year < exp_year {
        Ok(false)
    } else if cur_month > exp_month {
        Ok(true)
    } else if cur_month < exp_month {
        Ok(false)
    } else {
        Ok(cur_day > exp_day)
    }
}

/// Collapses whitespace and trims leading/trailing whitespace.
pub fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Pure Rust implementation of SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c82, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut blocks = Vec::new();
    blocks.extend_from_slice(data);
    blocks.push(0x80);
    while (blocks.len() + 8) % 64 != 0 {
        blocks.push(0x00);
    }
    let bit_len = (data.len() as u64) * 8;
    blocks.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in blocks.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        let bytes = h[i].to_be_bytes();
        result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Severity;

    /// Build a finding with the given category and target for matching tests.
    fn finding(category: &str, target: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Critical,
            category: category.to_string(),
            message: "irrelevant to matching".to_string(),
            type_name: target.map(|t| t.split('.').next().unwrap().to_string()),
            target: target.map(|t| t.to_string()),
            classification: None,
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
    fn unknown_key_in_suppress_entry_is_rejected() {
        // `targets` is a typo for `target`; without deny_unknown_fields it would
        // silently load as a targetless rule and change what it matches.
        let err = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            targets  = "Data.amount"
            reason   = "Planned migration"
            "#,
        )
        .expect_err("an unknown key in a suppress entry must be a parse error");

        // The error, including the anyhow context added by load_from_path, must
        // name the offending key so the user can find it.
        let full = format!("{:#}", err);
        assert!(
            full.contains("targets"),
            "error should name the unknown key `targets`, got: {}",
            full
        );
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        // `[[suppression]]` (wrong table name) plus a stray scalar: both are
        // unknown top-level keys and must fail rather than parse to zero rules.
        let err = SuppressionConfig::from_toml_str(
            r#"
            max_supressions = 10

            [[suppression]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .expect_err("an unknown top-level key must be a parse error");

        let full = format!("{:#}", err);
        assert!(
            full.contains("max_supressions") || full.contains("suppression"),
            "error should name the unknown top-level key, got: {}",
            full
        );
    }

    #[test]
    fn limits_table_still_parses_alongside_suppressions() {
        // `[limits]` is parsed independently by crate::limits, but the same file
        // flows through SuppressionConfig too, so the stricter rules must still
        // accept it.
        let config = SuppressionConfig::from_toml_str(
            r#"
            max_suppressions = 10
            allow_targetless = false

            [[suppress]]
            category    = "Struct Field Removed"
            target      = "ConfigData.threshold"
            author      = "Alice <alice@example.com>"
            reason      = "Planned migration."
            expiry      = "2026-12-31"
            fingerprint = "8a3f..."

            [limits]
            max_xdr_depth = 64
            "#,
        )
        .expect("a config carrying both [[suppress]] and [limits] must parse");
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn example_config_still_parses() {
        // Acceptance: the shipped example must keep parsing under the stricter rules.
        let contents = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/.safeguard.example.toml"
        ))
        .expect("failed to read .safeguard.example.toml");
        SuppressionConfig::from_toml_str(&contents)
            .expect(".safeguard.example.toml must parse under deny_unknown_fields");
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
            allow_targetless = true
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
    fn legacy_event_category_still_matches_its_structural_replacement() {
        // A config written before categories became purely structural must keep
        // suppressing the same finding, not silently stop applying.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Event Enum Case Value Changed"
            target   = "StatusEvent.Paused"
            "#,
        )
        .unwrap();

        assert!(config.is_suppressed(&finding(
            "Enum Case Value Changed",
            Some("StatusEvent.Paused")
        )));
        // Aliasing must not widen the target match.
        assert!(!config.is_suppressed(&finding(
            "Enum Case Value Changed",
            Some("StatusEvent.Active")
        )));
    }

    #[test]
    fn stable_categories_are_passed_through_unchanged() {
        for cat in [
            "Struct Field Removed",
            "Enum Case Value Changed",
            "Function Signature Changed",
            "Type Renamed",
            "Environment",
        ] {
            assert_eq!(stable_category(cat), cat);
        }
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
    fn test_compute_fingerprint() {
        let f = Finding {
            severity: Severity::Critical,
            category: "Struct Field Removed".to_string(),
            message: "Struct field threshold of type ConfigData was removed".to_string(),
            type_name: Some("ConfigData".to_string()),
            target: Some("ConfigData.threshold".to_string()),
            classification: None,
        };
        let fp = compute_fingerprint(&f);
        let expected_input = "category:Struct Field Removed\ntarget:ConfigData.threshold\nmessage:Struct field threshold of type ConfigData was removed";
        let expected_hash = sha256(expected_input.as_bytes());
        let expected_fp = hex::encode(expected_hash);
        assert_eq!(fp, expected_fp);
    }

    #[test]
    fn test_seconds_to_ymd_and_is_expired() {
        assert_eq!(seconds_to_ymd(0), (1970, 1, 1));
        assert_eq!(seconds_to_ymd(1709164800), (2024, 2, 29));

        assert!(is_expired("1970-01-01").unwrap());
        assert!(!is_expired("2099-12-31").unwrap());

        // Exact today must not be expired
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (y, m, d) = seconds_to_ymd(now_secs);
        let today_str = format!("{:04}-{:02}-{:02}", y, m, d);
        assert!(!is_expired(&today_str).unwrap());

        assert!(is_expired("invalid-date").is_err());
    }

    #[test]
    fn test_config_validation_limits() {
        let toml_exceed = r#"
            max_suppressions = 1
            [[suppress]]
            category = "CatA"
            [[suppress]]
            category = "CatB"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_exceed).is_err());

        let toml_wildcard_disabled = r#"
            [[suppress]]
            category = "Environment"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_wildcard_disabled).is_err());

        let toml_wildcard_exceed = r#"
            allow_targetless = true
            [[suppress]]
            category = "Env1"
            [[suppress]]
            category = "Env2"
            [[suppress]]
            category = "Env3"
            [[suppress]]
            category = "Env4"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_wildcard_exceed).is_err());

        let toml_missing_new_format = r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            fingerprint = "8a3f..."
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_missing_new_format).is_err());
    }

    #[test]
    fn test_fingerprint_matching() {
        let f = Finding {
            severity: Severity::Critical,
            category: "Struct Field Removed".to_string(),
            message: "Struct field threshold of type ConfigData was removed".to_string(),
            type_name: Some("ConfigData".to_string()),
            target: Some("ConfigData.threshold".to_string()),
            classification: None,
        };
        let fp = compute_fingerprint(&f);

        let toml_str = format!(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            author = "Alice"
            expiry = "2099-12-31"
            fingerprint = "{}"
            "#,
            fp.to_uppercase()
        );
        let config = SuppressionConfig::from_toml_str(&toml_str).unwrap();
        assert!(config.is_suppressed(&f));

        let toml_mismatch = r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            author = "Alice"
            expiry = "2099-12-31"
            fingerprint = "incorrectfingerprint"
        "#;
        let config_mismatch = SuppressionConfig::from_toml_str(toml_mismatch).unwrap();
        assert!(!config_mismatch.is_suppressed(&f));
    }
}
