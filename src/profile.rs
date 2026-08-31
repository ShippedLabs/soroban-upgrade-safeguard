//! Named policy profiles for `.safeguard.toml`.
//!
//! One repository often needs different policies for local development, pull
//! requests, release candidates, and emergency validation. Maintaining a
//! separate config file per situation duplicates the shared `[[suppress]]`
//! records and classification data; editing one shared file in place makes a
//! run hard to reproduce (which policy was actually in effect?).
//!
//! Named profiles solve this by letting `.safeguard.toml` declare several
//! named policy variants that share one file. A profile controls only the
//! *policy* settings — gating, severity (`strict`), the suppression budget
//! (`max_suppressions`), resource limits, and output formatting. Suppression
//! records (`[[suppress]]`) and classification data stay in the file itself,
//! shared by every profile.
//!
//! ```toml
//! # Base config: applies when no profile is selected, and is the foundation
//! # every profile builds on.
//! strict = false
//!
//! [profiles.dev]
//! format = "text"
//!
//! [profiles.pr]
//! inherits = "dev"
//! strict   = true
//!
//! [profiles.pr.gating]
//! gate_event_indexer = true
//!
//! [profiles.release]
//! inherits = "pr"
//! format   = "json"
//!
//! [profiles.release.limits]
//! max_xdr_depth = 32
//! ```
//!
//! Select a profile with `--profile <NAME>`, or set `default_profile` in the
//! file so a bare invocation picks one up. `--profile` and the
//! `SAFEGUARD_PROFILE` environment variable both win over `default_profile`.
//!
//! # Precedence
//!
//! Two rules, matching [`crate::manifest`]'s split of "valued" vs.
//! "escalation" settings:
//!
//! **Valued settings** — `format`, `max_suppressions`, `gating.*`, `limits.*`
//! — last writer wins:
//!
//! ```text
//! built-in default  <  base configuration  <  inherited profiles (root to leaf)  <  selected profile  <  CLI / env
//! ```
//!
//! Note the selected profile *is* the leaf of its own inheritance chain, so
//! "inherited profiles" and "selected profile" are really one ordered fold —
//! ancestors first, most specific (the selected profile) last.
//!
//! **Escalation booleans** — `strict`, `explain`, `no_color` — OR-chain: any
//! layer may enable, none may disable. A `dev` profile with `strict = false`
//! cannot silently weaken a `strict = true` set at the base or on the CLI.
//! `gating.*` are booleans too but are *valued*, not escalation: being able to
//! turn a gate off is the entire point of a profile.
//!
//! # Inheritance
//!
//! A profile may declare `inherits = "<name>"` to build on another named
//! profile. Chains are walked to a bounded depth ([`MAX_PROFILE_DEPTH`]) and
//! checked for cycles; both failures name the full chain so the mistake is
//! easy to find. Selecting or inheriting from a name that isn't declared is a
//! hard error, as is any unknown field in a `[profiles.<name>]` table
//! (`deny_unknown_fields`).

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize, Serializer};

use crate::config::OutputFormat;
use crate::limits::{LimitsConfig, ResourcePolicy};
use crate::manifest::PolicyOverrides;
use crate::suppression::PolicyConfig;

/// Maximum depth of a profile's `inherits` chain (the profile itself counts
/// as depth 1). Bounded so a mistaken or generated config fails fast with a
/// readable chain instead of recursing indefinitely.
pub const MAX_PROFILE_DEPTH: usize = 8;

// ── Raw (on-disk) schema ─────────────────────────────────────────────────────

/// One `[profiles.<name>]` table exactly as written on disk.
///
/// Every field is optional: an omitted field simply does not contribute a
/// layer to the fold, leaving whatever the base configuration or an ancestor
/// profile already set.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProfile {
    /// The name of another profile this one builds on. Resolved before this
    /// profile's own fields are applied, so this profile's fields win on
    /// conflict.
    #[serde(default)]
    pub inherits: Option<String>,
    #[serde(default)]
    pub format: Option<OutputFormat>,
    #[serde(default)]
    pub explain: Option<bool>,
    #[serde(default)]
    pub strict: Option<bool>,
    #[serde(default)]
    pub no_color: Option<bool>,
    #[serde(default)]
    pub max_suppressions: Option<usize>,
    /// Axis gating overrides. Field-for-field with [`PolicyConfig`].
    #[serde(default)]
    pub gating: PolicyOverrides,
    /// Resource limit overrides.
    #[serde(default)]
    pub limits: LimitsConfig,
}

// ── Provenance ───────────────────────────────────────────────────────────────

/// Where a resolved profile-controlled value came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Origin {
    /// The compiled-in default, because no layer set the value.
    #[default]
    BuiltIn,
    /// The base configuration — the fields set at the root of the file,
    /// outside any `[profiles.<name>]` table.
    BaseConfig,
    /// A named profile, by name. Includes both ancestors and the selected
    /// profile itself.
    Profile(String),
    /// A command-line flag or its equivalent environment variable.
    Cli,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::BuiltIn => write!(f, "built-in"),
            Origin::BaseConfig => write!(f, "base config"),
            Origin::Profile(name) => write!(f, "profile '{name}'"),
            Origin::Cli => write!(f, "cli"),
        }
    }
}

impl Serialize for Origin {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// A resolved value paired with the layer that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sourced<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T> Sourced<T> {
    fn built_in(value: T) -> Self {
        Self {
            value,
            origin: Origin::BuiltIn,
        }
    }
}

impl<T: Default> Default for Sourced<T> {
    fn default() -> Self {
        Self::built_in(T::default())
    }
}

/// Axis gating after the precedence fold, one origin per gate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResolvedGating {
    pub gate_storage_layout: Sourced<bool>,
    pub gate_call_abi: Sourced<bool>,
    pub gate_event_indexer: Sourced<bool>,
    pub gate_source_level: Sourced<bool>,
    pub gate_runtime_surface: Sourced<bool>,
}

/// Resource limits after the precedence fold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResolvedLimits {
    pub max_xdr_depth: Sourced<u32>,
    pub max_xdr_len: Sourced<usize>,
    pub max_entries: Sourced<usize>,
    pub max_walk_depth: Sourced<usize>,
}

/// The fully resolved, deterministic outcome of profile selection: which
/// profile (if any) was selected, its full inheritance chain, and every
/// profile-controlled setting with the layer that produced it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResolvedProfile {
    /// The profile named on the CLI, via `SAFEGUARD_PROFILE`, or via
    /// `default_profile` in the file. `None` when nothing selected one.
    pub selected: Option<String>,
    /// The full inheritance chain, root ancestor first, selected profile
    /// last. Empty when no profile was selected.
    pub chain: Vec<String>,
    pub format: Sourced<OutputFormat>,
    pub explain: Sourced<bool>,
    pub strict: Sourced<bool>,
    pub no_color: Sourced<bool>,
    pub max_suppressions: Sourced<Option<usize>>,
    pub gating: ResolvedGating,
    pub limits: ResolvedLimits,
}

// ── Inputs ───────────────────────────────────────────────────────────────────

/// The profile-controlled settings read from the base configuration (the
/// fields at the root of `.safeguard.toml`, outside any profile table).
#[derive(Debug, Clone, Default)]
pub struct BaseValues {
    pub format: Option<OutputFormat>,
    pub explain: Option<bool>,
    pub strict: Option<bool>,
    pub no_color: Option<bool>,
    pub max_suppressions: Option<usize>,
    pub gating: PolicyOverrides,
    pub limits: LimitsConfig,
}

/// The CLI/environment half of the precedence chain. Both are treated as one
/// [`Origin::Cli`] layer: an environment variable is, for provenance
/// purposes, just a CLI flag that happens to be set another way.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub format: Option<OutputFormat>,
    /// Escalation-only: `true` if either the CLI flag or its environment
    /// variable was set. There is no way to force this *off* from the CLI,
    /// matching [`crate::config::ResolvedConfig::resolve`]'s existing
    /// behavior for `--strict`, `--explain`, and `--no-color`.
    pub strict: bool,
    pub explain: bool,
    pub no_color: bool,
    pub max_suppressions: Option<usize>,
    pub max_xdr_depth: Option<u32>,
    pub max_xdr_len: Option<usize>,
    pub max_entries: Option<usize>,
    pub max_walk_depth: Option<usize>,
}

// ── Resolution ───────────────────────────────────────────────────────────────

/// One layer in the fold: the base configuration, or one profile in the
/// selected profile's inheritance chain.
struct Layer {
    origin: Origin,
    format: Option<OutputFormat>,
    explain: Option<bool>,
    strict: Option<bool>,
    no_color: Option<bool>,
    max_suppressions: Option<usize>,
    gating: PolicyOverrides,
    limits: LimitsConfig,
}

/// Resolve `selected` (if any) against `profiles`, folding `base` and `cli`
/// on top per the precedence rules documented at module level.
///
/// Fails on a missing profile (selected or inherited), an inheritance cycle,
/// or a chain deeper than [`MAX_PROFILE_DEPTH`]. Unknown fields and
/// incompatible value types are rejected earlier, by `serde` while parsing
/// `[profiles.<name>]` itself (see [`RawProfile`]).
pub fn resolve(
    profiles: &BTreeMap<String, RawProfile>,
    selected: Option<&str>,
    base: BaseValues,
    cli: CliOverrides,
) -> Result<ResolvedProfile> {
    let chain = match selected {
        Some(name) => build_chain(name, profiles)?,
        None => Vec::new(),
    };

    let mut layers = Vec::with_capacity(chain.len() + 1);
    layers.push(Layer {
        origin: Origin::BaseConfig,
        format: base.format,
        explain: base.explain,
        strict: base.strict,
        no_color: base.no_color,
        max_suppressions: base.max_suppressions,
        gating: base.gating,
        limits: base.limits,
    });
    for name in &chain {
        // `build_chain` only ever returns names it found in `profiles`.
        let profile = profiles
            .get(name)
            .expect("chain names are validated to exist in `profiles`");
        layers.push(Layer {
            origin: Origin::Profile(name.clone()),
            format: profile.format,
            explain: profile.explain,
            strict: profile.strict,
            no_color: profile.no_color,
            max_suppressions: profile.max_suppressions,
            gating: profile.gating,
            limits: profile.limits.clone(),
        });
    }

    // Escalation booleans: the CLI/env layer wins immediately if set; else the
    // first layer (base configuration outranking no one, then ancestors
    // before the selected profile) to enable it wins. No layer can disable a
    // setting an earlier layer enabled.
    let escalate = |cli_value: bool, get: fn(&Layer) -> Option<bool>| -> Sourced<bool> {
        if cli_value {
            return Sourced {
                value: true,
                origin: Origin::Cli,
            };
        }
        for layer in &layers {
            if get(layer) == Some(true) {
                return Sourced {
                    value: true,
                    origin: layer.origin.clone(),
                };
            }
        }
        Sourced::built_in(false)
    };

    // Valued settings: last writer wins, CLI/env outranking every layer.
    let mut format = Sourced::built_in(OutputFormat::default());
    for layer in &layers {
        if let Some(v) = layer.format {
            format = Sourced {
                value: v,
                origin: layer.origin.clone(),
            };
        }
    }
    if let Some(v) = cli.format {
        format = Sourced {
            value: v,
            origin: Origin::Cli,
        };
    }

    let mut max_suppressions: Sourced<Option<usize>> = Sourced::built_in(None);
    for layer in &layers {
        if let Some(v) = layer.max_suppressions {
            max_suppressions = Sourced {
                value: Some(v),
                origin: layer.origin.clone(),
            };
        }
    }
    if let Some(v) = cli.max_suppressions {
        max_suppressions = Sourced {
            value: Some(v),
            origin: Origin::Cli,
        };
    }

    let gate = |get: fn(&PolicyOverrides) -> Option<bool>, default: bool| -> Sourced<bool> {
        let mut current = Sourced::built_in(default);
        for layer in &layers {
            if let Some(v) = get(&layer.gating) {
                current = Sourced {
                    value: v,
                    origin: layer.origin.clone(),
                };
            }
        }
        current
    };
    let gating_defaults = PolicyConfig::default();

    let base_limits = ResourcePolicy::default();
    macro_rules! limit {
        ($field:ident, $cli_field:expr) => {{
            let mut current = Sourced::built_in(base_limits.$field);
            for layer in &layers {
                if let Some(v) = layer.limits.$field {
                    current = Sourced {
                        value: v,
                        origin: layer.origin.clone(),
                    };
                }
            }
            if let Some(v) = $cli_field {
                current = Sourced {
                    value: v,
                    origin: Origin::Cli,
                };
            }
            current
        }};
    }

    Ok(ResolvedProfile {
        selected: selected.map(str::to_string),
        chain,
        format,
        explain: escalate(cli.explain, |l| l.explain),
        strict: escalate(cli.strict, |l| l.strict),
        no_color: escalate(cli.no_color, |l| l.no_color),
        max_suppressions,
        gating: ResolvedGating {
            gate_storage_layout: gate(
                |p| p.gate_storage_layout,
                gating_defaults.gate_storage_layout,
            ),
            gate_call_abi: gate(|p| p.gate_call_abi, gating_defaults.gate_call_abi),
            gate_event_indexer: gate(|p| p.gate_event_indexer, gating_defaults.gate_event_indexer),
            gate_source_level: gate(|p| p.gate_source_level, gating_defaults.gate_source_level),
            gate_runtime_surface: gate(
                |p| p.gate_runtime_surface,
                gating_defaults.gate_runtime_surface,
            ),
        },
        limits: ResolvedLimits {
            max_xdr_depth: limit!(max_xdr_depth, cli.max_xdr_depth),
            max_xdr_len: limit!(max_xdr_len, cli.max_xdr_len),
            max_entries: limit!(max_entries, cli.max_entries),
            max_walk_depth: limit!(max_walk_depth, cli.max_walk_depth),
        },
    })
}

/// Walk `selected`'s `inherits` chain to its root, checking for missing
/// profiles, cycles, and excess depth. Returns the chain root-first with
/// `selected` last.
fn build_chain(selected: &str, profiles: &BTreeMap<String, RawProfile>) -> Result<Vec<String>> {
    // Built leaf-to-root as we walk, then reversed at the end.
    let mut leaf_to_root: Vec<String> = Vec::new();
    let mut current = selected.to_string();

    loop {
        if leaf_to_root.len() >= MAX_PROFILE_DEPTH {
            bail!(
                "Profile inheritance chain exceeds the maximum depth of {}:\n  {}",
                MAX_PROFILE_DEPTH,
                chain_display(&leaf_to_root, &current)
            );
        }
        if leaf_to_root.contains(&current) {
            bail!(
                "Profile inheritance cycle detected:\n  {}",
                chain_display(&leaf_to_root, &current)
            );
        }
        let profile = profiles.get(&current).ok_or_else(|| {
            anyhow!(
                "Unknown profile '{current}' referenced in inheritance chain: {}",
                chain_display(&leaf_to_root, &current)
            )
        })?;
        leaf_to_root.push(current.clone());
        match &profile.inherits {
            Some(parent) => current = parent.clone(),
            None => break,
        }
    }

    leaf_to_root.reverse();
    Ok(leaf_to_root)
}

/// Render `stack` (leaf-to-root so far) plus `next` as `a -> b -> c` for error
/// messages, in the order a human wrote them (selected profile first).
fn chain_display(stack: &[String], next: &str) -> String {
    let mut names: Vec<&str> = stack.iter().map(String::as_str).collect();
    names.push(next);
    names.join(" -> ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(inherits: Option<&str>) -> RawProfile {
        RawProfile {
            inherits: inherits.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn no_selection_yields_base_config_only() {
        let profiles = BTreeMap::new();
        let base = BaseValues {
            strict: Some(true),
            ..Default::default()
        };
        let resolved = resolve(&profiles, None, base, CliOverrides::default()).unwrap();
        assert_eq!(resolved.selected, None);
        assert!(resolved.chain.is_empty());
        assert!(resolved.strict.value);
        assert_eq!(resolved.strict.origin, Origin::BaseConfig);
    }

    #[test]
    fn missing_selected_profile_is_an_error() {
        let profiles = BTreeMap::new();
        let err = resolve(
            &profiles,
            Some("nope"),
            BaseValues::default(),
            CliOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Unknown profile 'nope'"));
    }

    #[test]
    fn missing_inherited_profile_is_an_error() {
        let mut profiles = BTreeMap::new();
        profiles.insert("child".to_string(), profile(Some("ghost")));
        let err = resolve(
            &profiles,
            Some("child"),
            BaseValues::default(),
            CliOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Unknown profile 'ghost'"));
    }

    #[test]
    fn self_inheritance_is_a_cycle() {
        let mut profiles = BTreeMap::new();
        profiles.insert("loopy".to_string(), profile(Some("loopy")));
        let err = resolve(
            &profiles,
            Some("loopy"),
            BaseValues::default(),
            CliOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn indirect_cycle_is_detected() {
        let mut profiles = BTreeMap::new();
        profiles.insert("a".to_string(), profile(Some("b")));
        profiles.insert("b".to_string(), profile(Some("c")));
        profiles.insert("c".to_string(), profile(Some("a")));
        let err = resolve(
            &profiles,
            Some("a"),
            BaseValues::default(),
            CliOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn chain_deeper_than_max_depth_is_rejected() {
        let mut profiles = BTreeMap::new();
        // Build a straight-line chain one longer than MAX_PROFILE_DEPTH allows.
        for i in 0..=MAX_PROFILE_DEPTH {
            let name = format!("p{i}");
            let parent = (i > 0).then(|| format!("p{}", i - 1));
            profiles.insert(name, profile(parent.as_deref()));
        }
        let leaf = format!("p{MAX_PROFILE_DEPTH}");
        let err = resolve(
            &profiles,
            Some(&leaf),
            BaseValues::default(),
            CliOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("maximum depth"));
    }

    #[test]
    fn precedence_base_then_inherited_then_selected_then_cli() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "base_profile".to_string(),
            RawProfile {
                format: Some(OutputFormat::Text),
                max_suppressions: Some(1),
                ..Default::default()
            },
        );
        profiles.insert(
            "leaf".to_string(),
            RawProfile {
                inherits: Some("base_profile".to_string()),
                max_suppressions: Some(2),
                ..Default::default()
            },
        );
        let base = BaseValues {
            format: Some(OutputFormat::Markdown),
            max_suppressions: Some(0),
            ..Default::default()
        };
        let cli = CliOverrides {
            max_suppressions: Some(3),
            ..Default::default()
        };

        let resolved = resolve(&profiles, Some("leaf"), base, cli).unwrap();
        assert_eq!(resolved.chain, vec!["base_profile", "leaf"]);
        // format: only base config and the ancestor profile set it; ancestor wins.
        assert_eq!(resolved.format.value, OutputFormat::Text);
        assert_eq!(
            resolved.format.origin,
            Origin::Profile("base_profile".to_string())
        );
        // max_suppressions: every layer sets it, CLI wins.
        assert_eq!(resolved.max_suppressions.value, Some(3));
        assert_eq!(resolved.max_suppressions.origin, Origin::Cli);
    }

    #[test]
    fn strict_escalates_and_cannot_be_weakened() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "relaxed".to_string(),
            RawProfile {
                strict: Some(false),
                ..Default::default()
            },
        );
        let base = BaseValues {
            strict: Some(true),
            ..Default::default()
        };
        let resolved = resolve(&profiles, Some("relaxed"), base, CliOverrides::default()).unwrap();
        assert!(resolved.strict.value);
        assert_eq!(resolved.strict.origin, Origin::BaseConfig);
    }

    #[test]
    fn gating_gate_is_valued_not_escalating() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "quiet".to_string(),
            RawProfile {
                gating: PolicyOverrides {
                    gate_call_abi: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let base = BaseValues {
            gating: PolicyOverrides {
                gate_call_abi: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve(&profiles, Some("quiet"), base, CliOverrides::default()).unwrap();
        // Unlike `strict`, the more specific (selected) profile wins and can
        // turn the gate off.
        assert!(!resolved.gating.gate_call_abi.value);
        assert_eq!(
            resolved.gating.gate_call_abi.origin,
            Origin::Profile("quiet".to_string())
        );
    }

    #[test]
    fn limits_fold_through_base_profile_and_cli() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "tight".to_string(),
            RawProfile {
                limits: LimitsConfig {
                    max_xdr_depth: Some(10),
                    max_entries: Some(500),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let base = BaseValues {
            limits: LimitsConfig {
                max_xdr_depth: Some(5),
                max_xdr_len: Some(1000),
                ..Default::default()
            },
            ..Default::default()
        };
        let cli = CliOverrides {
            max_xdr_len: Some(2000),
            ..Default::default()
        };
        let resolved = resolve(&profiles, Some("tight"), base, cli).unwrap();
        assert_eq!(resolved.limits.max_xdr_depth.value, 10); // profile beats base
        assert_eq!(
            resolved.limits.max_xdr_depth.origin,
            Origin::Profile("tight".to_string())
        );
        assert_eq!(resolved.limits.max_xdr_len.value, 2000); // cli beats base
        assert_eq!(resolved.limits.max_xdr_len.origin, Origin::Cli);
        assert_eq!(resolved.limits.max_entries.value, 500); // profile only
        assert_eq!(resolved.limits.max_walk_depth.origin, Origin::BuiltIn); // untouched
    }

    #[test]
    fn deserializes_profile_table_and_rejects_unknown_fields() {
        let toml = r#"
            inherits = "dev"
            strict = true
            [gating]
            gate_event_indexer = true
            [limits]
            max_xdr_depth = 16
        "#;
        let parsed: RawProfile = toml::from_str(toml).unwrap();
        assert_eq!(parsed.inherits.as_deref(), Some("dev"));
        assert_eq!(parsed.strict, Some(true));
        assert_eq!(parsed.gating.gate_event_indexer, Some(true));
        assert_eq!(parsed.limits.max_xdr_depth, Some(16));

        let bad = r#"
            not_a_real_field = true
        "#;
        assert!(toml::from_str::<RawProfile>(bad).is_err());
    }

    #[test]
    fn rejects_incompatible_override_type() {
        // `strict` must be a bool, not a string.
        let bad = r#"strict = "yes""#;
        assert!(toml::from_str::<RawProfile>(bad).is_err());
    }
}
