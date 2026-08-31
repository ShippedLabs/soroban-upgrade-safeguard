//! Central resource policy for bounding untrusted XDR input.
//!
//! The safeguard runs as a CI gate and, in RPC mode, decodes WASM fetched for an
//! arbitrary contract ID. That input — the embedded `contractspecv0` /
//! `contractenvmetav0` sections — is **adversarial**. Without bounds a crafted
//! section can declare an enormous vector length (multi-gigabyte allocation) or
//! nest a type to arbitrary depth (native stack overflow → `SIGABRT`), crashing
//! the process and disabling the gate.
//!
//! This module defines a single [`ResourcePolicy`] that is threaded through every
//! decode ([`crate::parser`], [`crate::loader`]) and every recursive type walk
//! ([`crate::mapper`], [`crate::diff`]). Violations surface as a typed
//! [`LimitError`] — a *controlled* error distinct from a decode failure or a
//! "critical finding", so the CLI can exit with a dedicated code rather than
//! aborting.
//!
//! Limits are configurable in two coordinated ways (flags override file override
//! defaults): a `[limits]` table in `.safeguard.toml` (see [`LimitsConfig`]) for
//! committed CI policy, and `--max-*` CLI flags for ad-hoc runs.

use std::fmt;

use serde::Deserialize;
use stellar_xdr::curr::Limits;

/// Default maximum XDR recursion depth for a single decoded entry.
///
/// Soroban spec types are shallow in practice; 64 leaves generous headroom while
/// staying far below the stack depth that would risk a `SIGABRT`.
pub const DEFAULT_MAX_XDR_DEPTH: u32 = 64;

/// Default maximum number of bytes decoded from a single custom section.
///
/// The budget is shared across every entry in one section (see
/// [`ResourcePolicy::xdr_limits`]), so it doubles as a per-section total-byte
/// cap. Real spec sections are kilobytes; 32 MiB is a wide safety margin.
pub const DEFAULT_MAX_XDR_LEN: usize = 32 * 1024 * 1024;

/// Default maximum number of decoded spec entries accepted, summed across all
/// `contractspecv0` sections (env-metadata entries are budgeted separately).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Default maximum recursion depth for the type walkers (`type_to_string`,
/// UDT-dependency extraction, structural equality). Independent of the XDR
/// decode depth because the walkers are also reachable via public APIs that
/// accept programmatically-built (never-decoded) types.
pub const DEFAULT_MAX_WALK_DEPTH: usize = 128;

/// A single, reusable policy bounding how much work untrusted input may cause.
///
/// Every limit is independently configurable. `Copy` so it can be threaded by
/// value through the pipeline without ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ResourcePolicy {
    /// Maximum XDR recursion depth per entry (maps to [`Limits::depth`]).
    pub max_xdr_depth: u32,
    /// Maximum bytes decoded per custom section (maps to [`Limits::len`]).
    /// Shared across all entries in one section — the per-section total-byte cap.
    pub max_xdr_len: usize,
    /// Maximum decoded entry count, summed across all sections of a kind.
    pub max_entries: usize,
    /// Maximum recursion depth for the type walkers. Independent of
    /// [`Self::max_xdr_depth`].
    pub max_walk_depth: usize,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            max_xdr_depth: DEFAULT_MAX_XDR_DEPTH,
            max_xdr_len: DEFAULT_MAX_XDR_LEN,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_walk_depth: DEFAULT_MAX_WALK_DEPTH,
        }
    }
}

impl ResourcePolicy {
    /// The per-section XDR decode budget.
    ///
    /// Construct a fresh value per section so each section gets its own `len`
    /// budget; the cross-section entry cap is enforced separately by the
    /// caller in `parser`.
    #[must_use]
    pub fn xdr_limits(&self) -> Limits {
        Limits {
            depth: self.max_xdr_depth,
            len: self.max_xdr_len,
        }
    }
}

/// Which decoded-entry budget a count violation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// `contractspecv0` entries.
    Spec,
    /// `contractenvmetav0` entries.
    EnvMeta,
}

impl EntryKind {
    fn label(self) -> &'static str {
        match self {
            EntryKind::Spec => "contractspecv0",
            EntryKind::EnvMeta => "contractenvmetav0",
        }
    }
}

/// A controlled resource-limit violation.
///
/// Distinct from an ordinary decode error and from a comparison "finding": it
/// means the input was rejected as adversarial *before* it could exhaust memory
/// or the stack. It implements [`std::error::Error`], so it boxes cleanly into
/// [`anyhow::Error`] via `?` and can be recovered at the top level with
/// [`anyhow::Error::downcast_ref`] to select a dedicated exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    /// XDR nesting exceeded [`ResourcePolicy::max_xdr_depth`] during decode.
    XdrDepthExceeded { limit: u32 },
    /// A declared XDR length exceeded [`ResourcePolicy::max_xdr_len`] for the
    /// section (would have triggered an unbounded allocation).
    XdrLengthExceeded { limit: usize },
    /// A type walk exceeded [`ResourcePolicy::max_walk_depth`].
    WalkDepthExceeded { limit: usize },
    /// The decoded entry count exceeded [`ResourcePolicy::max_entries`].
    EntryCountExceeded { limit: usize, kind: EntryKind },
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitError::XdrDepthExceeded { limit } => write!(
                f,
                "XDR nesting exceeded the maximum decode depth of {limit} (raise `max_xdr_depth`)"
            ),
            LimitError::XdrLengthExceeded { limit } => write!(
                f,
                "a declared XDR length exceeded the per-section byte budget of {limit} \
                 (raise `max_xdr_len`)"
            ),
            LimitError::WalkDepthExceeded { limit } => write!(
                f,
                "type nesting exceeded the maximum walk depth of {limit} (raise `max_walk_depth`)"
            ),
            LimitError::EntryCountExceeded { limit, kind } => write!(
                f,
                "{} entry count exceeded the maximum of {limit} (raise `max_entries`)",
                kind.label()
            ),
        }
    }
}

impl std::error::Error for LimitError {}

/// Recover a [`LimitError`] from anywhere in an [`anyhow::Error`] chain.
///
/// Limit violations are often wrapped in contextual `anyhow` layers as they
/// bubble up (e.g. "Failed to decode contractspecv0 section 0 …"). Walking the
/// whole chain — rather than downcasting only the outermost error — lets the CLI
/// still recognize a resource-limit violation and choose its dedicated exit code
/// regardless of how much context was attached along the way.
#[must_use]
pub fn find_limit_error(err: &anyhow::Error) -> Option<&LimitError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<LimitError>())
}

impl LimitError {
    /// Map a stellar-xdr error to the corresponding [`LimitError`], if it was a
    /// depth/length limit violation. Returns `None` for any other XDR error so
    /// the caller can preserve its existing (contextual) error path.
    pub fn from_xdr_error(err: &stellar_xdr::curr::Error, policy: &ResourcePolicy) -> Option<Self> {
        match err {
            stellar_xdr::curr::Error::DepthLimitExceeded => Some(LimitError::XdrDepthExceeded {
                limit: policy.max_xdr_depth,
            }),
            stellar_xdr::curr::Error::LengthLimitExceeded => Some(LimitError::XdrLengthExceeded {
                limit: policy.max_xdr_len,
            }),
            _ => None,
        }
    }
}

/// The `[limits]` table parsed from `.safeguard.toml`.
///
/// Every field is optional; an omitted field keeps the compiled-in default. This
/// mirrors [`crate::suppression::SuppressionConfig`] so a repo can commit both a
/// suppression policy and a resource policy in the same file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Overrides [`ResourcePolicy::max_xdr_depth`].
    #[serde(default)]
    pub max_xdr_depth: Option<u32>,
    /// Overrides [`ResourcePolicy::max_xdr_len`].
    #[serde(default)]
    pub max_xdr_len: Option<usize>,
    /// Overrides [`ResourcePolicy::max_entries`].
    #[serde(default)]
    pub max_entries: Option<usize>,
    /// Overrides [`ResourcePolicy::max_walk_depth`].
    #[serde(default)]
    pub max_walk_depth: Option<usize>,
}

/// The top-level shape of `.safeguard.toml` as far as limits are concerned.
///
/// The file also holds `[[suppress]]` rules (parsed independently by
/// [`crate::suppression`]); this view only reads the optional `[limits]` table
/// and ignores everything else.
#[derive(Debug, Clone, Default, Deserialize)]
struct LimitsFile {
    #[serde(default)]
    limits: LimitsConfig,
}

impl LimitsConfig {
    /// Load the `[limits]` table from `path` if the file exists.
    ///
    /// Returns `Ok(None)` when the file is absent (so callers fall back to
    /// defaults), and an error only when the file exists but cannot be read or
    /// parsed as TOML.
    pub fn load_optional(path: &std::path::Path) -> anyhow::Result<Option<Self>> {
        use anyhow::Context;

        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let parsed: LimitsFile = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse [limits] in '{}'", path.display()))?;
        Ok(Some(parsed.limits))
    }

    /// Fold these overrides onto `base`, keeping `base` for any unset field.
    #[must_use]
    pub fn apply_to(&self, mut base: ResourcePolicy) -> ResourcePolicy {
        if let Some(v) = self.max_xdr_depth {
            base.max_xdr_depth = v;
        }
        if let Some(v) = self.max_xdr_len {
            base.max_xdr_len = v;
        }
        if let Some(v) = self.max_entries {
            base.max_entries = v;
        }
        if let Some(v) = self.max_walk_depth {
            base.max_walk_depth = v;
        }
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_matches_constants() {
        let p = ResourcePolicy::default();
        assert_eq!(p.max_xdr_depth, DEFAULT_MAX_XDR_DEPTH);
        assert_eq!(p.max_xdr_len, DEFAULT_MAX_XDR_LEN);
        assert_eq!(p.max_entries, DEFAULT_MAX_ENTRIES);
        assert_eq!(p.max_walk_depth, DEFAULT_MAX_WALK_DEPTH);
    }

    #[test]
    fn xdr_limits_reflect_policy() {
        let p = ResourcePolicy {
            max_xdr_depth: 10,
            max_xdr_len: 999,
            ..ResourcePolicy::default()
        };
        let limits = p.xdr_limits();
        assert_eq!(limits.depth, 10);
        assert_eq!(limits.len, 999);
    }

    #[test]
    fn limit_error_is_std_error_and_displays() {
        let e = LimitError::EntryCountExceeded {
            limit: 5,
            kind: EntryKind::Spec,
        };
        // Boxes into anyhow via the std::error::Error impl.
        let any: anyhow::Error = e.clone().into();
        assert_eq!(any.downcast_ref::<LimitError>(), Some(&e));
        assert!(any.to_string().contains("contractspecv0"));
    }

    #[test]
    fn from_xdr_error_maps_only_limit_variants() {
        let p = ResourcePolicy::default();
        assert_eq!(
            LimitError::from_xdr_error(&stellar_xdr::curr::Error::DepthLimitExceeded, &p),
            Some(LimitError::XdrDepthExceeded {
                limit: p.max_xdr_depth
            })
        );
        assert_eq!(
            LimitError::from_xdr_error(&stellar_xdr::curr::Error::LengthLimitExceeded, &p),
            Some(LimitError::XdrLengthExceeded {
                limit: p.max_xdr_len
            })
        );
        assert_eq!(
            LimitError::from_xdr_error(&stellar_xdr::curr::Error::Invalid, &p),
            None
        );
    }

    #[test]
    fn config_applies_only_set_fields() {
        let cfg = LimitsConfig {
            max_xdr_depth: Some(7),
            max_entries: Some(42),
            ..LimitsConfig::default()
        };
        let p = cfg.apply_to(ResourcePolicy::default());
        assert_eq!(p.max_xdr_depth, 7);
        assert_eq!(p.max_entries, 42);
        // Untouched fields keep the base value.
        assert_eq!(p.max_xdr_len, DEFAULT_MAX_XDR_LEN);
        assert_eq!(p.max_walk_depth, DEFAULT_MAX_WALK_DEPTH);
    }
}
