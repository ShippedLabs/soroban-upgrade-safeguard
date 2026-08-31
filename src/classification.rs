//! Explicit, configurable classification of user-defined types as *events* or
//! ordinary *storage/interface* types.
//!
//! ## Why this exists
//!
//! `contractspecv0` carries no marker that says "this type is an event". The
//! only signal historically available was the type's *name*, and the tool used
//! a raw substring test (`name.to_lowercase().contains("event")`). That is both
//! a false-positive machine (a `PreventList` or `EventCounterCache` struct is
//! flagged as an event) and a false-negative one (a genuine event whose name
//! lacks the substring is missed).
//!
//! Classification is *load-bearing* only for **display and remediation** — it
//! decides whether a finding's message and guidance mention off-chain indexers.
//! It deliberately does **not** feed the suppression key: categories are
//! structural (`Struct Field Removed`, never `Event Schema Removed`), so a
//! suppression rule keeps matching even if a type's classification later flips.
//! See [`crate::diff`] and [`crate::suppression`].
//!
//! ## Configuration (`[classification]` in `.safeguard.toml`)
//!
//! ```toml
//! [classification]
//! # Types explicitly treated as events (exact, case-sensitive names).
//! events  = ["LedgerEvent", "TransferLog"]
//! # Types explicitly treated as ordinary storage, overriding the heuristic.
//! storage = ["EventCounterCache", "PreventList"]
//! # Opt-in: also treat any name containing "event" (case-insensitive) as an
//! # event. Off by default so a coincidental substring is never load-bearing.
//! name_heuristic = false
//! ```
//!
//! Resolution precedence (first match wins):
//! 1. `storage` list  -> [`TypeClass::Storage`]
//! 2. `events` list   -> [`TypeClass::Event`] (`heuristic = false`)
//! 3. name heuristic (only if `name_heuristic = true`) -> [`TypeClass::Event`]
//!    (`heuristic = true`)
//! 4. otherwise       -> [`TypeClass::Storage`]

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How a user-defined type is classified for reporting purposes.
///
/// This is metadata attached to a [`crate::diff::Finding`]; it never affects
/// the structural category used for suppression matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "class", rename_all = "lowercase")]
pub enum TypeClass {
    /// An ordinary storage or interface type.
    Storage,
    /// A type classified as an event. `heuristic` records *how* it was
    /// classified so the report can flag heuristic guesses as such.
    Event {
        /// `true` when the classification came from the opt-in name heuristic
        /// rather than an explicit `events` entry. Surfaced in the report so a
        /// reviewer can tell a guess from a declaration.
        heuristic: bool,
    },
}

impl TypeClass {
    /// Whether this classifies the type as an event (by any means).
    pub fn is_event(self) -> bool {
        matches!(self, TypeClass::Event { .. })
    }

    /// Whether this classification was produced by the name heuristic rather
    /// than an explicit configuration entry.
    pub fn is_heuristic(self) -> bool {
        matches!(self, TypeClass::Event { heuristic: true })
    }
}

/// Explicit configuration controlling how types are classified.
///
/// The default classifies *everything* as [`TypeClass::Storage`]: with no
/// configuration the tool makes no event claims at all, so a name that merely
/// contains "event" is never treated as one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassificationConfig {
    /// Exact type names to treat as events.
    pub events: BTreeSet<String>,
    /// Exact type names to treat as ordinary storage, overriding both the
    /// `events` list and the name heuristic.
    pub storage: BTreeSet<String>,
    /// When `true`, any type whose name contains "event" (case-insensitive) and
    /// is not listed in `storage`/`events` is classified as a *heuristic* event.
    /// Off by default.
    pub name_heuristic: bool,
}

impl ClassificationConfig {
    /// A config that classifies nothing as an event — the safe default.
    pub fn none() -> Self {
        Self::default()
    }

    /// Resolve the classification of a type by name.
    pub fn classify(&self, name: &str) -> TypeClass {
        if self.storage.contains(name) {
            return TypeClass::Storage;
        }
        if self.events.contains(name) {
            return TypeClass::Event { heuristic: false };
        }
        if self.name_heuristic && name.to_lowercase().contains("event") {
            return TypeClass::Event { heuristic: true };
        }
        TypeClass::Storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_classifies_nothing_as_event() {
        let cfg = ClassificationConfig::none();
        // A name that merely contains "event" is NOT an event without config.
        assert_eq!(cfg.classify("StatusEvent"), TypeClass::Storage);
        assert_eq!(cfg.classify("PreventList"), TypeClass::Storage);
        assert_eq!(cfg.classify("Balance"), TypeClass::Storage);
    }

    #[test]
    fn explicit_events_are_classified_even_without_substring() {
        let mut cfg = ClassificationConfig::none();
        cfg.events.insert("Transfer".to_string());
        // A genuine event whose name lacks "event" is classifiable.
        assert_eq!(
            cfg.classify("Transfer"),
            TypeClass::Event { heuristic: false }
        );
    }

    #[test]
    fn storage_list_overrides_events_and_heuristic() {
        let mut cfg = ClassificationConfig {
            name_heuristic: true,
            ..Default::default()
        };
        cfg.events.insert("EventCounterCache".to_string());
        cfg.storage.insert("EventCounterCache".to_string());
        // storage wins over both the events list and the substring heuristic.
        assert_eq!(cfg.classify("EventCounterCache"), TypeClass::Storage);
    }

    #[test]
    fn heuristic_is_opt_in_and_flagged() {
        let cfg = ClassificationConfig {
            name_heuristic: true,
            ..Default::default()
        };
        assert_eq!(
            cfg.classify("LedgerEvent"),
            TypeClass::Event { heuristic: true }
        );
        // A struct whose name merely contains "event" is a *heuristic* guess.
        assert!(cfg.classify("PreventList").is_event()); // contains "event" (prEVENTlist)
        assert!(cfg.classify("PreventList").is_heuristic());
    }

    #[test]
    fn explicit_event_beats_heuristic_flag() {
        let mut cfg = ClassificationConfig {
            name_heuristic: true,
            ..Default::default()
        };
        cfg.events.insert("LedgerEvent".to_string());
        // Explicitly configured -> not flagged as a heuristic guess.
        assert_eq!(
            cfg.classify("LedgerEvent"),
            TypeClass::Event { heuristic: false }
        );
    }
}
