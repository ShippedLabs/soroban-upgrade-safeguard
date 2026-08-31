use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0,
    ScSpecUdtUnionV0,
};

/// A declaration name that occurs more than once within its entry kind
/// (function, struct, enum, union, or error enum) in a raw, undecoded entry
/// list.
///
/// This mirrors the first-wins semantics [`ContractSpec::from_entries`] uses
/// when building its maps (the first occurrence is kept and a warning is
/// printed to stderr; later duplicates are dropped). It is the structured,
/// non-printing counterpart of that behavior, used by [`crate::lint`] and any
/// other caller that needs the list of offending names rather than a
/// side-effecting warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DuplicateDeclaration {
    /// Entry kind: "function", "struct", "enum", "union", or "error_enum".
    pub kind: &'static str,
    /// The duplicated declaration name.
    pub name: String,
    /// How many times this name occurs for this kind in `entries`.
    pub occurrences: usize,
}

// `kind` is `&'static str` (matched against elsewhere as a static, e.g.
// `LintTarget::new`), which serde cannot derive `Deserialize` for directly —
// a derived impl would need to borrow `kind` from the deserializer's input
// with lifetime `'de`, not manufacture a `'static` reference. Deserialize
// into an owned string instead and map it onto the fixed set of known kinds.
impl<'de> Deserialize<'de> for DuplicateDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            kind: String,
            name: String,
            occurrences: usize,
        }
        let raw = Raw::deserialize(deserializer)?;
        let kind: &'static str = match raw.kind.as_str() {
            "function" => "function",
            "struct" => "struct",
            "enum" => "enum",
            "union" => "union",
            "error_enum" => "error_enum",
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown duplicate-declaration kind '{other}'"
                )))
            }
        };
        Ok(DuplicateDeclaration {
            kind,
            name: raw.name,
            occurrences: raw.occurrences,
        })
    }
}

/// A structured representation of a Soroban contract's public interface,
/// organized by type for easy comparison between contract versions.
#[derive(Debug, Default)]
pub struct ContractSpec {
    /// Contract functions, keyed by name.
    #[cfg(feature = "unstable")]
    pub functions: HashMap<String, ScSpecFunctionV0>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) functions: HashMap<String, ScSpecFunctionV0>,

    /// User-defined structs, keyed by name.
    #[cfg(feature = "unstable")]
    pub structs: HashMap<String, ScSpecUdtStructV0>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) structs: HashMap<String, ScSpecUdtStructV0>,

    /// User-defined enums, keyed by name.
    #[cfg(feature = "unstable")]
    pub enums: HashMap<String, ScSpecUdtEnumV0>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) enums: HashMap<String, ScSpecUdtEnumV0>,

    /// User-defined unions (tagged enums with data), keyed by name.
    #[cfg(feature = "unstable")]
    pub unions: HashMap<String, ScSpecUdtUnionV0>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) unions: HashMap<String, ScSpecUdtUnionV0>,

    /// Error enums, keyed by name.
    #[cfg(feature = "unstable")]
    pub error_enums: HashMap<String, ScSpecUdtErrorEnumV0>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) error_enums: HashMap<String, ScSpecUdtErrorEnumV0>,
}

impl ContractSpec {
    /// Get the contract functions, keyed by name.
    pub fn functions(&self) -> &HashMap<String, ScSpecFunctionV0> {
        &self.functions
    }

    /// Get the user-defined structs, keyed by name.
    pub fn structs(&self) -> &HashMap<String, ScSpecUdtStructV0> {
        &self.structs
    }

    /// Get the user-defined enums, keyed by name.
    pub fn enums(&self) -> &HashMap<String, ScSpecUdtEnumV0> {
        &self.enums
    }

    /// Get the user-defined unions, keyed by name.
    pub fn unions(&self) -> &HashMap<String, ScSpecUdtUnionV0> {
        &self.unions
    }

    /// Get the error enums, keyed by name.
    pub fn error_enums(&self) -> &HashMap<String, ScSpecUdtErrorEnumV0> {
        &self.error_enums
    }
}

impl ContractSpec {
    /// Build a `ContractSpec` from a list of decoded `ScSpecEntry` objects.
    ///
    /// If multiple entries with the same name for a given kind (e.g., two functions
    /// with the same name) are encountered, a warning is printed to stderr. Under the
    /// first-wins tie-break strategy, the first entry encountered in the `entries`
    /// slice is retained, and subsequent duplicates are ignored.
    pub fn from_entries(entries: &[ScSpecEntry]) -> Self {
        let mut spec = ContractSpec::default();

        for entry in entries {
            match entry {
                ScSpecEntry::FunctionV0(f) => {
                    let name = f.name.to_string();
                    match spec.functions.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate function '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(f.clone());
                        }
                    }
                }
                ScSpecEntry::UdtStructV0(s) => {
                    let name = s.name.to_string();
                    match spec.structs.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate struct '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(s.clone());
                        }
                    }
                }
                ScSpecEntry::UdtEnumV0(e) => {
                    let name = e.name.to_string();
                    match spec.enums.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate enum '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(e.clone());
                        }
                    }
                }
                ScSpecEntry::UdtUnionV0(u) => {
                    let name = u.name.to_string();
                    match spec.unions.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate union '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(u.clone());
                        }
                    }
                }
                ScSpecEntry::UdtErrorEnumV0(e) => {
                    let name = e.name.to_string();
                    match spec.error_enums.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate error enum '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(e.clone());
                        }
                    }
                }
            }
        }

        spec
    }

    /// Report every declaration name that occurs more than once within its
    /// entry kind in `entries`, in a single pass over the raw (undecoded)
    /// list -- i.e. before [`ContractSpec::from_entries`] applies its
    /// first-wins de-duplication.
    ///
    /// Returned in deterministic (kind, then name) order.
    pub fn duplicate_declarations(entries: &[ScSpecEntry]) -> Vec<DuplicateDeclaration> {
        let mut counts: BTreeMap<(&'static str, String), usize> = BTreeMap::new();
        for entry in entries {
            let (kind, name) = match entry {
                ScSpecEntry::FunctionV0(f) => ("function", f.name.to_string()),
                ScSpecEntry::UdtStructV0(s) => ("struct", s.name.to_string()),
                ScSpecEntry::UdtEnumV0(e) => ("enum", e.name.to_string()),
                ScSpecEntry::UdtUnionV0(u) => ("union", u.name.to_string()),
                ScSpecEntry::UdtErrorEnumV0(e) => ("error_enum", e.name.to_string()),
            };
            *counts.entry((kind, name)).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .filter(|(_, occurrences)| *occurrences > 1)
            .map(|((kind, name), occurrences)| DuplicateDeclaration {
                kind,
                name,
                occurrences,
            })
            .collect()
    }

    /// Returns a summary string of the spec contents.
    pub fn summary(&self) -> String {
        format!(
            "Functions: {}, Structs: {}, Enums: {}, Unions: {}, Errors: {}",
            self.functions.len(),
            self.structs.len(),
            self.enums.len(),
            self.unions.len(),
            self.error_enums.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{StringM, VecM};

    #[test]
    fn test_from_entries_duplicate_function_first_wins() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.functions.len(), 1);
        let resolved = spec.functions.get("my_func").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_struct_first_wins() {
        let s1 = ScSpecUdtStructV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_struct".try_into().unwrap(),
            fields: VecM::default(),
        };
        let s2 = ScSpecUdtStructV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_struct".try_into().unwrap(),
            fields: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtStructV0(s1), ScSpecEntry::UdtStructV0(s2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.structs.len(), 1);
        let resolved = spec.structs.get("my_struct").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_enum_first_wins() {
        let e1 = ScSpecUdtEnumV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_enum".try_into().unwrap(),
            cases: VecM::default(),
        };
        let e2 = ScSpecUdtEnumV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_enum".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtEnumV0(e1), ScSpecEntry::UdtEnumV0(e2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.enums.len(), 1);
        let resolved = spec.enums.get("my_enum").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_union_first_wins() {
        let u1 = ScSpecUdtUnionV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_union".try_into().unwrap(),
            cases: VecM::default(),
        };
        let u2 = ScSpecUdtUnionV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_union".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtUnionV0(u1), ScSpecEntry::UdtUnionV0(u2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.unions.len(), 1);
        let resolved = spec.unions.get("my_union").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_error_enum_first_wins() {
        let e1 = ScSpecUdtErrorEnumV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_err".try_into().unwrap(),
            cases: VecM::default(),
        };
        let e2 = ScSpecUdtErrorEnumV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_err".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![
            ScSpecEntry::UdtErrorEnumV0(e1),
            ScSpecEntry::UdtErrorEnumV0(e2),
        ];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.error_enums.len(), 1);
        let resolved = spec.error_enums.get("my_err").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_unique_names_no_warning() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func1".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func2".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 2);
    }

    #[test]
    fn test_duplicate_declarations_detects_same_kind_repeats() {
        let f1 = ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "dup_fn".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = f1.clone();
        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

        let dups = ContractSpec::duplicate_declarations(&entries);
        assert_eq!(
            dups,
            vec![DuplicateDeclaration {
                kind: "function",
                name: "dup_fn".to_string(),
                occurrences: 2,
            }]
        );
    }

    #[test]
    fn test_duplicate_declarations_ignores_cross_kind_same_name() {
        // Same name, different kinds: not a "duplicate declaration" (that's
        // covered separately by the lint module's cross-kind-collision rule).
        let f = ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "Token".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Token".try_into().unwrap(),
            fields: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(f), ScSpecEntry::UdtStructV0(s)];

        assert!(ContractSpec::duplicate_declarations(&entries).is_empty());
    }

    #[test]
    fn test_duplicate_declarations_empty_for_unique_names() {
        let entries: Vec<ScSpecEntry> = vec![];
        assert!(ContractSpec::duplicate_declarations(&entries).is_empty());
    }
}
