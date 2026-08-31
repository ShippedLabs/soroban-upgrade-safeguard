//! A stable, order-independent hash of a contract's exported interface.
//!
//! A [`crate::spec::ContractSpec`] is built from `HashMap`s, so it has no
//! inherent iteration order, and two builds of semantically identical source can
//! lay their `contractspecv0` entries out in any order. Comparing two builds
//! therefore normally means running the full pairwise diff and reading the
//! verdict.
//!
//! The interface hash answers the same question directly and cheaply: two specs
//! with the same [`InterfaceHash`] expose the same functions and types. It is
//! computed by serializing the spec into a *canonical form* — a byte stream
//! whose content depends only on what a compatibility check cares about — and
//! taking its SHA-256.
//!
//! # What the hash covers
//!
//! Included, because a change to any of these changes the interface:
//!
//! - **Functions**: name, parameter names, parameter types, parameter *order*,
//!   and return types (in order).
//! - **Structs**: name, field names, field types, and field *order* — Soroban
//!   serializes struct fields positionally, so order is layout-relevant.
//! - **Unions**: name, case names, case payload types, and case *order* — union
//!   cases serialize by positional discriminant.
//! - **Enums** and **error enums**: name, and the set of `(case name, value)`
//!   pairs. Declaration order is *not* included: cases carry explicit integer
//!   values and [`crate::diff`] matches them by name, so reordering a `#[repr]`
//!   enum's variants without touching names or values is not an interface
//!   change.
//! - The kind of each named type. A type named `Status` that is a struct hashes
//!   differently from one that is an enum, so a kind change (see
//!   [`crate::diff::detect_type_kind_changes`]) always moves the hash.
//!
//! Deliberately excluded, because these are prose or provenance rather than
//! interface shape:
//!
//! - **Doc strings** on any entry, field, parameter, or case. Editing a comment
//!   must not invalidate a cached interface hash. Note that the diff still
//!   *reports* doc changes as informational findings — the hash tracks the
//!   interface, not the full finding set.
//! - The **`lib`** field on user-defined types, which records the defining
//!   library and is never compared by the diff.
//! - Everything outside the spec: WASM bytes, compiler version, section
//!   ordering, `contractenvmetav0` (the Soroban protocol version), and
//!   `contractmetav0`. Two builds with the same interface hash may target
//!   different protocol versions.
//!
//! # Stability
//!
//! [`CANONICAL_FORM_VERSION`] is mixed into the hash, so any future change to
//! the canonicalization necessarily changes every hash rather than silently
//! producing collisions across tool versions. Bump it whenever the encoding
//! below changes.

use std::fmt;

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

use crate::spec::ContractSpec;

/// Version of the canonical serialization, mixed into every hash.
///
/// Bump this whenever [`canonical_form`] changes what it emits, so hashes from
/// different tool versions can never be mistaken for one another.
pub const CANONICAL_FORM_VERSION: u32 = 1;

/// Domain-separation prefix, so this hash can never collide with a bare
/// SHA-256 of some other artifact that happens to share bytes.
const DOMAIN: &str = "soroban-upgrade-safeguard/interface-hash";

/// A SHA-256 digest of a [`ContractSpec`]'s canonical form.
///
/// Two specs that are semantically equal — same functions and types, regardless
/// of the order the entries happened to be emitted in — produce the same hash.
/// See the [module documentation](self) for exactly what is covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceHash([u8; 32]);

impl InterfaceHash {
    /// Compute the interface hash of a spec.
    pub fn of_spec(spec: &ContractSpec) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(canonical_form(spec));
        let digest = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest as a lowercase 64-character hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first 12 hex characters, for compact display.
    ///
    /// Never use this for equality — it is a label, not an identity.
    pub fn to_short_hex(&self) -> String {
        self.to_hex()[..12].to_string()
    }
}

impl fmt::Display for InterfaceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for InterfaceHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl ContractSpec {
    /// Compute this spec's [`InterfaceHash`].
    pub fn interface_hash(&self) -> InterfaceHash {
        InterfaceHash::of_spec(self)
    }
}

/// A length-prefixed byte-stream writer.
///
/// Every variable-length item is written as its length followed by its bytes,
/// which makes the encoding unambiguous: no choice of type, field, or case name
/// can produce the same stream as a different spec by colliding with a
/// separator. Fixed-width integers are big-endian so the form is
/// platform-independent.
#[derive(Default)]
struct Canonicalizer {
    buf: Vec<u8>,
}

impl Canonicalizer {
    /// Write a length-prefixed string.
    fn str(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    /// Write a fixed-width tag. Tags are drawn from a closed set defined in
    /// this module, so they need no length prefix ambiguity guard beyond the
    /// one `str` already provides.
    fn tag(&mut self, value: &str) {
        self.str(value);
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Write a type definition structurally.
    ///
    /// This deliberately does *not* reuse [`crate::mapper::type_to_string`],
    /// which is written for human display and is not injective: a user-defined
    /// type named `u32` renders identically to the primitive `u32`. The diff
    /// compares types with `==`, so the hash has to distinguish exactly what
    /// `==` distinguishes.
    fn type_def(&mut self, type_def: &ScSpecTypeDef) {
        match type_def {
            ScSpecTypeDef::Val => self.tag("val"),
            ScSpecTypeDef::Bool => self.tag("bool"),
            ScSpecTypeDef::Void => self.tag("void"),
            ScSpecTypeDef::Error => self.tag("error"),
            ScSpecTypeDef::U32 => self.tag("u32"),
            ScSpecTypeDef::I32 => self.tag("i32"),
            ScSpecTypeDef::U64 => self.tag("u64"),
            ScSpecTypeDef::I64 => self.tag("i64"),
            ScSpecTypeDef::Timepoint => self.tag("timepoint"),
            ScSpecTypeDef::Duration => self.tag("duration"),
            ScSpecTypeDef::U128 => self.tag("u128"),
            ScSpecTypeDef::I128 => self.tag("i128"),
            ScSpecTypeDef::U256 => self.tag("u256"),
            ScSpecTypeDef::I256 => self.tag("i256"),
            ScSpecTypeDef::Bytes => self.tag("bytes"),
            ScSpecTypeDef::String => self.tag("string"),
            ScSpecTypeDef::Symbol => self.tag("symbol"),
            ScSpecTypeDef::Address => self.tag("address"),
            ScSpecTypeDef::Option(inner) => {
                self.tag("option");
                self.type_def(&inner.value_type);
            }
            ScSpecTypeDef::Result(inner) => {
                self.tag("result");
                self.type_def(&inner.ok_type);
                self.type_def(&inner.error_type);
            }
            ScSpecTypeDef::Vec(inner) => {
                self.tag("vec");
                self.type_def(&inner.element_type);
            }
            ScSpecTypeDef::Map(inner) => {
                self.tag("map");
                self.type_def(&inner.key_type);
                self.type_def(&inner.value_type);
            }
            ScSpecTypeDef::Tuple(inner) => {
                self.tag("tuple");
                let types: &[ScSpecTypeDef] = inner.value_types.as_ref();
                self.u64(types.len() as u64);
                for t in types {
                    self.type_def(t);
                }
            }
            ScSpecTypeDef::BytesN(inner) => {
                self.tag("bytesn");
                self.u32(inner.n);
            }
            ScSpecTypeDef::Udt(inner) => {
                self.tag("udt");
                self.str(&inner.name.to_string());
            }
        }
    }

    fn function(&mut self, name: &str, function: &ScSpecFunctionV0) {
        self.tag("fn");
        self.str(name);

        // Parameter order is part of the interface: Soroban invokes positionally.
        let inputs: &[ScSpecFunctionInputV0] = function.inputs.as_ref();
        self.u64(inputs.len() as u64);
        for input in inputs {
            self.str(&input.name.to_string());
            self.type_def(&input.type_);
        }

        let outputs: &[ScSpecTypeDef] = function.outputs.as_ref();
        self.u64(outputs.len() as u64);
        for output in outputs {
            self.type_def(output);
        }
    }

    fn struct_(&mut self, name: &str, def: &ScSpecUdtStructV0) {
        self.tag("struct");
        self.str(name);

        // Field order is layout-relevant: structs serialize positionally.
        let fields: &[ScSpecUdtStructFieldV0] = def.fields.as_ref();
        self.u64(fields.len() as u64);
        for field in fields {
            self.str(&field.name.to_string());
            self.type_def(&field.type_);
        }
    }

    fn union(&mut self, name: &str, def: &ScSpecUdtUnionV0) {
        self.tag("union");
        self.str(name);

        // Case order is layout-relevant: unions serialize by positional
        // discriminant.
        let cases: &[ScSpecUdtUnionCaseV0] = def.cases.as_ref();
        self.u64(cases.len() as u64);
        for case in cases {
            match case {
                ScSpecUdtUnionCaseV0::VoidV0(void_case) => {
                    self.tag("void");
                    self.str(&void_case.name.to_string());
                }
                ScSpecUdtUnionCaseV0::TupleV0(tuple_case) => {
                    self.tag("tuple");
                    self.str(&tuple_case.name.to_string());
                    let types: &[ScSpecTypeDef] = tuple_case.type_.as_ref();
                    self.u64(types.len() as u64);
                    for t in types {
                        self.type_def(t);
                    }
                }
            }
        }
    }

    fn enum_(&mut self, name: &str, def: &ScSpecUdtEnumV0) {
        self.tag("enum");
        self.str(name);

        // Cases carry explicit values and the diff matches them by name, so
        // declaration order is not an interface change. Sort to canonicalize.
        let cases: &[ScSpecUdtEnumCaseV0] = def.cases.as_ref();
        let mut sorted: Vec<(String, u32)> = cases
            .iter()
            .map(|case| (case.name.to_string(), case.value))
            .collect();
        sorted.sort();

        self.u64(sorted.len() as u64);
        for (case_name, value) in sorted {
            self.str(&case_name);
            self.u32(value);
        }
    }

    fn error_enum(&mut self, name: &str, def: &ScSpecUdtErrorEnumV0) {
        self.tag("error_enum");
        self.str(name);

        // Same reasoning as `enum_`: matched by name, values explicit.
        let cases: &[ScSpecUdtErrorEnumCaseV0] = def.cases.as_ref();
        let mut sorted: Vec<(String, u32)> = cases
            .iter()
            .map(|case| (case.name.to_string(), case.value))
            .collect();
        sorted.sort();

        self.u64(sorted.len() as u64);
        for (case_name, value) in sorted {
            self.str(&case_name);
            self.u32(value);
        }
    }
}

/// Serialize a spec into its canonical byte form.
///
/// Exposed so tests can assert on the form directly and so callers debugging a
/// hash mismatch can diff the inputs rather than two opaque digests.
pub fn canonical_form(spec: &ContractSpec) -> Vec<u8> {
    let mut out = Canonicalizer::default();

    out.str(DOMAIN);
    out.u32(CANONICAL_FORM_VERSION);

    // Each section is emitted in a fixed order with its entries sorted by name,
    // which is what makes the form independent of `HashMap` iteration order.
    // The section tag and count are written even when empty, so "no unions" is
    // encoded distinctly rather than being indistinguishable from a spec that
    // never had a union section.
    let mut names: Vec<&String> = spec.functions.keys().collect();
    names.sort();
    out.tag("functions");
    out.u64(names.len() as u64);
    for name in names {
        out.function(name, &spec.functions[name]);
    }

    let mut names: Vec<&String> = spec.structs.keys().collect();
    names.sort();
    out.tag("structs");
    out.u64(names.len() as u64);
    for name in names {
        out.struct_(name, &spec.structs[name]);
    }

    let mut names: Vec<&String> = spec.unions.keys().collect();
    names.sort();
    out.tag("unions");
    out.u64(names.len() as u64);
    for name in names {
        out.union(name, &spec.unions[name]);
    }

    let mut names: Vec<&String> = spec.enums.keys().collect();
    names.sort();
    out.tag("enums");
    out.u64(names.len() as u64);
    for name in names {
        out.enum_(name, &spec.enums[name]);
    }

    let mut names: Vec<&String> = spec.error_enums.keys().collect();
    names.sort();
    out.tag("error_enums");
    out.u64(names.len() as u64);
    for name in names {
        out.error_enum(name, &spec.error_enums[name]);
    }

    out.buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtUnionCaseVoidV0, StringM, VecM};

    fn function(
        name: &str,
        inputs: &[(&str, ScSpecTypeDef)],
        output: Option<ScSpecTypeDef>,
    ) -> ScSpecEntry {
        let inputs: VecM<ScSpecFunctionInputV0, 10> = inputs
            .iter()
            .map(|(param, type_)| ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: (*param).try_into().unwrap(),
                type_: type_.clone(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let outputs: VecM<ScSpecTypeDef, 1> = match output {
            Some(t) => vec![t].try_into().unwrap(),
            None => VecM::default(),
        };

        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
            inputs,
            outputs,
        })
    }

    fn struct_(name: &str, fields: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
        ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: fields
                .iter()
                .map(|(field, type_)| ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: (*field).try_into().unwrap(),
                    type_: type_.clone(),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        })
    }

    fn enum_(name: &str, cases: &[(&str, u32)]) -> ScSpecEntry {
        ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: cases
                .iter()
                .map(|(case, value)| ScSpecUdtEnumCaseV0 {
                    doc: StringM::default(),
                    name: (*case).try_into().unwrap(),
                    value: *value,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        })
    }

    fn union_void(name: &str, cases: &[&str]) -> ScSpecEntry {
        ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: cases
                .iter()
                .map(|case| {
                    ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                        doc: StringM::default(),
                        name: (*case).try_into().unwrap(),
                    })
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        })
    }

    fn hash_of(entries: &[ScSpecEntry]) -> InterfaceHash {
        ContractSpec::from_entries(entries).interface_hash()
    }

    /// The headline property: entry order must not affect the hash.
    #[test]
    fn entry_order_does_not_affect_the_hash() {
        let a = function("transfer", &[("to", ScSpecTypeDef::Address)], None);
        let b = struct_("Data", &[("amount", ScSpecTypeDef::I128)]);
        let c = enum_("Status", &[("Active", 0), ("Frozen", 1)]);

        let forward = hash_of(&[a.clone(), b.clone(), c.clone()]);
        let reversed = hash_of(&[c.clone(), b.clone(), a.clone()]);
        let shuffled = hash_of(&[b, a, c]);

        assert_eq!(forward, reversed);
        assert_eq!(forward, shuffled);
    }

    /// Property-style: every permutation of a multi-entry spec hashes the same.
    #[test]
    fn all_permutations_agree() {
        let entries = vec![
            function("mint", &[("amount", ScSpecTypeDef::U32)], None),
            function("burn", &[("amount", ScSpecTypeDef::U32)], None),
            struct_("Config", &[("owner", ScSpecTypeDef::Address)]),
            enum_("Phase", &[("Open", 0), ("Closed", 1)]),
            union_void("Either", &["Left", "Right"]),
        ];

        let expected = hash_of(&entries);

        // Rotate through every cyclic ordering plus the full reversal; that is
        // enough distinct orderings to catch any accidental order dependence
        // without enumerating 120 permutations.
        for rotation in 0..entries.len() {
            let mut rotated = entries.clone();
            rotated.rotate_left(rotation);
            assert_eq!(hash_of(&rotated), expected, "rotation {rotation} differed");

            rotated.reverse();
            assert_eq!(
                hash_of(&rotated),
                expected,
                "reversed rotation {rotation} differed"
            );
        }
    }

    #[test]
    fn identical_specs_hash_identically() {
        let build = || {
            vec![
                function("transfer", &[("to", ScSpecTypeDef::Address)], None),
                struct_("Data", &[("amount", ScSpecTypeDef::I128)]),
            ]
        };
        assert_eq!(hash_of(&build()), hash_of(&build()));
    }

    #[test]
    fn empty_spec_is_stable_and_distinct() {
        assert_eq!(hash_of(&[]), hash_of(&[]));
        assert_ne!(
            hash_of(&[]),
            hash_of(&[function("noop", &[], None)]),
            "an empty spec must not collide with a one-function spec"
        );
    }

    // --- Changes that MUST move the hash -------------------------------------

    #[test]
    fn adding_a_function_changes_the_hash() {
        let base = vec![function("a", &[], None)];
        let mut extended = base.clone();
        extended.push(function("b", &[], None));
        assert_ne!(hash_of(&base), hash_of(&extended));
    }

    #[test]
    fn renaming_a_function_changes_the_hash() {
        assert_ne!(
            hash_of(&[function("transfer", &[], None)]),
            hash_of(&[function("send", &[], None)])
        );
    }

    #[test]
    fn renaming_a_parameter_changes_the_hash() {
        assert_ne!(
            hash_of(&[function("f", &[("to", ScSpecTypeDef::Address)], None)]),
            hash_of(&[function("f", &[("dest", ScSpecTypeDef::Address)], None)])
        );
    }

    #[test]
    fn changing_a_parameter_type_changes_the_hash() {
        assert_ne!(
            hash_of(&[function("f", &[("v", ScSpecTypeDef::U32)], None)]),
            hash_of(&[function("f", &[("v", ScSpecTypeDef::U64)], None)])
        );
    }

    #[test]
    fn reordering_parameters_changes_the_hash() {
        let a = function(
            "f",
            &[("x", ScSpecTypeDef::U32), ("y", ScSpecTypeDef::Address)],
            None,
        );
        let b = function(
            "f",
            &[("y", ScSpecTypeDef::Address), ("x", ScSpecTypeDef::U32)],
            None,
        );
        assert_ne!(hash_of(&[a]), hash_of(&[b]));
    }

    #[test]
    fn changing_a_return_type_changes_the_hash() {
        assert_ne!(
            hash_of(&[function("f", &[], Some(ScSpecTypeDef::U32))]),
            hash_of(&[function("f", &[], Some(ScSpecTypeDef::U64))])
        );
        assert_ne!(
            hash_of(&[function("f", &[], None)]),
            hash_of(&[function("f", &[], Some(ScSpecTypeDef::Void))]),
            "no declared return must differ from an explicit void return"
        );
    }

    #[test]
    fn reordering_struct_fields_changes_the_hash() {
        let a = struct_("S", &[("x", ScSpecTypeDef::U32), ("y", ScSpecTypeDef::U32)]);
        let b = struct_("S", &[("y", ScSpecTypeDef::U32), ("x", ScSpecTypeDef::U32)]);
        assert_ne!(
            hash_of(&[a]),
            hash_of(&[b]),
            "struct fields serialize positionally, so order is interface-relevant"
        );
    }

    #[test]
    fn reordering_union_cases_changes_the_hash() {
        assert_ne!(
            hash_of(&[union_void("U", &["A", "B"])]),
            hash_of(&[union_void("U", &["B", "A"])]),
            "union cases serialize by positional discriminant"
        );
    }

    #[test]
    fn changing_an_enum_case_value_changes_the_hash() {
        assert_ne!(
            hash_of(&[enum_("E", &[("A", 0)])]),
            hash_of(&[enum_("E", &[("A", 1)])])
        );
    }

    #[test]
    fn a_type_changing_kind_changes_the_hash() {
        // The #250 case: `Status` goes from a struct to an enum. Nothing about
        // the name changed, so only the kind tag can distinguish these.
        assert_ne!(
            hash_of(&[struct_("Status", &[])]),
            hash_of(&[enum_("Status", &[])])
        );
    }

    #[test]
    fn a_udt_named_like_a_primitive_is_distinguishable() {
        // `type_to_string` renders both of these as "u32"; a hash built on it
        // would collide here.
        let primitive = function("f", &[("v", ScSpecTypeDef::U32)], None);
        let udt = function(
            "f",
            &[(
                "v",
                ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                    name: "u32".try_into().unwrap(),
                }),
            )],
            None,
        );
        assert_ne!(hash_of(&[primitive]), hash_of(&[udt]));
    }

    #[test]
    fn name_boundaries_are_unambiguous() {
        // Without length prefixing, ("ab", "c") and ("a", "bc") could produce
        // the same stream.
        assert_ne!(
            hash_of(&[function("ab", &[("c", ScSpecTypeDef::U32)], None)]),
            hash_of(&[function("a", &[("bc", ScSpecTypeDef::U32)], None)])
        );
    }

    // --- Changes that MUST NOT move the hash ---------------------------------

    #[test]
    fn reordering_enum_cases_does_not_change_the_hash() {
        // Cases carry explicit values and are matched by name, so declaration
        // order is not an interface change.
        assert_eq!(
            hash_of(&[enum_("E", &[("A", 0), ("B", 1)])]),
            hash_of(&[enum_("E", &[("B", 1), ("A", 0)])])
        );
    }

    #[test]
    fn doc_strings_do_not_change_the_hash() {
        let bare = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "f".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        });
        let documented = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: "Transfers tokens.".try_into().unwrap(),
            name: "f".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        });
        assert_eq!(
            hash_of(&[bare]),
            hash_of(&[documented]),
            "editing a doc comment must not invalidate a cached interface hash"
        );
    }

    #[test]
    fn the_lib_field_does_not_change_the_hash() {
        let local = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "S".try_into().unwrap(),
            fields: VecM::default(),
        });
        let from_lib = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: "some_dependency".try_into().unwrap(),
            name: "S".try_into().unwrap(),
            fields: VecM::default(),
        });
        assert_eq!(hash_of(&[local]), hash_of(&[from_lib]));
    }

    // --- Representation ------------------------------------------------------

    #[test]
    fn hex_representation_is_well_formed() {
        let hash = hash_of(&[function("f", &[], None)]);
        let hex = hash.to_hex();

        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(hex, hash.to_string());
        assert_eq!(hash.to_short_hex(), &hex[..12]);
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn serializes_as_a_hex_string() {
        let hash = hash_of(&[function("f", &[], None)]);
        assert_eq!(
            serde_json::to_value(hash).unwrap(),
            serde_json::Value::String(hash.to_hex())
        );
    }

    #[test]
    fn canonical_form_is_domain_separated_and_versioned() {
        let form = canonical_form(&ContractSpec::default());
        let domain = DOMAIN.as_bytes();

        // The domain string appears length-prefixed at the very front.
        assert_eq!(&form[..8], &(domain.len() as u64).to_be_bytes());
        assert_eq!(&form[8..8 + domain.len()], domain);
        assert_eq!(
            &form[8 + domain.len()..8 + domain.len() + 4],
            &CANONICAL_FORM_VERSION.to_be_bytes()
        );
    }

    #[test]
    fn canonical_form_is_deterministic() {
        let entries = vec![
            function("b", &[], None),
            function("a", &[], None),
            struct_("Z", &[]),
        ];
        let spec = ContractSpec::from_entries(&entries);

        // Recomputing from the same spec, and from a differently-ordered build
        // of the same entries, must both yield byte-identical forms.
        assert_eq!(canonical_form(&spec), canonical_form(&spec));

        let mut reordered = entries.clone();
        reordered.reverse();
        assert_eq!(
            canonical_form(&spec),
            canonical_form(&ContractSpec::from_entries(&reordered))
        );
    }
}
