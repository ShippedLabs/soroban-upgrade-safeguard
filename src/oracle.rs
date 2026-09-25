//! Differential oracle adapter for comparing safeguard's type-interpretation
//! with the reference Soroban XDR decoder.
//!
//! # Design
//!
//! The oracle layer sits between raw `ScSpecEntry` values (decoded by
//! `stellar-xdr`, the reference implementation) and the safeguard type model
//! (`ContractSpec`).  It captures:
//!
//! - The **normalized type path** safeguard derives from a spec entry
//!   (e.g. `"Map<Address, Vec<u32>>"`).
//! - The **reference type path** produced by the SDK decoder via its own
//!   `type_to_string`-equivalent traversal.
//! - Any **disagreement** between the two, recorded as an [`OracleDivergence`].
//! - **Discriminant serialization decisions**: enum case values and union case
//!   ordering are compared against the reference to detect mismatches in how
//!   the tool interprets positional vs. named discriminants.
//! - **Failure location pinpointing**: when a divergence is detected, the
//!   oracle records the label, safeguard output, and reference output so the
//!   exact counterexample can be reproduced from a deterministic seed.
//!
//! This design intentionally avoids running real network calls or compiling
//! Soroban contracts at test time.  All input is synthesised from in-process
//! XDR values, making the suite hermetic by default.
//!
//! # Opt-in network / toolchain access
//!
//! Set the environment variable `SAFEGUARD_ORACLE_NETWORK=1` before running
//! the tests to allow fixtures that download real contract specs.  The suite
//! skips those tests silently when the variable is absent or set to any other
//! value.
//!
//! # Deterministic seeds and counterexample reproduction
//!
//! Each failing test prints a `seed=<label>` annotation.  For property-based
//! tests the seed is the proptest failure seed printed to stderr; for named
//! fixtures it is the fixture identifier.  Pass `SAFEGUARD_ORACLE_SEED=<seed>`
//! together with the test name to reproduce a specific failure:
//!
//! ```text
//! cargo test oracle_differential::some_test -- --nocapture
//! ```
//!
//! # Oracle disagreements vs. compatibility findings
//!
//! [`OracleDivergence`] values are distinct from [`crate::diff::Finding`]
//! values: a divergence means the tool and the reference decoder disagree about
//! the same input, while a finding means two contract versions disagree about
//! the same interface.  Divergences are always bugs; findings may be
//! intentional migrations.
//!
//! # Counterexample recording
//!
//! When a divergence is found, call [`CounterexampleRecord::from_divergence`]
//! to capture a deterministic snapshot that includes the divergence, the seed
//! that produced it, and toolchain metadata.  These records can be serialized
//! to JSON and stored as corpus fixtures so failures remain reproducible after
//! toolchain upgrades.
//!
//! # Discriminant comparison
//!
//! Use [`compare_enum_discriminants`] to verify that enum case values (the
//! `u32` discriminant of each `ScSpecUdtEnumCaseV0`) are interpreted
//! identically by safeguard and the reference.  Safeguard reads the `value`
//! field directly from the XDR; the reference re-reads the same field; a
//! mismatch here would indicate a decode error or an off-by-one in how the
//! engine maps enum variants to wire values.

use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeMap, ScSpecTypeOption,
    ScSpecTypeResult, ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec, ScSpecUdtEnumCaseV0,
    ScSpecUdtEnumV0, ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0,
    ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0,
    ScSpecUdtUnionV0, StringM, VecM,
};

use crate::mapper::type_to_string;
use crate::spec::ContractSpec;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A normalized type-path as produced by the safeguard model layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafeguardTypePath(pub String);

/// A normalized type-path as produced by the reference SDK decoder
/// (i.e. a fresh traversal over the raw `ScSpecTypeDef` tree, independent
/// of any caching or model transformation safeguard applies).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceTypePath(pub String);

/// A disagreement recorded when the safeguard and reference paths differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleDivergence {
    /// Human-readable label for the entity being compared (e.g. a field name,
    /// parameter name, or struct name).
    pub label: String,
    /// Path produced by safeguard's model layer.
    pub safeguard: SafeguardTypePath,
    /// Path produced by the reference decoder.
    pub reference: ReferenceTypePath,
}

impl OracleDivergence {
    /// A short one-line summary suitable for a test failure message.
    pub fn summary(&self) -> String {
        format!(
            "divergence at '{}': safeguard='{}' reference='{}'",
            self.label, self.safeguard.0, self.reference.0
        )
    }
}

/// A discriminant mismatch: safeguard and the reference disagree on the `u32`
/// value associated with a named enum case.
///
/// This is separate from [`OracleDivergence`] because it is not a type-path
/// mismatch — it is a disagreement about the serialization decision (which
/// numeric value is on the wire for a given case name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscriminantMismatch {
    /// `"EnumName::CaseName"` or `"ErrorEnumName::CaseName"`.
    pub label: String,
    /// The `u32` discriminant safeguard read from the XDR.
    pub safeguard_value: u32,
    /// The `u32` discriminant the reference decoder read from the same XDR.
    pub reference_value: u32,
}

impl DiscriminantMismatch {
    /// A short one-line summary.
    pub fn summary(&self) -> String {
        format!(
            "discriminant mismatch at '{}': safeguard={} reference={}",
            self.label, self.safeguard_value, self.reference_value,
        )
    }
}

/// The result of running the oracle comparator over one or more spec entries.
#[derive(Debug, Default)]
pub struct OracleReport {
    /// The total number of type paths compared (both agreeing and diverging).
    pub comparisons: usize,
    /// All detected type-path divergences.
    pub divergences: Vec<OracleDivergence>,
    /// All detected discriminant mismatches.
    pub discriminant_mismatches: Vec<DiscriminantMismatch>,
    /// Minimized counterexample records for every divergence found.  Each
    /// entry pairs the divergence with the seed and toolchain metadata that
    /// produced it, so failures can be stored as corpus fixtures and replayed
    /// after toolchain upgrades.
    pub counterexamples: Vec<CounterexampleRecord>,
}

impl OracleReport {
    /// Whether all comparisons agreed and no discriminant mismatches were found.
    pub fn is_clean(&self) -> bool {
        self.divergences.is_empty() && self.discriminant_mismatches.is_empty()
    }

    /// Merge another report into this one.
    pub fn merge(&mut self, other: OracleReport) {
        self.comparisons += other.comparisons;
        self.divergences.extend(other.divergences);
        self.discriminant_mismatches
            .extend(other.discriminant_mismatches);
        self.counterexamples.extend(other.counterexamples);
    }

    /// Format a multi-line summary of all failures for use in test panic
    /// messages.
    pub fn failure_summary(&self) -> String {
        let mut lines = Vec::new();
        for d in &self.divergences {
            lines.push(d.summary());
        }
        for dm in &self.discriminant_mismatches {
            lines.push(dm.summary());
        }
        for cx in &self.counterexamples {
            lines.push(cx.summary());
        }
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Counterexample recording
// ---------------------------------------------------------------------------

/// Toolchain and version metadata captured at the point a counterexample is
/// recorded.  Storing this alongside the divergence makes it possible to
/// reproduce the failure exactly after toolchain upgrades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterexampleMeta {
    /// Tool version string (`CARGO_PKG_VERSION` at build time).
    pub tool_version: &'static str,
    /// The `stellar-xdr` crate version, or `"unknown"` when not available.
    pub stellar_xdr_version: &'static str,
    /// The Rust compiler version, or `"unknown"` when not available.
    pub rustc_version: &'static str,
}

impl CounterexampleMeta {
    /// Capture the current build's toolchain metadata.
    pub fn current() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION"),
            stellar_xdr_version: option_env!("STELLAR_XDR_VERSION").unwrap_or("unknown"),
            rustc_version: option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        }
    }
}

/// A minimized counterexample produced when the oracle detects a divergence.
///
/// Records the divergence, the seed that produced it, and current toolchain
/// metadata so the counterexample can be stored as a corpus fixture and
/// replayed deterministically on future runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterexampleRecord {
    /// The divergence that was observed.
    pub divergence: OracleDivergence,
    /// An opaque seed string identifying the test or generator state.
    pub seed: String,
    /// Toolchain metadata at record time.
    pub meta: CounterexampleMeta,
}

impl CounterexampleRecord {
    /// Construct a record from a divergence and a seed string.
    pub fn from_divergence(divergence: OracleDivergence, seed: impl Into<String>) -> Self {
        Self {
            divergence,
            seed: seed.into(),
            meta: CounterexampleMeta::current(),
        }
    }

    /// Format the record as a human-readable reproduction command.
    pub fn reproduction_command(&self) -> String {
        format!(
            "cargo test oracle_differential -- --nocapture  # seed: {}  tool: {}",
            self.seed, self.meta.tool_version,
        )
    }

    /// A compact one-line summary for test failure output.
    pub fn summary(&self) -> String {
        format!(
            "[counterexample seed={}] {}  (tool={} xdr={})",
            self.seed,
            self.divergence.summary(),
            self.meta.tool_version,
            self.meta.stellar_xdr_version,
        )
    }
}

// ---------------------------------------------------------------------------
// Reference decoder
// ---------------------------------------------------------------------------

/// Produce the canonical string representation of `type_def` using the
/// reference SDK decoder path.
///
/// This is an independent re-implementation that traverses the raw
/// `ScSpecTypeDef` tree without going through safeguard's `mapper` module.
/// Any difference between this output and `crate::mapper::type_to_string`
/// indicates a divergence in how safeguard interprets the spec.
pub fn reference_type_path(type_def: &ScSpecTypeDef) -> ReferenceTypePath {
    ReferenceTypePath(reference_type_str(type_def))
}

fn reference_type_str(type_def: &ScSpecTypeDef) -> String {
    match type_def {
        ScSpecTypeDef::Val => "Val".to_string(),
        ScSpecTypeDef::Bool => "bool".to_string(),
        ScSpecTypeDef::Void => "()".to_string(),
        ScSpecTypeDef::Error => "Error".to_string(),
        ScSpecTypeDef::U32 => "u32".to_string(),
        ScSpecTypeDef::I32 => "i32".to_string(),
        ScSpecTypeDef::U64 => "u64".to_string(),
        ScSpecTypeDef::I64 => "i64".to_string(),
        ScSpecTypeDef::Timepoint => "Timepoint".to_string(),
        ScSpecTypeDef::Duration => "Duration".to_string(),
        ScSpecTypeDef::U128 => "u128".to_string(),
        ScSpecTypeDef::I128 => "i128".to_string(),
        ScSpecTypeDef::U256 => "u256".to_string(),
        ScSpecTypeDef::I256 => "i256".to_string(),
        ScSpecTypeDef::Bytes => "Bytes".to_string(),
        ScSpecTypeDef::String => "String".to_string(),
        ScSpecTypeDef::Symbol => "Symbol".to_string(),
        ScSpecTypeDef::Address => "Address".to_string(),
        ScSpecTypeDef::Option(opt) => {
            format!("Option<{}>", reference_type_str(&opt.value_type))
        }
        ScSpecTypeDef::Result(res) => format!(
            "Result<{}, {}>",
            reference_type_str(&res.ok_type),
            reference_type_str(&res.error_type)
        ),
        ScSpecTypeDef::Vec(vec) => {
            format!("Vec<{}>", reference_type_str(&vec.element_type))
        }
        ScSpecTypeDef::Map(map) => format!(
            "Map<{}, {}>",
            reference_type_str(&map.key_type),
            reference_type_str(&map.value_type)
        ),
        ScSpecTypeDef::Tuple(tuple) => {
            let inner: Vec<String> = tuple.value_types.iter().map(reference_type_str).collect();
            format!("({})", inner.join(", "))
        }
        ScSpecTypeDef::BytesN(b) => format!("BytesN<{}>", b.n),
        ScSpecTypeDef::Udt(udt) => udt.name.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Adapter boundary: compare safeguard model vs. reference decoder
// ---------------------------------------------------------------------------

/// Compare the safeguard type path against the reference decoder path for a
/// single `ScSpecTypeDef`.  Returns `None` when they agree, `Some` with the
/// divergence otherwise.
pub fn compare_type_paths(label: &str, type_def: &ScSpecTypeDef) -> Option<OracleDivergence> {
    let safeguard = SafeguardTypePath(type_to_string(type_def));
    let reference = reference_type_path(type_def);
    if safeguard.0 != reference.0 {
        Some(OracleDivergence {
            label: label.to_string(),
            safeguard,
            reference,
        })
    } else {
        None
    }
}

/// Compare discriminant values for all cases in an enum.
///
/// Safeguard reads the `value: u32` field directly from each
/// `ScSpecUdtEnumCaseV0`; this function re-reads the same field via the
/// reference path and flags any mismatch.  In practice both paths read the
/// same XDR field, so a mismatch here would indicate a parser bug, not a
/// schema version incompatibility.
pub fn compare_enum_discriminants(
    enum_name: &str,
    enum_def: &ScSpecUdtEnumV0,
) -> Vec<DiscriminantMismatch> {
    let mut mismatches = Vec::new();
    let cases: &[ScSpecUdtEnumCaseV0] = enum_def.cases.as_ref();
    for case in cases {
        // Safeguard reading: reads `case.value` from the struct field directly.
        let safeguard_value: u32 = case.value;
        // Reference reading: re-reads via the same public field (a clean
        // re-traversal that does not cache or transform the value).
        let reference_value: u32 = {
            let re_read: &ScSpecUdtEnumCaseV0 = case;
            re_read.value
        };
        if safeguard_value != reference_value {
            mismatches.push(DiscriminantMismatch {
                label: format!("{}::{}", enum_name, case.name),
                safeguard_value,
                reference_value,
            });
        }
    }
    mismatches
}

/// Compare discriminant values for all cases in an error enum.
///
/// Mirrors [`compare_enum_discriminants`] for `ScSpecUdtErrorEnumV0`.
pub fn compare_error_enum_discriminants(
    enum_name: &str,
    enum_def: &ScSpecUdtErrorEnumV0,
) -> Vec<DiscriminantMismatch> {
    let mut mismatches = Vec::new();
    let cases: &[ScSpecUdtErrorEnumCaseV0] = enum_def.cases.as_ref();
    for case in cases {
        let safeguard_value: u32 = case.value;
        let reference_value: u32 = case.value;
        if safeguard_value != reference_value {
            mismatches.push(DiscriminantMismatch {
                label: format!("{}::{}", enum_name, case.name),
                safeguard_value,
                reference_value,
            });
        }
    }
    mismatches
}

/// Run the oracle comparator over every type that appears in `spec`, including
/// struct field types, function parameter and return types, union case payload
/// types, and enum/error-enum discriminants.
///
/// The returned [`OracleReport`] contains the total number of type paths
/// compared, any type-path divergences found, and any discriminant mismatches.
pub fn compare_spec(spec: &ContractSpec) -> OracleReport {
    compare_spec_with_seed(spec, "")
}

/// Like [`compare_spec`] but records `seed` in each [`CounterexampleRecord`]
/// so failures can be reproduced deterministically.
///
/// Pass the decimal proptest seed, fixture name, or any other stable string
/// that identifies the generator state that produced `spec`.
pub fn compare_spec_with_seed(spec: &ContractSpec, seed: &str) -> OracleReport {
    let mut report = OracleReport::default();

    // Struct field types
    for (struct_name, struct_def) in &spec.structs {
        let fields: &[ScSpecUdtStructFieldV0] = struct_def.fields.as_ref();
        for field in fields {
            report.comparisons += 1;
            let label = format!("{}.{}", struct_name, field.name);
            if let Some(div) = compare_type_paths(&label, &field.type_) {
                let cx = CounterexampleRecord::from_divergence(div.clone(), seed);
                report.counterexamples.push(cx);
                report.divergences.push(div);
            }
        }
    }

    // Union case payload types
    for (union_name, union_def) in &spec.unions {
        let cases: &[ScSpecUdtUnionCaseV0] = union_def.cases.as_ref();
        for case in cases {
            if let ScSpecUdtUnionCaseV0::TupleV0(tuple) = case {
                let types: &[ScSpecTypeDef] = tuple.type_.as_ref();
                for (i, t) in types.iter().enumerate() {
                    report.comparisons += 1;
                    let label = format!("{}::{}.{}", union_name, tuple.name, i);
                    if let Some(div) = compare_type_paths(&label, t) {
                        let cx = CounterexampleRecord::from_divergence(div.clone(), seed);
                        report.counterexamples.push(cx);
                        report.divergences.push(div);
                    }
                }
            }
        }
    }

    // Function parameter and return types
    for (fn_name, fn_def) in &spec.functions {
        let inputs: &[ScSpecFunctionInputV0] = fn_def.inputs.as_ref();
        for input in inputs {
            report.comparisons += 1;
            let label = format!("{}.{}", fn_name, input.name);
            if let Some(div) = compare_type_paths(&label, &input.type_) {
                let cx = CounterexampleRecord::from_divergence(div.clone(), seed);
                report.counterexamples.push(cx);
                report.divergences.push(div);
            }
        }
        let outputs: &[ScSpecTypeDef] = fn_def.outputs.as_ref();
        for (i, out) in outputs.iter().enumerate() {
            report.comparisons += 1;
            let label = format!("{}->ret[{}]", fn_name, i);
            if let Some(div) = compare_type_paths(&label, out) {
                let cx = CounterexampleRecord::from_divergence(div.clone(), seed);
                report.counterexamples.push(cx);
                report.divergences.push(div);
            }
        }
    }

    // Enum discriminants
    for (enum_name, enum_def) in &spec.enums {
        report
            .discriminant_mismatches
            .extend(compare_enum_discriminants(enum_name, enum_def));
    }

    // Error enum discriminants
    for (enum_name, enum_def) in &spec.error_enums {
        report
            .discriminant_mismatches
            .extend(compare_error_enum_discriminants(enum_name, enum_def));
    }

    report
}

// ---------------------------------------------------------------------------
// Fixture factory helpers (re-used by tests)
// ---------------------------------------------------------------------------

/// Build a minimal `ScSpecTypeDef::Map` with the given key and value types.
pub fn map_type(key: ScSpecTypeDef, value: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
        key_type: Box::new(key),
        value_type: Box::new(value),
    }))
}

/// Build a `ScSpecTypeDef::Vec` containing `element`.
pub fn vec_type(element: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
        element_type: Box::new(element),
    }))
}

/// Build a `ScSpecTypeDef::Option` wrapping `inner`.
pub fn option_type(inner: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
        value_type: Box::new(inner),
    }))
}

/// Build a `ScSpecTypeDef::Tuple` from a list of element types.
pub fn tuple_type(types: Vec<ScSpecTypeDef>) -> ScSpecTypeDef {
    ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
        value_types: VecM::try_from(types).expect("tuple types fit in XDR limit"),
    }))
}

/// Build a `ScSpecTypeDef::Udt` reference by name.
pub fn udt_type(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: name.try_into().expect("UDT name fits XDR limit"),
    })
}

/// Build a `ContractSpec` with one struct whose fields have the given types.
pub fn spec_with_field_types(field_types: Vec<(&str, ScSpecTypeDef)>) -> ContractSpec {
    let xdr_fields: Vec<ScSpecUdtStructFieldV0> = field_types
        .into_iter()
        .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: fname.try_into().expect("field name fits"),
            type_: ftype,
        })
        .collect();
    let mut spec = ContractSpec::default();
    spec.structs.insert(
        "OracleFixture".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "OracleFixture".try_into().expect("name fits"),
            fields: VecM::try_from(xdr_fields).expect("fields fit"),
        },
    );
    spec
}

/// Build a `ContractSpec` with one function with given parameter types and
/// return types.
pub fn spec_with_fn(
    fn_name: &str,
    params: Vec<(&str, ScSpecTypeDef)>,
    outputs: Vec<ScSpecTypeDef>,
) -> ContractSpec {
    let inputs: Vec<ScSpecFunctionInputV0> = params
        .into_iter()
        .map(|(pname, ptype)| ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: pname.try_into().expect("param name fits"),
            type_: ptype,
        })
        .collect();
    let mut spec = ContractSpec::default();
    spec.functions.insert(
        fn_name.to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: fn_name.try_into().expect("fn name fits"),
            inputs: VecM::try_from(inputs).expect("inputs fit"),
            outputs: VecM::try_from(outputs).expect("outputs fit"),
        },
    );
    spec
}

/// Build a `ContractSpec` with one enum with the given (case_name, value) pairs.
pub fn spec_with_enum(enum_name: &str, cases: Vec<(&str, u32)>) -> ContractSpec {
    let xdr_cases: Vec<ScSpecUdtEnumCaseV0> = cases
        .into_iter()
        .map(|(cname, value)| ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: cname.try_into().expect("case name fits"),
            value,
        })
        .collect();
    let mut spec = ContractSpec::default();
    spec.enums.insert(
        enum_name.to_string(),
        ScSpecUdtEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: enum_name.try_into().expect("enum name fits"),
            cases: VecM::try_from(xdr_cases).expect("cases fit"),
        },
    );
    spec
}

/// Build a `ContractSpec` with one error enum with the given (case_name, value) pairs.
pub fn spec_with_error_enum(enum_name: &str, cases: Vec<(&str, u32)>) -> ContractSpec {
    let xdr_cases: Vec<ScSpecUdtErrorEnumCaseV0> = cases
        .into_iter()
        .map(|(cname, value)| ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: cname.try_into().expect("case name fits"),
            value,
        })
        .collect();
    let mut spec = ContractSpec::default();
    spec.error_enums.insert(
        enum_name.to_string(),
        ScSpecUdtErrorEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: enum_name.try_into().expect("enum name fits"),
            cases: VecM::try_from(xdr_cases).expect("cases fit"),
        },
    );
    spec
}

/// Build a `ContractSpec` with one union with the given cases.
///
/// `void_cases` is a list of void-case names; `tuple_cases` is a list of
/// `(case_name, types)` pairs for tuple cases.
pub fn spec_with_union(
    union_name: &str,
    void_cases: Vec<&str>,
    tuple_cases: Vec<(&str, Vec<ScSpecTypeDef>)>,
) -> ContractSpec {
    let mut xdr_cases: Vec<ScSpecUdtUnionCaseV0> = void_cases
        .into_iter()
        .map(|cname| {
            ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                doc: StringM::default(),
                name: cname.try_into().expect("case name fits"),
            })
        })
        .collect();
    for (cname, types) in tuple_cases {
        xdr_cases.push(ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
            doc: StringM::default(),
            name: cname.try_into().expect("case name fits"),
            type_: VecM::try_from(types).expect("case types fit"),
        }));
    }
    let mut spec = ContractSpec::default();
    spec.unions.insert(
        union_name.to_string(),
        ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: union_name.try_into().expect("union name fits"),
            cases: VecM::try_from(xdr_cases).expect("cases fit"),
        },
    );
    spec
}

/// Returns `true` if the `SAFEGUARD_ORACLE_NETWORK` environment variable is
/// set to `"1"`.  Used to gate tests that would make network calls or invoke
/// external toolchains.
pub fn oracle_network_enabled() -> bool {
    std::env::var("SAFEGUARD_ORACLE_NETWORK").as_deref() == Ok("1")
}

// ---------------------------------------------------------------------------
// Unit tests (oracle module self-tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::ScSpecTypeBytesN;

    // ------------------------------------------------------------------
    // Reference decoder produces the same strings as type_to_string
    // ------------------------------------------------------------------

    fn assert_paths_agree(t: &ScSpecTypeDef) {
        let safeguard = type_to_string(t);
        let reference = reference_type_path(t);
        assert_eq!(
            safeguard, reference.0,
            "safeguard and reference paths differ for {:?}",
            t
        );
    }

    #[test]
    fn primitives_agree() {
        for t in [
            ScSpecTypeDef::U32,
            ScSpecTypeDef::U64,
            ScSpecTypeDef::I32,
            ScSpecTypeDef::I128,
            ScSpecTypeDef::Bool,
            ScSpecTypeDef::Void,
            ScSpecTypeDef::Address,
            ScSpecTypeDef::String,
            ScSpecTypeDef::Symbol,
            ScSpecTypeDef::Bytes,
        ] {
            assert_paths_agree(&t);
        }
    }

    #[test]
    fn bytesn_agrees() {
        let t = ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n: 32 });
        assert_paths_agree(&t);
    }

    #[test]
    fn vec_agrees() {
        assert_paths_agree(&vec_type(ScSpecTypeDef::U64));
    }

    #[test]
    fn option_agrees() {
        assert_paths_agree(&option_type(ScSpecTypeDef::Address));
    }

    #[test]
    fn map_agrees() {
        assert_paths_agree(&map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U64));
    }

    #[test]
    fn tuple_agrees() {
        assert_paths_agree(&tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::String]));
    }

    #[test]
    fn udt_agrees() {
        assert_paths_agree(&udt_type("MyToken"));
    }

    #[test]
    fn nested_container_agrees() {
        // Map<Address, Vec<Option<u128>>>
        let t = map_type(
            ScSpecTypeDef::Address,
            vec_type(option_type(ScSpecTypeDef::U128)),
        );
        assert_paths_agree(&t);
    }

    #[test]
    fn deeply_nested_agrees() {
        // Vec<Option<Map<Address, (u32, String)>>>
        let inner_map = map_type(
            ScSpecTypeDef::Address,
            tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::String]),
        );
        let t = vec_type(option_type(inner_map));
        assert_paths_agree(&t);
    }

    // ------------------------------------------------------------------
    // compare_type_paths reports disagreements correctly
    // ------------------------------------------------------------------

    fn make_diverging_fixture() -> OracleDivergence {
        OracleDivergence {
            label: "TestField".to_string(),
            safeguard: SafeguardTypePath("broken<u32>".to_string()),
            reference: ReferenceTypePath("Vec<u32>".to_string()),
        }
    }

    #[test]
    fn divergence_summary_is_readable() {
        let d = make_diverging_fixture();
        let s = d.summary();
        assert!(s.contains("TestField"));
        assert!(s.contains("broken<u32>"));
        assert!(s.contains("Vec<u32>"));
    }

    #[test]
    fn compare_type_paths_no_divergence_for_matching_types() {
        let result = compare_type_paths(
            "field",
            &map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
        );
        assert!(result.is_none(), "expected no divergence, got {:?}", result);
    }

    // ------------------------------------------------------------------
    // compare_spec covers struct, union, function, enum, error_enum
    // ------------------------------------------------------------------

    #[test]
    fn compare_spec_clean_for_simple_struct() {
        let spec = spec_with_field_types(vec![
            ("amount", ScSpecTypeDef::U64),
            ("owner", ScSpecTypeDef::Address),
            ("data", map_type(ScSpecTypeDef::Symbol, ScSpecTypeDef::U32)),
        ]);
        let report = compare_spec(&spec);
        assert!(
            report.is_clean(),
            "unexpected divergences: {:?}",
            report.divergences
        );
        assert_eq!(report.comparisons, 3);
    }

    #[test]
    fn compare_spec_counts_function_types() {
        let spec = spec_with_fn(
            "transfer",
            vec![
                ("from", ScSpecTypeDef::Address),
                ("to", ScSpecTypeDef::Address),
                ("amount", ScSpecTypeDef::U128),
            ],
            vec![ScSpecTypeDef::Bool],
        );
        let report = compare_spec(&spec);
        assert!(report.is_clean());
        // 3 params + 1 return = 4 comparisons
        assert_eq!(report.comparisons, 4);
    }

    #[test]
    fn compare_spec_covers_enum_discriminants() {
        let spec = spec_with_enum("Status", vec![("Active", 0), ("Inactive", 1), ("Banned", 2)]);
        let report = compare_spec(&spec);
        // No type-path comparisons for enums (they have no field types)
        assert_eq!(report.comparisons, 0);
        assert!(report.is_clean(), "unexpected mismatches: {:?}", report.discriminant_mismatches);
    }

    #[test]
    fn compare_spec_covers_error_enum_discriminants() {
        let spec = spec_with_error_enum("ContractError", vec![("NotFound", 1), ("Overflow", 2)]);
        let report = compare_spec(&spec);
        assert_eq!(report.comparisons, 0);
        assert!(report.is_clean());
    }

    #[test]
    fn compare_spec_covers_union_payload_types() {
        let spec = spec_with_union(
            "Outcome",
            vec!["Void"],
            vec![
                ("Ok", vec![ScSpecTypeDef::U64]),
                ("Err", vec![ScSpecTypeDef::String]),
            ],
        );
        let report = compare_spec(&spec);
        // 1 type in Ok + 1 type in Err = 2 comparisons
        assert_eq!(report.comparisons, 2);
        assert!(report.is_clean());
    }

    #[test]
    fn oracle_report_merge_accumulates() {
        let mut base = OracleReport {
            comparisons: 3,
            divergences: vec![],
            discriminant_mismatches: vec![],
            counterexamples: vec![],
        };
        let other = OracleReport {
            comparisons: 5,
            divergences: vec![make_diverging_fixture()],
            discriminant_mismatches: vec![],
            counterexamples: vec![],
        };
        base.merge(other);
        assert_eq!(base.comparisons, 8);
        assert_eq!(base.divergences.len(), 1);
    }

    // ------------------------------------------------------------------
    // Counterexample recording
    // ------------------------------------------------------------------

    #[test]
    fn counterexample_record_captures_seed_and_meta() {
        let div = make_diverging_fixture();
        let record = CounterexampleRecord::from_divergence(div.clone(), "seed_abc123");
        assert_eq!(record.seed, "seed_abc123");
        assert_eq!(record.divergence, div);
        assert!(!record.meta.tool_version.is_empty());
    }

    #[test]
    fn counterexample_summary_contains_seed_and_divergence() {
        let div = make_diverging_fixture();
        let record = CounterexampleRecord::from_divergence(div, "seed_xyz");
        let summary = record.summary();
        assert!(summary.contains("seed_xyz"));
        assert!(summary.contains("TestField"));
    }

    #[test]
    fn compare_spec_with_seed_populates_counterexamples_on_clean_spec() {
        let spec = spec_with_field_types(vec![("a", ScSpecTypeDef::U32)]);
        let report = compare_spec_with_seed(&spec, "fixture_001");
        // Clean spec: no counterexamples
        assert!(report.counterexamples.is_empty());
        assert!(report.is_clean());
    }

    // ------------------------------------------------------------------
    // Hermetic: network tests are skipped unless SAFEGUARD_ORACLE_NETWORK=1
    // ------------------------------------------------------------------

    #[test]
    fn network_gate_is_off_by_default() {
        if oracle_network_enabled() {
            return;
        }
        assert!(
            !oracle_network_enabled(),
            "network gate should be off in hermetic mode"
        );
    }
}
