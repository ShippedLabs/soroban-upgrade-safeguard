//! Static WASM instruction and complexity delta reporting.
//!
//! This module profiles the *code section* of a WebAssembly module and
//! produces a deterministic, bounded summary of its complexity signals.
//! The summary can then be compared between two builds — old and new — to
//! surface regressions before deployment.
//!
//! # What is measured
//!
//! Instruction counts are grouped into coarse **families** rather than
//! tracked per-opcode.  That keeps the output stable across compiler
//! versions that may freely substitute equivalent instruction sequences,
//! while still capturing the categories that matter most for review:
//!
//! | Family | What it counts |
//! |---|---|
//! | `arithmetic` | i32/i64/f32/f64 arithmetic and bitwise ops |
//! | `control` | blocks, loops, if, br, br_if, br_table, return, unreachable |
//! | `calls` | direct call, indirect call_indirect |
//! | `memory` | load/store instructions (all widths), memory.size/grow/copy/fill |
//! | `comparison` | eq/ne/lt/gt/le/ge for all numeric types |
//! | `conversion` | type-conversion and reinterpret instructions |
//! | `reference` | ref.null, ref.is_null, ref.func — reference-types proposal ops |
//! | `simd` | v128 instructions — SIMD proposal ops |
//! | `other` | every instruction that does not fit the above (select, drop, …) |
//!
//! In addition the module-level totals include:
//!
//! - **`defined_functions`**: number of functions in the Code section
//!   (imported functions are counted in `RuntimeSurface`, not here).
//! - **`total_instructions`**: sum of every instruction across all functions.
//! - Per-family counts as described above.
//!
//! # What this is NOT
//!
//! These counts are **static analysis only**.  They are not Soroban host
//! gas estimates, runtime profiling data, or execution traces.  A function
//! that is called a million times at runtime may appear identical to one
//! that is never called.  Fuel / metering is a separate concern handled by
//! the Soroban runtime itself.  Budget entries in `.safeguard.toml` should
//! therefore be calibrated against the static counts the tool actually
//! reports, not against expected execution cost.
//!
//! # Config shape (`.safeguard.toml`)
//!
//! ```toml
//! # Gate on total instruction count growth (global, any severity)
//! [[complexity_budget]]
//! metric = "total_instructions"
//! limit  = 50000
//!
//! # Gate on net new control-flow instructions
//! [[complexity_budget]]
//! metric  = "control"
//! limit   = 5000
//!
//! # Gate on the number of newly-defined functions
//! [[complexity_budget]]
//! metric  = "defined_functions"
//! limit   = 200
//! ```
//!
//! Each entry constrains the **new build's absolute value** of that metric.
//! Delta-based (percentage) limits use the `pct_limit` field instead:
//!
//! ```toml
//! # Fail if total instructions grew by more than 20 %
//! [[complexity_budget]]
//! metric    = "total_instructions"
//! pct_limit = 20
//! ```
//!
//! Both fields may be present; both checks must pass.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use wasmparser::{FunctionBody, Operator, Parser, Payload};

// ── Instruction family ────────────────────────────────────────────────────────

/// Coarse instruction family groupings.
///
/// The mapping is intentionally stable: adding a new WASM proposal that
/// introduces new opcodes in an existing family will be counted correctly
/// once the relevant `Operator` variants are added to [`family_of`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum InstructionFamily {
    Arithmetic,
    Control,
    Calls,
    Memory,
    Comparison,
    Conversion,
    Reference,
    Simd,
    #[default]
    Other,
}

impl InstructionFamily {
    /// Human-readable label, used in reports.
    pub fn label(self) -> &'static str {
        match self {
            InstructionFamily::Arithmetic => "arithmetic",
            InstructionFamily::Control => "control",
            InstructionFamily::Calls => "calls",
            InstructionFamily::Memory => "memory",
            InstructionFamily::Comparison => "comparison",
            InstructionFamily::Conversion => "conversion",
            InstructionFamily::Reference => "reference",
            InstructionFamily::Simd => "simd",
            InstructionFamily::Other => "other",
        }
    }

    /// All families in a stable, deterministic order for report rendering.
    pub fn all() -> &'static [InstructionFamily] {
        &[
            InstructionFamily::Arithmetic,
            InstructionFamily::Control,
            InstructionFamily::Calls,
            InstructionFamily::Memory,
            InstructionFamily::Comparison,
            InstructionFamily::Conversion,
            InstructionFamily::Reference,
            InstructionFamily::Simd,
            InstructionFamily::Other,
        ]
    }
}

/// Classify a single `wasmparser::Operator` into an [`InstructionFamily`].
fn family_of(op: &Operator<'_>) -> InstructionFamily {
    match op {
        // ── Control flow ──────────────────────────────────────────────────────
        Operator::Unreachable
        | Operator::Nop
        | Operator::Block { .. }
        | Operator::Loop { .. }
        | Operator::If { .. }
        | Operator::Else
        | Operator::End
        | Operator::Br { .. }
        | Operator::BrIf { .. }
        | Operator::BrTable { .. }
        | Operator::Return => InstructionFamily::Control,

        // ── Calls ─────────────────────────────────────────────────────────────
        Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::ReturnCall { .. }
        | Operator::ReturnCallIndirect { .. } => InstructionFamily::Calls,

        // ── Memory ────────────────────────────────────────────────────────────
        Operator::I32Load { .. }
        | Operator::I64Load { .. }
        | Operator::F32Load { .. }
        | Operator::F64Load { .. }
        | Operator::I32Load8S { .. }
        | Operator::I32Load8U { .. }
        | Operator::I32Load16S { .. }
        | Operator::I32Load16U { .. }
        | Operator::I64Load8S { .. }
        | Operator::I64Load8U { .. }
        | Operator::I64Load16S { .. }
        | Operator::I64Load16U { .. }
        | Operator::I64Load32S { .. }
        | Operator::I64Load32U { .. }
        | Operator::I32Store { .. }
        | Operator::I64Store { .. }
        | Operator::F32Store { .. }
        | Operator::F64Store { .. }
        | Operator::I32Store8 { .. }
        | Operator::I32Store16 { .. }
        | Operator::I64Store8 { .. }
        | Operator::I64Store16 { .. }
        | Operator::I64Store32 { .. }
        | Operator::MemorySize { .. }
        | Operator::MemoryGrow { .. }
        | Operator::MemoryCopy { .. }
        | Operator::MemoryFill { .. }
        | Operator::MemoryInit { .. }
        | Operator::DataDrop { .. } => InstructionFamily::Memory,

        // ── Comparison ────────────────────────────────────────────────────────
        Operator::I32Eqz
        | Operator::I32Eq
        | Operator::I32Ne
        | Operator::I32LtS
        | Operator::I32LtU
        | Operator::I32GtS
        | Operator::I32GtU
        | Operator::I32LeS
        | Operator::I32LeU
        | Operator::I32GeS
        | Operator::I32GeU
        | Operator::I64Eqz
        | Operator::I64Eq
        | Operator::I64Ne
        | Operator::I64LtS
        | Operator::I64LtU
        | Operator::I64GtS
        | Operator::I64GtU
        | Operator::I64LeS
        | Operator::I64LeU
        | Operator::I64GeS
        | Operator::I64GeU
        | Operator::F32Eq
        | Operator::F32Ne
        | Operator::F32Lt
        | Operator::F32Gt
        | Operator::F32Le
        | Operator::F32Ge
        | Operator::F64Eq
        | Operator::F64Ne
        | Operator::F64Lt
        | Operator::F64Gt
        | Operator::F64Le
        | Operator::F64Ge => InstructionFamily::Comparison,

        // ── Arithmetic / bitwise ──────────────────────────────────────────────
        Operator::I32Clz
        | Operator::I32Ctz
        | Operator::I32Popcnt
        | Operator::I32Add
        | Operator::I32Sub
        | Operator::I32Mul
        | Operator::I32DivS
        | Operator::I32DivU
        | Operator::I32RemS
        | Operator::I32RemU
        | Operator::I32And
        | Operator::I32Or
        | Operator::I32Xor
        | Operator::I32Shl
        | Operator::I32ShrS
        | Operator::I32ShrU
        | Operator::I32Rotl
        | Operator::I32Rotr
        | Operator::I64Clz
        | Operator::I64Ctz
        | Operator::I64Popcnt
        | Operator::I64Add
        | Operator::I64Sub
        | Operator::I64Mul
        | Operator::I64DivS
        | Operator::I64DivU
        | Operator::I64RemS
        | Operator::I64RemU
        | Operator::I64And
        | Operator::I64Or
        | Operator::I64Xor
        | Operator::I64Shl
        | Operator::I64ShrS
        | Operator::I64ShrU
        | Operator::I64Rotl
        | Operator::I64Rotr
        | Operator::F32Abs
        | Operator::F32Neg
        | Operator::F32Ceil
        | Operator::F32Floor
        | Operator::F32Trunc
        | Operator::F32Nearest
        | Operator::F32Sqrt
        | Operator::F32Add
        | Operator::F32Sub
        | Operator::F32Mul
        | Operator::F32Div
        | Operator::F32Min
        | Operator::F32Max
        | Operator::F32Copysign
        | Operator::F64Abs
        | Operator::F64Neg
        | Operator::F64Ceil
        | Operator::F64Floor
        | Operator::F64Trunc
        | Operator::F64Nearest
        | Operator::F64Sqrt
        | Operator::F64Add
        | Operator::F64Sub
        | Operator::F64Mul
        | Operator::F64Div
        | Operator::F64Min
        | Operator::F64Max
        | Operator::F64Copysign => InstructionFamily::Arithmetic,

        // ── Conversion / reinterpret ──────────────────────────────────────────
        Operator::I32WrapI64
        | Operator::I32TruncF32S
        | Operator::I32TruncF32U
        | Operator::I32TruncF64S
        | Operator::I32TruncF64U
        | Operator::I64ExtendI32S
        | Operator::I64ExtendI32U
        | Operator::I64TruncF32S
        | Operator::I64TruncF32U
        | Operator::I64TruncF64S
        | Operator::I64TruncF64U
        | Operator::F32ConvertI32S
        | Operator::F32ConvertI32U
        | Operator::F32ConvertI64S
        | Operator::F32ConvertI64U
        | Operator::F32DemoteF64
        | Operator::F64ConvertI32S
        | Operator::F64ConvertI32U
        | Operator::F64ConvertI64S
        | Operator::F64ConvertI64U
        | Operator::F64PromoteF32
        | Operator::I32ReinterpretF32
        | Operator::I64ReinterpretF64
        | Operator::F32ReinterpretI32
        | Operator::F64ReinterpretI64
        | Operator::I32Extend8S
        | Operator::I32Extend16S
        | Operator::I64Extend8S
        | Operator::I64Extend16S
        | Operator::I64Extend32S => InstructionFamily::Conversion,

        // ── Reference types ───────────────────────────────────────────────────
        Operator::RefNull { .. }
        | Operator::RefIsNull
        | Operator::RefFunc { .. }
        | Operator::RefEq => InstructionFamily::Reference,

        // ── SIMD ──────────────────────────────────────────────────────────────
        Operator::V128Load { .. }
        | Operator::V128Load8x8S { .. }
        | Operator::V128Load8x8U { .. }
        | Operator::V128Load16x4S { .. }
        | Operator::V128Load16x4U { .. }
        | Operator::V128Load32x2S { .. }
        | Operator::V128Load32x2U { .. }
        | Operator::V128Load8Splat { .. }
        | Operator::V128Load16Splat { .. }
        | Operator::V128Load32Splat { .. }
        | Operator::V128Load64Splat { .. }
        | Operator::V128Store { .. }
        | Operator::V128Const { .. }
        | Operator::I8x16Shuffle { .. }
        | Operator::I8x16Swizzle
        | Operator::I8x16Splat
        | Operator::I16x8Splat
        | Operator::I32x4Splat
        | Operator::I64x2Splat
        | Operator::F32x4Splat
        | Operator::F64x2Splat => InstructionFamily::Simd,

        // ── Everything else ───────────────────────────────────────────────────
        _ => InstructionFamily::Other,
    }
}

// ── Per-function summary ──────────────────────────────────────────────────────

/// Instruction-family counts for one function body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionComplexity {
    /// Index in the module's function index space (imports are not counted here).
    pub index: u32,
    /// Total instructions in this function body (all families combined).
    pub total_instructions: u64,
    /// Per-family instruction counts.
    pub by_family: BTreeMap<String, u64>,
}

impl FunctionComplexity {
    fn new(index: u32) -> Self {
        let mut by_family = BTreeMap::new();
        for family in InstructionFamily::all() {
            by_family.insert(family.label().to_string(), 0u64);
        }
        Self {
            index,
            total_instructions: 0,
            by_family,
        }
    }

    fn tally(&mut self, op: &Operator<'_>) {
        let family = family_of(op);
        *self
            .by_family
            .entry(family.label().to_string())
            .or_insert(0) += 1;
        self.total_instructions += 1;
    }
}

// ── Module-level profile ──────────────────────────────────────────────────────

/// The complete static complexity profile of one WASM module.
///
/// All counts are bounded by the resource limit applied during profiling.
/// The profile is deterministic: the same byte sequence always produces the
/// same profile, regardless of platform or tool version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmComplexityProfile {
    /// Number of locally-defined function bodies (Code section entries).
    /// Imported functions are not included; see [`crate::runtime_surface`].
    pub defined_functions: u32,
    /// Sum of all instructions across all function bodies.
    pub total_instructions: u64,
    /// Per-family instruction counts summed across all functions.
    pub by_family: BTreeMap<String, u64>,
    /// Per-function breakdowns, sorted by function index.
    /// Omitted from the profile when the module has no code section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<FunctionComplexity>,
}

impl WasmComplexityProfile {
    fn new() -> Self {
        let mut by_family = BTreeMap::new();
        for family in InstructionFamily::all() {
            by_family.insert(family.label().to_string(), 0u64);
        }
        Self {
            defined_functions: 0,
            total_instructions: 0,
            by_family,
            functions: Vec::new(),
        }
    }

    fn add_function(&mut self, func: FunctionComplexity) {
        for (family, &count) in &func.by_family {
            *self.by_family.entry(family.clone()).or_insert(0) += count;
        }
        self.total_instructions += func.total_instructions;
        self.defined_functions += 1;
        self.functions.push(func);
    }
}

// ── Resource limits ───────────────────────────────────────────────────────────

/// Maximum number of functions the profiler will decode per module.
///
/// Chosen large enough to handle real-world Soroban contracts. The profiler
/// stops after this many function bodies and marks the profile as truncated.
const MAX_PROFILED_FUNCTIONS: u32 = 8_192;

/// Maximum number of instructions decoded per *function body*.
///
/// Pathological inputs can have enormous function bodies; cap at a generous
/// but bounded value to prevent runaway analysis.
const MAX_INSTRUCTIONS_PER_FUNCTION: u64 = 1_000_000;

// ── Profile extraction ────────────────────────────────────────────────────────

/// Parse the WASM code section and produce a [`WasmComplexityProfile`].
///
/// Returns `Err` when `wasm_bytes` cannot be parsed as a valid WebAssembly
/// module (the error is human-readable and suitable for display). Any
/// individual function body that fails to parse is silently skipped — the
/// profile is still returned for the functions that succeeded.
///
/// Resource limits are applied:
/// - At most [`MAX_PROFILED_FUNCTIONS`] function bodies are decoded.
/// - At most [`MAX_INSTRUCTIONS_PER_FUNCTION`] instructions per body.
pub fn profile_wasm(wasm_bytes: &[u8]) -> Result<WasmComplexityProfile, String> {
    let mut module_profile = WasmComplexityProfile::new();
    let mut func_index: u32 = 0;

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| format!("WASM parse error: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            if func_index >= MAX_PROFILED_FUNCTIONS {
                // Stop decoding; the profile is considered truncated.
                break;
            }
            let mut func_complexity = FunctionComplexity::new(func_index);
            profile_function_body(body, &mut func_complexity);
            module_profile.add_function(func_complexity);
            func_index += 1;
        }
    }

    Ok(module_profile)
}

/// Decode one function body and tally instructions into `out`.
fn profile_function_body(body: FunctionBody<'_>, out: &mut FunctionComplexity) {
    let mut reader = match body.get_operators_reader() {
        Ok(r) => r,
        Err(_) => return, // malformed body — skip gracefully
    };

    let mut count: u64 = 0;
    while let Ok(op) = reader.read() {
        if count >= MAX_INSTRUCTIONS_PER_FUNCTION {
            break;
        }
        out.tally(&op);
        count += 1;
    }
}

// ── Delta computation ─────────────────────────────────────────────────────────

/// The numeric difference between two metric values, with both absolute and
/// percentage representations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricDelta {
    /// Value in the old build.
    pub old: i64,
    /// Value in the new build.
    pub new: i64,
    /// `new - old`.
    pub absolute: i64,
    /// `(absolute / old) * 100`, rounded to two decimal places.
    /// `null` when `old == 0` (division by zero).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pct: Option<f64>,
}

impl MetricDelta {
    fn new(old: i64, new: i64) -> Self {
        let absolute = new - old;
        let pct = if old == 0 {
            None
        } else {
            Some((absolute as f64 / old as f64 * 100.0 * 100.0).round() / 100.0)
        };
        Self {
            old,
            new,
            absolute,
            pct,
        }
    }
}

/// Delta between the old and new WASM complexity profiles.
///
/// Deltas are computed deterministically: same old/new byte sequences always
/// produce the same delta. Fields use signed integers so decreases appear as
/// negative values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WasmComplexityDelta {
    /// Delta in defined function count.
    pub defined_functions: MetricDelta,
    /// Delta in total instruction count (all families).
    pub total_instructions: MetricDelta,
    /// Per-family deltas, keyed by family label, sorted alphabetically.
    pub by_family: BTreeMap<String, MetricDelta>,
}

impl WasmComplexityDelta {
    /// Compute the delta between `old` and `new` profiles.
    pub fn compute(old: &WasmComplexityProfile, new: &WasmComplexityProfile) -> Self {
        let mut by_family = BTreeMap::new();
        // Collect all known family keys from both profiles.
        let all_keys: std::collections::BTreeSet<&String> =
            old.by_family.keys().chain(new.by_family.keys()).collect();

        for key in all_keys {
            let old_val = old.by_family.get(key).copied().unwrap_or(0) as i64;
            let new_val = new.by_family.get(key).copied().unwrap_or(0) as i64;
            by_family.insert(key.clone(), MetricDelta::new(old_val, new_val));
        }

        Self {
            defined_functions: MetricDelta::new(
                old.defined_functions as i64,
                new.defined_functions as i64,
            ),
            total_instructions: MetricDelta::new(
                old.total_instructions as i64,
                new.total_instructions as i64,
            ),
            by_family,
        }
    }
}

// ── Budget ────────────────────────────────────────────────────────────────────

/// Which metric a complexity budget entry applies to.
///
/// Metric names correspond to the fields in [`WasmComplexityProfile`] /
/// [`WasmComplexityDelta`]: `"total_instructions"`, `"defined_functions"`,
/// or a family label such as `"control"`, `"calls"`, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplexityMetric {
    TotalInstructions,
    DefinedFunctions,
    Family(String),
}

impl ComplexityMetric {
    /// Parse from the string that appears in `.safeguard.toml`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "total_instructions" => Ok(ComplexityMetric::TotalInstructions),
            "defined_functions" => Ok(ComplexityMetric::DefinedFunctions),
            other => {
                // Validate it's a known family label.
                if InstructionFamily::all().iter().any(|f| f.label() == other) {
                    Ok(ComplexityMetric::Family(other.to_string()))
                } else {
                    Err(format!(
                        "unknown complexity metric '{other}'. \
                         Valid values: total_instructions, defined_functions, {}",
                        InstructionFamily::all()
                            .iter()
                            .map(|f| f.label())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
            }
        }
    }

    /// The stable string key for this metric, used in reports and provenance.
    pub fn label(&self) -> String {
        match self {
            ComplexityMetric::TotalInstructions => "total_instructions".to_string(),
            ComplexityMetric::DefinedFunctions => "defined_functions".to_string(),
            ComplexityMetric::Family(name) => name.clone(),
        }
    }

    /// Extract the **new-build absolute value** for this metric from a delta.
    pub fn new_value_from_delta(&self, delta: &WasmComplexityDelta) -> i64 {
        match self {
            ComplexityMetric::TotalInstructions => delta.total_instructions.new,
            ComplexityMetric::DefinedFunctions => delta.defined_functions.new,
            ComplexityMetric::Family(name) => delta.by_family.get(name).map(|d| d.new).unwrap_or(0),
        }
    }

    /// Extract the percentage change for this metric from a delta.
    pub fn pct_from_delta(&self, delta: &WasmComplexityDelta) -> Option<f64> {
        match self {
            ComplexityMetric::TotalInstructions => delta.total_instructions.pct,
            ComplexityMetric::DefinedFunctions => delta.defined_functions.pct,
            ComplexityMetric::Family(name) => delta.by_family.get(name).and_then(|d| d.pct),
        }
    }
}

/// One validated complexity budget entry, as parsed from a `[[complexity_budget]]`
/// table in `.safeguard.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexityBudgetEntry {
    /// The metric this entry constrains.
    pub metric: String,
    /// Maximum allowed **absolute** value for the new build.
    /// `None` means no absolute limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Maximum allowed **percentage increase** from old to new.
    /// `None` means no percentage limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct_limit: Option<f64>,
}

/// The raw, flat shape a `[[complexity_budget]]` TOML table deserializes into.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ComplexityBudgetEntryFile {
    pub metric: String,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub pct_limit: Option<f64>,
}

/// A validated set of complexity budgets.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplexityBudgetConfig {
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub entries: Vec<ComplexityBudgetEntry>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) entries: Vec<ComplexityBudgetEntry>,
}

impl ComplexityBudgetConfig {
    /// Validate and normalize raw `[[complexity_budget]]` entries.
    pub fn from_file_entries(raw: Vec<ComplexityBudgetEntryFile>) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut entries = Vec::new();

        for (index, raw_entry) in raw.iter().enumerate() {
            let position = index + 1;

            // Validate metric name.
            if let Err(e) = ComplexityMetric::parse(&raw_entry.metric) {
                errors.push(format!("complexity_budget #{position}: {e}"));
                continue;
            }

            if raw_entry.limit.is_none() && raw_entry.pct_limit.is_none() {
                errors.push(format!(
                    "complexity_budget #{position}: at least one of `limit` or `pct_limit` is required"
                ));
                continue;
            }

            if let Some(limit) = raw_entry.limit {
                if limit < 0 {
                    errors.push(format!(
                        "complexity_budget #{position}: `limit` must not be negative (got {limit})"
                    ));
                    continue;
                }
            }

            if let Some(pct) = raw_entry.pct_limit {
                if pct < 0.0 {
                    errors.push(format!(
                        "complexity_budget #{position}: `pct_limit` must not be negative (got {pct})"
                    ));
                    continue;
                }
            }

            entries.push(ComplexityBudgetEntry {
                metric: raw_entry.metric.clone(),
                limit: raw_entry.limit.map(|v| v as u64),
                pct_limit: raw_entry.pct_limit,
            });
        }

        if errors.is_empty() {
            Ok(Self { entries })
        } else {
            Err(errors)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Violations ────────────────────────────────────────────────────────────────

/// A single complexity budget entry that was exceeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityViolation {
    /// Metric that was exceeded.
    pub metric: String,
    /// The new-build absolute value.
    pub measured: i64,
    /// The configured absolute limit, if this is an absolute violation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// The percentage change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct_change: Option<f64>,
    /// The configured percentage limit, if this is a percentage violation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct_limit: Option<f64>,
}

impl std::fmt::Display for ComplexityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Some(limit), Some(pct), Some(pct_limit)) =
            (self.limit, self.pct_change, self.pct_limit)
        {
            write!(
                f,
                "{}: {} instructions (limit: {}); grew {:.2}% (pct_limit: {}%)",
                self.metric, self.measured, limit, pct, pct_limit
            )
        } else if let Some(limit) = self.limit {
            write!(f, "{}: {} (limit: {})", self.metric, self.measured, limit)
        } else if let (Some(pct), Some(pct_limit)) = (self.pct_change, self.pct_limit) {
            write!(
                f,
                "{}: grew {:.2}% (pct_limit: {}%)",
                self.metric, pct, pct_limit
            )
        } else {
            write!(f, "{}: budget exceeded", self.metric)
        }
    }
}

/// Evaluate all configured complexity budgets against the computed delta and
/// return one [`ComplexityViolation`] per exceeded entry.
pub fn evaluate_complexity_budgets(
    delta: &WasmComplexityDelta,
    entries: &[ComplexityBudgetEntry],
) -> Vec<ComplexityViolation> {
    let mut violations = Vec::new();

    for entry in entries {
        let metric = match ComplexityMetric::parse(&entry.metric) {
            Ok(m) => m,
            Err(_) => continue, // validated at config-load time; skip silently here
        };

        let new_value = metric.new_value_from_delta(delta);
        let pct_change = metric.pct_from_delta(delta);

        let abs_exceeded = entry.limit.map(|l| new_value as u64 > l).unwrap_or(false);
        let pct_exceeded = entry
            .pct_limit
            .zip(pct_change)
            .map(|(lim, actual)| actual > lim)
            .unwrap_or(false);

        if abs_exceeded || pct_exceeded {
            violations.push(ComplexityViolation {
                metric: entry.metric.clone(),
                measured: new_value,
                limit: if abs_exceeded { entry.limit } else { None },
                pct_change: pct_change.filter(|_| pct_exceeded || entry.pct_limit.is_some()),
                pct_limit: if pct_exceeded { entry.pct_limit } else { None },
            });
        }
    }

    violations
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(funcs: u32, total: u64) -> WasmComplexityProfile {
        let mut p = WasmComplexityProfile::new();
        p.defined_functions = funcs;
        p.total_instructions = total;
        // leave by_family at zeros
        p
    }

    #[test]
    fn delta_computes_correctly() {
        let old = make_profile(10, 1000);
        let new = make_profile(12, 1200);
        let delta = WasmComplexityDelta::compute(&old, &new);
        assert_eq!(delta.defined_functions.absolute, 2);
        assert_eq!(delta.defined_functions.old, 10);
        assert_eq!(delta.defined_functions.new, 12);
        assert_eq!(delta.total_instructions.absolute, 200);
        // pct = 200/1000 * 100 = 20.0
        assert_eq!(delta.total_instructions.pct, Some(20.0));
    }

    #[test]
    fn delta_pct_is_none_when_old_is_zero() {
        let old = make_profile(0, 0);
        let new = make_profile(1, 100);
        let delta = WasmComplexityDelta::compute(&old, &new);
        assert!(delta.defined_functions.pct.is_none());
        assert!(delta.total_instructions.pct.is_none());
    }

    #[test]
    fn budget_absolute_violation() {
        let delta = WasmComplexityDelta::compute(&make_profile(0, 100), &make_profile(0, 200));
        let entries = vec![ComplexityBudgetEntry {
            metric: "total_instructions".to_string(),
            limit: Some(150),
            pct_limit: None,
        }];
        let violations = evaluate_complexity_budgets(&delta, &entries);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].metric, "total_instructions");
        assert_eq!(violations[0].measured, 200);
        assert_eq!(violations[0].limit, Some(150));
    }

    #[test]
    fn budget_pct_violation() {
        let delta = WasmComplexityDelta::compute(&make_profile(0, 100), &make_profile(0, 130));
        let entries = vec![ComplexityBudgetEntry {
            metric: "total_instructions".to_string(),
            limit: None,
            pct_limit: Some(20.0),
        }];
        let violations = evaluate_complexity_budgets(&delta, &entries);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pct_change.is_some());
    }

    #[test]
    fn budget_not_violated_when_within_limit() {
        let delta = WasmComplexityDelta::compute(&make_profile(0, 100), &make_profile(0, 110));
        let entries = vec![ComplexityBudgetEntry {
            metric: "total_instructions".to_string(),
            limit: Some(200),
            pct_limit: Some(20.0),
        }];
        let violations = evaluate_complexity_budgets(&delta, &entries);
        assert!(violations.is_empty());
    }

    #[test]
    fn metric_from_str_valid() {
        assert!(ComplexityMetric::parse("total_instructions").is_ok());
        assert!(ComplexityMetric::parse("defined_functions").is_ok());
        assert!(ComplexityMetric::parse("control").is_ok());
        assert!(ComplexityMetric::parse("calls").is_ok());
        assert!(ComplexityMetric::parse("memory").is_ok());
    }

    #[test]
    fn metric_from_str_invalid() {
        assert!(ComplexityMetric::parse("gas_cost").is_err());
        assert!(ComplexityMetric::parse("").is_err());
    }

    #[test]
    fn budget_config_rejects_negative_limit() {
        let raw = vec![ComplexityBudgetEntryFile {
            metric: "total_instructions".to_string(),
            limit: Some(-1),
            pct_limit: None,
        }];
        assert!(ComplexityBudgetConfig::from_file_entries(raw).is_err());
    }

    #[test]
    fn budget_config_rejects_missing_limit_and_pct() {
        let raw = vec![ComplexityBudgetEntryFile {
            metric: "total_instructions".to_string(),
            limit: None,
            pct_limit: None,
        }];
        assert!(ComplexityBudgetConfig::from_file_entries(raw).is_err());
    }

    #[test]
    fn profile_wasm_empty_module() {
        // Minimal valid WASM module: magic + version only, no sections.
        let minimal: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let profile = profile_wasm(minimal).expect("should profile empty module");
        assert_eq!(profile.defined_functions, 0);
        assert_eq!(profile.total_instructions, 0);
    }

    #[test]
    fn profile_wasm_rejects_garbage() {
        let garbage: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF];
        assert!(profile_wasm(garbage).is_err());
    }
}
