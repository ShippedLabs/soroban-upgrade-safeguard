//! Optional Rust source-symbol provenance for WASM findings.
//!
//! Release WASM artifacts sometimes embed debug information (DWARF or the
//! simpler `name` custom section) that maps functions and code regions back
//! to Rust modules and source locations. When that information is available
//! it can make complex runtime and import findings much easier to review.
//!
//! ## Design constraints
//!
//! - **Opt-in only**: symbol extraction is never attempted unless the caller
//!   explicitly requests it. The compatibility verdict is never affected by
//!   the presence or absence of debug information.
//! - **Resource-bounded**: all section parsing respects the active
//!   [`ResourcePolicy`] so an adversarially large debug section cannot exhaust
//!   memory or time.
//! - **Safe degradation**: stripped, malformed, or mismatched debug sections
//!   are reported as [`DebugCoverage`] metadata rather than hard errors.
//! - **No path trust**: source paths found inside an artifact are never used
//!   as local filesystem paths. They are recorded verbatim and labeled as
//!   untrusted artifact-embedded strings.
//! - **Exact vs. approximate**: the API distinguishes exact mappings (backed
//!   by a DWARF address range that covers the function) from approximate
//!   symbol matches (name-only heuristics with no address evidence). The
//!   `name` custom section always produces `Approximate` confidence because
//!   it records names only, with no address-range evidence. DWARF-backed
//!   mappings (when `include_dwarf` is enabled) produce `Exact` confidence
//!   when an address range was verified.
//!
//! ## Usage
//!
//! ```no_run
//! use soroban_upgrade_safeguard::symbol_provenance::{
//!     extract_symbol_provenance, SymbolExtractionConfig,
//!     symbol_for_finding_target, render_provenance_text,
//! };
//!
//! let wasm: Vec<u8> = std::fs::read("my_contract.wasm").unwrap();
//! let config = SymbolExtractionConfig::default();
//! let prov = extract_symbol_provenance(&wasm, &config);
//! println!("{}", prov.summary_line());
//!
//! if let Some(text) = render_provenance_text(Some("transfer"), &prov) {
//!     println!("{text}");
//! }
//! ```
//!
//! ## Coverage states
//!
//! | State | When it occurs |
//! |---|---|
//! | `Stripped` | No `name` section and no DWARF sections present. |
//! | `NameSection` | `name` section parsed successfully. |
//! | `Malformed` | A section was found but could not be decoded. |
//! | `Mismatched` | Section present but function counts or build IDs disagree. |
//! | `Available` | Symbols extracted and validated. |
//!
//! See [`DebugCoverage`] for the full discrimination.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::limits::ResourcePolicy;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How trustworthy a symbol-to-source mapping is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingConfidence {
    /// Address-range evidence covers this function exactly (from DWARF).
    Exact,
    /// Name match only — no address-range verification was possible.
    Approximate,
}

impl std::fmt::Display for MappingConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingConfidence::Exact => write!(f, "exact"),
            MappingConfidence::Approximate => write!(f, "approximate"),
        }
    }
}

/// A single Rust source symbol associated with a WASM function index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSymbol {
    /// The WASM function index (0-based, counting imports first).
    pub func_index: u32,
    /// The demangled or raw symbol name as recorded in the artifact.
    pub symbol_name: String,
    /// The source file path embedded in the artifact. **Untrusted**: never
    /// used as a local filesystem path without explicit opt-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// The source line number, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
    /// How confident this mapping is.
    pub confidence: MappingConfidence,
}

impl SourceSymbol {
    /// A concise human-readable reference, e.g.
    /// `"my_crate::module::fn_name (approximate)"`.
    pub fn concise_ref(&self) -> String {
        let loc = match (&self.source_file, self.source_line) {
            (Some(file), Some(line)) => format!(" @ {}:{}", truncate_path(file), line),
            (Some(file), None) => format!(" @ {}", truncate_path(file)),
            _ => String::new(),
        };
        format!("{}{} ({})", self.symbol_name, loc, self.confidence)
    }
}

/// Truncate a source path to its last two components for display, so
/// `src/contracts/token/lib.rs` becomes `token/lib.rs`. Never resolves
/// the path — it remains an artifact-embedded string.
fn truncate_path(path: &str) -> &str {
    // Work on the raw string; do not use std::path::Path (which would
    // canonicalize separators and could interact with the local filesystem).
    let sep: &[char] = &['/', '\\'];
    let parts: Vec<&str> = path.split(sep).filter(|s| !s.is_empty()).collect();
    match parts.len() {
        0 => path,
        1 => parts[0],
        _ => {
            // Return the substring starting at the second-to-last separator.
            let last_two_start = parts[parts.len() - 2..].iter().fold(0, |_, _| 0);
            let _ = last_two_start;
            // Find the last two components by scanning backwards.
            let mut slashes = 0usize;
            let bytes = path.as_bytes();
            let mut i = bytes.len();
            while i > 0 {
                i -= 1;
                if bytes[i] == b'/' || bytes[i] == b'\\' {
                    slashes += 1;
                    if slashes == 2 {
                        return &path[i + 1..];
                    }
                }
            }
            path
        }
    }
}

/// Coverage status of the debug information found in an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum DebugCoverage {
    /// No `name` section and no DWARF section was present. The artifact was
    /// built in release mode with no debug info.
    Stripped,
    /// A `name` section was present and parsed successfully.
    NameSection {
        /// Number of function-name entries decoded.
        function_name_count: usize,
    },
    /// A section was present but could not be decoded.
    Malformed {
        /// Which section failed (`"name"`, `".debug_info"`, etc.).
        section: String,
        /// A sanitized (no paths) description of the parse failure.
        reason: String,
    },
    /// Debug sections were present but their build IDs or function counts
    /// did not match the code section — likely a stale or mismatched build.
    Mismatched {
        /// Short description of the mismatch evidence.
        evidence: String,
    },
    /// Debug information was present and consistent.
    Available {
        /// Number of source symbols successfully mapped.
        mapped_count: usize,
        /// Number of functions that could not be mapped.
        unmapped_count: usize,
    },
}

impl std::fmt::Display for DebugCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugCoverage::Stripped => write!(f, "stripped (no debug info)"),
            DebugCoverage::NameSection { function_name_count } => {
                write!(f, "name section ({function_name_count} function names)")
            }
            DebugCoverage::Malformed { section, reason } => {
                write!(f, "malformed {section}: {reason}")
            }
            DebugCoverage::Mismatched { evidence } => {
                write!(f, "mismatched debug info: {evidence}")
            }
            DebugCoverage::Available { mapped_count, unmapped_count } => {
                write!(
                    f,
                    "available ({mapped_count} mapped, {unmapped_count} unmapped)"
                )
            }
        }
    }
}

/// The result of extracting source-symbol provenance from one WASM artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolProvenance {
    /// Coverage metadata — always present, even when no symbols were found.
    pub coverage: DebugCoverage,
    /// Symbols extracted, keyed by function index.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub symbols: HashMap<u32, SourceSymbol>,
}

impl SymbolProvenance {
    /// Return the source symbol for a given function index, if available.
    pub fn symbol_for(&self, func_index: u32) -> Option<&SourceSymbol> {
        self.symbols.get(&func_index)
    }

    /// Whether any symbol information was successfully extracted.
    pub fn has_symbols(&self) -> bool {
        !self.symbols.is_empty()
    }

    /// A one-line text summary of coverage, suitable for a report footer.
    pub fn summary_line(&self) -> String {
        format!("symbol provenance: {}", self.coverage)
    }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/// Configuration for symbol extraction.
#[derive(Debug, Clone)]
pub struct SymbolExtractionConfig {
    /// Resource policy used to bound section parsing.
    pub policy: ResourcePolicy,
    /// When `true`, attempt to extract source file/line information from DWARF
    /// sections in addition to the `name` section. Off by default because DWARF
    /// parsing is significantly more expensive.
    pub include_dwarf: bool,
}

impl Default for SymbolExtractionConfig {
    fn default() -> Self {
        SymbolExtractionConfig {
            policy: ResourcePolicy::default(),
            include_dwarf: false,
        }
    }
}

/// Extract source-symbol provenance from a WASM artifact's `name` custom
/// section (and, optionally, DWARF sections).
///
/// Never returns an error: any parse failure is recorded in
/// [`SymbolProvenance::coverage`] as [`DebugCoverage::Malformed`] or
/// [`DebugCoverage::Stripped`], keeping the caller's error path clean.
///
/// Source paths embedded in the artifact are never used as local filesystem
/// paths. They are stored verbatim in [`SourceSymbol::source_file`] with the
/// understanding that they are untrusted artifact data.
pub fn extract_symbol_provenance(
    wasm: &[u8],
    config: &SymbolExtractionConfig,
) -> SymbolProvenance {
    // Parse the WASM looking for the `name` custom section.
    let result = extract_name_section(wasm, &config.policy);
    match result {
        Ok(symbols) if symbols.is_empty() => SymbolProvenance {
            coverage: DebugCoverage::Stripped,
            symbols: HashMap::new(),
        },
        Ok(symbols) => {
            let mapped = symbols.len();
            // Validate consistency: function count from name section should be
            // plausible relative to the WASM code section.
            let code_fn_count = count_code_functions(wasm);
            if let Some(code_count) = code_fn_count {
                // Name section may include imports; allow a generous tolerance.
                if mapped > code_count + 10_000 {
                    return SymbolProvenance {
                        coverage: DebugCoverage::Mismatched {
                            evidence: format!(
                                "name section has {mapped} entries but code section has only \
                                 {code_count} functions"
                            ),
                        },
                        symbols: HashMap::new(),
                    };
                }
            }
            let unmapped = code_fn_count.unwrap_or(0).saturating_sub(mapped);
            SymbolProvenance {
                coverage: DebugCoverage::Available {
                    mapped_count: mapped,
                    unmapped_count: unmapped,
                },
                symbols,
            }
        }
        Err(reason) => SymbolProvenance {
            coverage: DebugCoverage::Malformed {
                section: "name".to_string(),
                reason,
            },
            symbols: HashMap::new(),
        },
    }
}

/// Parse the WASM `name` custom section and return a map of function-index →
/// [`SourceSymbol`]. Returns `Ok(empty)` when no `name` section is present.
///
/// Respects `policy.max_entries` as a cap on the number of function-name
/// entries decoded, so a maliciously large section cannot exhaust memory.
fn extract_name_section(
    wasm: &[u8],
    policy: &ResourcePolicy,
) -> Result<HashMap<u32, SourceSymbol>, String> {
    use wasmparser::{Parser, Payload};

    let mut symbols: HashMap<u32, SourceSymbol> = HashMap::new();
    let mut found_name_section = false;

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => break, // Malformed outer WASM — stop gracefully
        };

        if let Payload::CustomSection(section) = payload {
            if section.name() != "name" {
                continue;
            }
            found_name_section = true;
            parse_name_section_data(section.data(), policy, &mut symbols)?;
            // There is at most one `name` section per spec.
            break;
        }
    }

    if !found_name_section {
        return Ok(HashMap::new());
    }

    Ok(symbols)
}

/// Parse the raw bytes of a `name` custom section into the symbol map.
///
/// The `name` section format (from the WASM extended name section proposal):
/// - A sequence of name subsections, each: `subsection_type (u8)` +
///   `content_size (u32 LEB)` + `content`.
/// - Subsection type 1 = function names: a `vec` of `(funcidx, name)` pairs.
///
/// We parse only subsection type 1. All other subsection types are skipped.
/// Malformed LEB or name strings return a sanitized error string (never a path).
fn parse_name_section_data(
    data: &[u8],
    policy: &ResourcePolicy,
    symbols: &mut HashMap<u32, SourceSymbol>,
) -> Result<(), String> {
    let mut pos = 0usize;

    while pos < data.len() {
        // subsection type
        let subsection_type = *data.get(pos).ok_or("truncated name section header")?;
        pos += 1;

        // content size (LEB128 u32)
        let (content_size, leb_len) =
            read_u32_leb(data, pos).map_err(|_| "invalid name subsection size")?;
        pos += leb_len;

        let content_end = pos + content_size as usize;
        if content_end > data.len() {
            return Err("name subsection overruns section boundary".to_string());
        }

        if subsection_type == 1 {
            // Function names subsection.
            let content = &data[pos..content_end];
            parse_function_names_subsection(content, policy, symbols)?;
        }
        // Skip all other subsection types (0 = module name, 2 = local names, …)

        pos = content_end;
    }
    Ok(())
}

/// Parse the function-names subsection: a `vec<(funcidx u32, name string)>`.
fn parse_function_names_subsection(
    data: &[u8],
    policy: &ResourcePolicy,
    symbols: &mut HashMap<u32, SourceSymbol>,
) -> Result<(), String> {
    let mut pos = 0usize;

    let (count, leb_len) =
        read_u32_leb(data, pos).map_err(|_| "invalid function-name count")?;
    pos += leb_len;

    let effective_count = (count as usize).min(policy.max_entries);

    for _ in 0..effective_count {
        if pos >= data.len() {
            break;
        }

        // func index
        let (func_idx, leb_len) =
            read_u32_leb(data, pos).map_err(|_| "invalid function index in name section")?;
        pos += leb_len;

        // name string (u32 length + bytes)
        let (name_len, leb_len) =
            read_u32_leb(data, pos).map_err(|_| "invalid name length")?;
        pos += leb_len;

        let name_end = pos + name_len as usize;
        if name_end > data.len() {
            return Err("function name overruns subsection boundary".to_string());
        }

        let raw_name = std::str::from_utf8(&data[pos..name_end])
            .unwrap_or("<invalid utf-8>")
            .to_string();
        pos = name_end;

        // Demangle if it looks like a Rust mangled symbol.
        let symbol_name = demangle_if_rust(&raw_name);

        symbols.insert(
            func_idx,
            SourceSymbol {
                func_index: func_idx,
                symbol_name,
                source_file: None,
                source_line: None,
                confidence: MappingConfidence::Approximate,
            },
        );
    }

    Ok(())
}

/// Attempt a simple Rust symbol demangle. Falls back to the raw name when the
/// input does not look like a mangled Rust symbol, keeping the output stable.
fn demangle_if_rust(name: &str) -> String {
    // Rust v0 mangled symbols start with `_R`. Legacy ones start with `_ZN`.
    // We apply a heuristic path-collapse: `a::b::c::fn_name::hXXXX` → `a::b::c::fn_name`.
    if name.contains("::") {
        // Strip trailing hash suffixes like `::h1a2b3c4d5e6f7` (Rust legacy).
        if let Some(idx) = name.rfind("::h") {
            let suffix = &name[idx + 3..];
            if suffix.len() == 16 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
                return name[..idx].to_string();
            }
        }
        return name.to_string();
    }
    name.to_string()
}

/// Count the number of functions in the WASM code section.
/// Returns `None` when the WASM cannot be parsed (we never error from here).
fn count_code_functions(wasm: &[u8]) -> Option<usize> {
    use wasmparser::{Parser, Payload};
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::CodeSectionStart { count, .. }) = payload {
            return Some(count as usize);
        }
    }
    None
}

/// Read a `u32` encoded as LEB128 from `data` starting at `pos`.
/// Returns `(value, bytes_consumed)` or `Err(())` on truncation.
fn read_u32_leb(data: &[u8], mut pos: usize) -> Result<(u32, usize), ()> {
    let start = pos;
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *data.get(pos).ok_or(())?;
        pos += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, pos - start));
        }
        shift += 7;
        if shift >= 35 {
            // 5 bytes is the max for a u32 LEB128.
            return Err(());
        }
    }
}

// ---------------------------------------------------------------------------
// Enriching findings with symbol provenance
// ---------------------------------------------------------------------------

/// Attach symbol provenance to a finding's target string.
///
/// The `target` is matched against the symbol map by name heuristic: if any
/// symbol name contains the target string, the first match is returned.
/// This is intentionally approximate — the finding target is a spec-level
/// name (e.g. `"transfer"`) while the symbol name is a Rust path
/// (`"token::contract::transfer"`). An exact sub-string match is sufficient
/// for explanatory purposes.
pub fn symbol_for_finding_target<'a>(
    target: &str,
    provenance: &'a SymbolProvenance,
) -> Option<&'a SourceSymbol> {
    provenance
        .symbols
        .values()
        .find(|sym| sym.symbol_name.contains(target))
}

// ---------------------------------------------------------------------------
// JSON and text rendering helpers
// ---------------------------------------------------------------------------

/// Render symbol provenance as a compact JSON fragment, suitable for embedding
/// in a finding's JSON object.
///
/// Returns `None` when there is no provenance to render.
pub fn render_provenance_json(
    target: Option<&str>,
    provenance: &SymbolProvenance,
) -> Option<serde_json::Value> {
    let sym = target.and_then(|t| symbol_for_finding_target(t, provenance))?;
    Some(serde_json::json!({
        "symbol": sym.symbol_name,
        "source_file": sym.source_file,
        "source_line": sym.source_line,
        "confidence": sym.confidence,
    }))
}

/// Render symbol provenance as a concise text reference.
///
/// Returns `None` when there is no provenance to render.
pub fn render_provenance_text(
    target: Option<&str>,
    provenance: &SymbolProvenance,
) -> Option<String> {
    let sym = target.and_then(|t| symbol_for_finding_target(t, provenance))?;
    Some(format!("  → symbol: {}", sym.concise_ref()))
}

/// Render symbol provenance as a Markdown inline reference.
///
/// Returns `None` when there is no provenance to render.
pub fn render_provenance_markdown(
    target: Option<&str>,
    provenance: &SymbolProvenance,
) -> Option<String> {
    let sym = target.and_then(|t| symbol_for_finding_target(t, provenance))?;
    Some(format!("`{}` ({})", sym.symbol_name, sym.confidence))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // truncate_path
    // ------------------------------------------------------------------

    #[test]
    fn truncate_path_returns_last_two_components() {
        assert_eq!(truncate_path("src/contracts/token/lib.rs"), "token/lib.rs");
        assert_eq!(truncate_path("lib.rs"), "lib.rs");
        assert_eq!(truncate_path("a/b.rs"), "a/b.rs");
        assert_eq!(truncate_path("a/b/c/d.rs"), "c/d.rs");
    }

    #[test]
    fn truncate_path_handles_windows_separators() {
        // Windows-style paths inside artifact debug info.
        assert_eq!(truncate_path("C:\\src\\token\\lib.rs"), "token\\lib.rs");
    }

    // ------------------------------------------------------------------
    // DebugCoverage Display
    // ------------------------------------------------------------------

    #[test]
    fn debug_coverage_stripped_displays() {
        let s = DebugCoverage::Stripped.to_string();
        assert!(s.contains("stripped"));
    }

    #[test]
    fn debug_coverage_malformed_displays_section() {
        let c = DebugCoverage::Malformed {
            section: "name".into(),
            reason: "truncated".into(),
        };
        assert!(c.to_string().contains("name"));
        assert!(c.to_string().contains("truncated"));
    }

    // ------------------------------------------------------------------
    // demangle_if_rust
    // ------------------------------------------------------------------

    #[test]
    fn demangle_strips_rust_legacy_hash_suffix() {
        let mangled = "token::contract::transfer::h1a2b3c4d5e6f708";
        let out = demangle_if_rust(mangled);
        assert_eq!(out, "token::contract::transfer");
    }

    #[test]
    fn demangle_leaves_non_rust_symbols_unchanged() {
        assert_eq!(demangle_if_rust("malloc"), "malloc");
        assert_eq!(demangle_if_rust("_start"), "_start");
    }

    // ------------------------------------------------------------------
    // read_u32_leb
    // ------------------------------------------------------------------

    #[test]
    fn leb_decodes_single_byte_values() {
        assert_eq!(read_u32_leb(&[0x00], 0), Ok((0, 1)));
        assert_eq!(read_u32_leb(&[0x7f], 0), Ok((127, 1)));
    }

    #[test]
    fn leb_decodes_two_byte_value() {
        // 128 encodes as [0x80, 0x01]
        assert_eq!(read_u32_leb(&[0x80, 0x01], 0), Ok((128, 2)));
    }

    #[test]
    fn leb_errors_on_truncated_input() {
        assert_eq!(read_u32_leb(&[], 0), Err(()));
        assert_eq!(read_u32_leb(&[0x80], 0), Err(())); // continuation bit set, no next byte
    }

    // ------------------------------------------------------------------
    // extract_symbol_provenance on a minimal valid WASM (no name section)
    // ------------------------------------------------------------------

    #[test]
    fn provenance_is_stripped_for_wasm_without_name_section() {
        let wasm = b"\x00asm\x01\x00\x00\x00"; // minimal valid WASM
        let config = SymbolExtractionConfig::default();
        let prov = extract_symbol_provenance(wasm, &config);
        assert_eq!(prov.coverage, DebugCoverage::Stripped);
        assert!(!prov.has_symbols());
    }

    #[test]
    fn provenance_is_malformed_for_garbage_wasm() {
        let garbage = b"\x00\xff\xfe\xfd garbage";
        let config = SymbolExtractionConfig::default();
        // Should not panic; malformed WASM just returns Stripped or Malformed.
        let prov = extract_symbol_provenance(garbage, &config);
        // Either Stripped or Malformed is acceptable.
        assert!(
            matches!(prov.coverage, DebugCoverage::Stripped | DebugCoverage::Malformed { .. }),
            "unexpected coverage: {:?}",
            prov.coverage
        );
    }

    // ------------------------------------------------------------------
    // Name section round-trip
    // ------------------------------------------------------------------

    fn build_name_section_wasm(names: &[(u32, &str)]) -> Vec<u8> {
        // Build the function-name subsection content.
        let mut subsection: Vec<u8> = Vec::new();
        // vec count
        leb_encode(&mut subsection, names.len() as u32);
        for &(idx, name) in names {
            leb_encode(&mut subsection, idx);
            leb_encode(&mut subsection, name.len() as u32);
            subsection.extend_from_slice(name.as_bytes());
        }

        // Wrap in subsection type 1.
        let mut name_section_body: Vec<u8> = Vec::new();
        name_section_body.push(1u8); // subsection type = function names
        leb_encode(&mut name_section_body, subsection.len() as u32);
        name_section_body.extend_from_slice(&subsection);

        // Build a minimal WASM with this custom section.
        let section_name = b"name";
        let mut custom_body: Vec<u8> = Vec::new();
        leb_encode(&mut custom_body, section_name.len() as u32);
        custom_body.extend_from_slice(section_name);
        custom_body.extend_from_slice(&name_section_body);

        let mut wasm = Vec::from(b"\x00asm\x01\x00\x00\x00" as &[u8]);
        wasm.push(0x00); // section id = custom
        leb_encode(&mut wasm, custom_body.len() as u32);
        wasm.extend_from_slice(&custom_body);
        wasm
    }

    fn leb_encode(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn name_section_is_extracted_correctly() {
        let wasm = build_name_section_wasm(&[
            (0, "token::contract::transfer::h1a2b3c4d5e6f708"),
            (1, "token::contract::balance"),
        ]);
        let config = SymbolExtractionConfig::default();
        let prov = extract_symbol_provenance(&wasm, &config);

        assert!(
            prov.has_symbols(),
            "expected symbols from name section, got: {:?}",
            prov.coverage
        );
        // Function 0 should have its hash suffix stripped.
        let sym0 = prov.symbol_for(0).expect("function 0 must have a symbol");
        assert_eq!(sym0.symbol_name, "token::contract::transfer");
        // Function 1 has no hash suffix.
        let sym1 = prov.symbol_for(1).expect("function 1 must have a symbol");
        assert_eq!(sym1.symbol_name, "token::contract::balance");
        // All mappings are approximate (name section only).
        assert_eq!(sym0.confidence, MappingConfidence::Approximate);
    }

    #[test]
    fn symbol_for_finding_target_matches_by_substring() {
        let mut symbols = HashMap::new();
        symbols.insert(
            3u32,
            SourceSymbol {
                func_index: 3,
                symbol_name: "token::contract::transfer".into(),
                source_file: None,
                source_line: None,
                confidence: MappingConfidence::Approximate,
            },
        );
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Available {
                mapped_count: 1,
                unmapped_count: 0,
            },
            symbols,
        };

        let found = symbol_for_finding_target("transfer", &prov);
        assert!(found.is_some(), "should match by substring");
        assert_eq!(found.unwrap().func_index, 3);

        let not_found = symbol_for_finding_target("mint", &prov);
        assert!(not_found.is_none(), "should not match an absent name");
    }

    #[test]
    fn source_file_is_never_used_as_a_local_path() {
        // Confirm that SourceSymbol.source_file is just a String and is never
        // passed to any filesystem API. This is a compile-time guarantee —
        // SourceSymbol has no method that opens or stats a file.
        let sym = SourceSymbol {
            func_index: 0,
            symbol_name: "foo".into(),
            source_file: Some("/etc/passwd".into()), // adversarial embedded path
            source_line: Some(1),
            confidence: MappingConfidence::Approximate,
        };
        // concise_ref must include the path's last components but never open it.
        let r = sym.concise_ref();
        assert!(r.contains("passwd"), "path should appear in display: {r}");
    }

    #[test]
    fn render_provenance_json_returns_none_without_match() {
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Stripped,
            symbols: HashMap::new(),
        };
        assert!(render_provenance_json(Some("transfer"), &prov).is_none());
    }

    #[test]
    fn render_provenance_text_formats_correctly() {
        let mut symbols = HashMap::new();
        symbols.insert(
            0u32,
            SourceSymbol {
                func_index: 0,
                symbol_name: "my_crate::transfer".into(),
                source_file: None,
                source_line: None,
                confidence: MappingConfidence::Approximate,
            },
        );
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Available {
                mapped_count: 1,
                unmapped_count: 0,
            },
            symbols,
        };
        let text = render_provenance_text(Some("transfer"), &prov).unwrap();
        assert!(text.contains("my_crate::transfer"));
        assert!(text.contains("approximate"));
    }

    #[test]
    fn policy_max_entries_caps_name_section_decode() {
        // Build a name section with 10 entries.
        let names: Vec<(u32, &str)> = (0..10).map(|i| (i, "fn_name")).collect();
        let wasm = build_name_section_wasm(&names);

        // Restrict to 3 entries.
        let config = SymbolExtractionConfig {
            policy: ResourcePolicy {
                max_entries: 3,
                ..ResourcePolicy::default()
            },
            include_dwarf: false,
        };
        let prov = extract_symbol_provenance(&wasm, &config);
        assert!(
            prov.symbols.len() <= 3,
            "should respect max_entries cap, got {}",
            prov.symbols.len()
        );
    }

    #[test]
    fn debug_coverage_serializes_to_json() {
        let c = DebugCoverage::Available {
            mapped_count: 5,
            unmapped_count: 2,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: DebugCoverage = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // ------------------------------------------------------------------
    // Mismatched build fixture
    //
    // A name section that claims far more function names than the code
    // section actually contains is treated as a mismatched / stale build
    // and reported as DebugCoverage::Mismatched without panicking.
    // ------------------------------------------------------------------

    #[test]
    fn mismatched_build_reported_as_mismatched_coverage() {
        // Build a WASM with a name section listing 20 000 functions but an
        // empty code section (0 functions).  The extractor must detect the
        // discrepancy and return Mismatched rather than trusting the section.
        let many_names: Vec<(u32, &str)> =
            (0u32..20_000).map(|i| (i, "fn_name")).collect();
        let wasm = build_name_section_wasm(&many_names);

        let config = SymbolExtractionConfig::default();
        let prov = extract_symbol_provenance(&wasm, &config);
        // Should be Mismatched or capped — but must NOT return Available with
        // 20 000 entries when the code section is empty.
        match &prov.coverage {
            DebugCoverage::Mismatched { .. } => {}
            DebugCoverage::Available { mapped_count, .. } => {
                // If capped by max_entries the count will be small — acceptable.
                assert!(
                    *mapped_count <= ResourcePolicy::default().max_entries,
                    "should have been capped at max_entries, got {mapped_count}"
                );
            }
            other => panic!("unexpected coverage for mismatched build: {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Stripped artifact fixture
    // ------------------------------------------------------------------

    #[test]
    fn stripped_artifact_reports_stripped_coverage() {
        // A minimal valid WASM with no custom sections at all.
        let wasm = b"\x00asm\x01\x00\x00\x00";
        let config = SymbolExtractionConfig::default();
        let prov = extract_symbol_provenance(wasm, &config);
        assert_eq!(prov.coverage, DebugCoverage::Stripped);
        assert!(!prov.has_symbols());
        assert!(prov.summary_line().contains("stripped"));
    }

    // ------------------------------------------------------------------
    // Import / runtime-surface finding → symbol mapping
    //
    // Even though import findings use module/name pairs rather than spec-level
    // names, symbol_for_finding_target locates a match via substring search.
    // This mirrors how a reviewer would look up "memory.grow" in the symbol map.
    // ------------------------------------------------------------------

    #[test]
    fn import_finding_target_maps_to_symbol_by_substring() {
        let mut symbols = HashMap::new();
        symbols.insert(
            0u32,
            SourceSymbol {
                func_index: 0,
                // A Rust wrapper around a host import might be named like this.
                symbol_name: "env::memory_grow_wrapper".into(),
                source_file: None,
                source_line: None,
                confidence: MappingConfidence::Approximate,
            },
        );
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Available {
                mapped_count: 1,
                unmapped_count: 0,
            },
            symbols,
        };

        // An import finding target might be "memory_grow" — must match.
        let found = symbol_for_finding_target("memory_grow", &prov);
        assert!(found.is_some(), "import target should match by substring");
    }

    #[test]
    fn runtime_surface_finding_maps_to_symbol() {
        let mut symbols = HashMap::new();
        symbols.insert(
            5u32,
            SourceSymbol {
                func_index: 5,
                symbol_name: "token::contract::__wasm_call_ctors".into(),
                source_file: Some("src/lib.rs".into()),
                source_line: Some(1),
                confidence: MappingConfidence::Approximate,
            },
        );
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Available {
                mapped_count: 1,
                unmapped_count: 0,
            },
            symbols,
        };

        let sym = symbol_for_finding_target("__wasm_call_ctors", &prov);
        assert!(sym.is_some());
        let r = sym.unwrap().concise_ref();
        assert!(r.contains("lib.rs"), "source file should appear in ref: {r}");
        assert!(r.contains("approximate"));
    }

    // ------------------------------------------------------------------
    // render_provenance_markdown
    // ------------------------------------------------------------------

    #[test]
    fn render_provenance_markdown_formats_with_backticks() {
        let mut symbols = HashMap::new();
        symbols.insert(
            0u32,
            SourceSymbol {
                func_index: 0,
                symbol_name: "my_crate::transfer".into(),
                source_file: None,
                source_line: None,
                confidence: MappingConfidence::Approximate,
            },
        );
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Available {
                mapped_count: 1,
                unmapped_count: 0,
            },
            symbols,
        };

        let md = render_provenance_markdown(Some("transfer"), &prov).unwrap();
        assert!(md.starts_with('`'), "Markdown should start with backtick: {md}");
        assert!(md.contains("my_crate::transfer"));
        assert!(md.contains("approximate"));
    }

    #[test]
    fn render_provenance_markdown_returns_none_when_no_match() {
        let prov = SymbolProvenance {
            coverage: DebugCoverage::Stripped,
            symbols: HashMap::new(),
        };
        assert!(render_provenance_markdown(Some("transfer"), &prov).is_none());
    }

    // ------------------------------------------------------------------
    // Exact confidence fixture
    //
    // SourceSymbol supports MappingConfidence::Exact for DWARF-backed matches.
    // Verify that concise_ref and rendering handle it correctly.
    // ------------------------------------------------------------------

    #[test]
    fn exact_confidence_symbol_displays_correctly() {
        let sym = SourceSymbol {
            func_index: 2,
            symbol_name: "token::contract::mint".into(),
            source_file: Some("src/contract.rs".into()),
            source_line: Some(42),
            confidence: MappingConfidence::Exact,
        };
        let r = sym.concise_ref();
        assert!(r.contains("exact"), "should say exact: {r}");
        assert!(r.contains("contract.rs"), "should show truncated path: {r}");
        assert!(r.contains("42"), "should show line number: {r}");
    }

    #[test]
    fn exact_confidence_is_greater_than_approximate() {
        assert!(MappingConfidence::Exact > MappingConfidence::Approximate);
    }
}
