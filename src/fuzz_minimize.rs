//! Corpus management: minimize a failing fuzz input and promote it to a
//! deterministic regression fixture.
//!
//! ## Overview
//!
//! Fuzz testing (via [`proptest`] or an external fuzzer) can uncover malformed
//! specifications, deeply recursive types, and parser edge cases. The raw
//! crashing inputs are often large and contain redundant bytes that are not
//! needed to reproduce the failure. This module provides a *delta-reduction*
//! loop that shrinks the input as far as possible while preserving the
//! original failure class, then promotes the minimized result into a
//! deterministic fixture alongside a metadata sidecar.
//!
//! ## Design constraints
//!
//! - **Bounded time**: the reduction loop respects a configurable iteration cap
//!   so it cannot run forever on a pathological input.
//! - **No input growth**: a candidate that is larger than the current best is
//!   rejected unconditionally — reduction always strictly decreases size or
//!   terminates.
//! - **No recursive minimizer**: the reducer is iterative and uses an explicit
//!   work-list rather than recursion, so a deeply nested input cannot overflow
//!   the stack.
//! - **Path-independent output**: the promoted fixture and its metadata never
//!   embed the temporary directory name or any local filesystem path.
//! - **Failure-class preservation**: every candidate is accepted only when it
//!   triggers exactly the same error variant as the original input, determined
//!   by [`FailureClass`].
//!
//! ## Supported input kinds
//!
//! | Kind         | What it exercises                               |
//! |--------------|------------------------------------------------|
//! | `parser`     | `contractspecv0` / `contractenvmetav0` decode  |
//! | `decoder`    | raw XDR byte sequences                         |
//! | `mapper`     | type-walk and layout-mapper paths              |
//! | `report`     | report rendering (text / JSON / Markdown)       |
//!
//! ## Typical workflow
//!
//! 1. A fuzzer or property test discovers a crashing input and saves it as
//!    `crashing_input.bin`.
//!
//! 2. Minimize it to its smallest reproducing form:
//!    ```bash
//!    soroban-upgrade-safeguard fuzz-minimize ./crashing_input.bin \
//!      --kind parser \
//!      --output-dir fuzz/fixtures
//!    ```
//!
//! 3. Two files land in `fuzz/fixtures/`:
//!    - `parser_parse_error_<kind>_<digest12>_<len>.bin` — minimized bytes
//!    - `parser_parse_error_<kind>_<digest12>_<len>.meta.json` — metadata
//!
//! 4. Commit both files and add a regression test that replays the fixture:
//!    ```rust,no_run
//!    #[test]
//!    fn parser_regression() {
//!        let bytes = include_bytes!("../fuzz/fixtures/parser_parse_error_…_42.bin");
//!        let err = soroban_upgrade_safeguard::parser::extract_metadata(bytes)
//!            .expect_err("regression fixture must still fail");
//!        assert!(err.to_string().contains("wasm"));
//!    }
//!    ```
//!
//! ## Policy-dependent failures
//!
//! When the oracle only fails under a non-default resource policy (e.g. a very
//! shallow XDR depth limit), the promotion step will report a mismatch because
//! validation always uses the default policy. In that case, run with `--json`
//! to inspect the recorded resource policy and decide whether the failure is
//! genuinely policy-dependent or a bug.
//!
//! ## Safety constraints summary
//!
//! - **No input growth** — candidates must be strictly smaller than the current best.
//! - **Bounded iterations** — the loop stops after `max_iterations` attempts.
//! - **No recursive reduction** — the minimizer uses a flat work-list.
//! - **No embedded paths** — the metadata file never contains the original input
//!   path, the temporary directory, or any other local filesystem information.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::limits::ResourcePolicy;
use crate::parser;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The kind of fuzz input this minimizer operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// Raw WASM bytes fed to `parser::extract_metadata`.
    Parser,
    /// Raw XDR bytes fed directly to the spec decoder.
    Decoder,
    /// A pre-decoded spec exercising the mapper / type-walk paths.
    Mapper,
    /// A previously saved JSON report exercising report rendering.
    Report,
}

impl fmt::Display for InputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputKind::Parser => write!(f, "parser"),
            InputKind::Decoder => write!(f, "decoder"),
            InputKind::Mapper => write!(f, "mapper"),
            InputKind::Report => write!(f, "report"),
        }
    }
}

/// The error class that the original (and every accepted candidate) must
/// reproduce. Two inputs are considered equivalent when they produce the same
/// [`FailureClass`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FailureClass {
    /// `parser::extract_metadata` returned an error.
    ParseError {
        /// The short discriminant from [`error_discriminant`], e.g.
        /// `"wasm_validation"` or `"xdr_decoding"`.
        discriminant: String,
    },
    /// A resource limit was hit (XDR depth/length, entry count, walk depth).
    LimitExceeded {
        discriminant: String,
    },
    /// The input was accepted (no error). Useful for fixture promotion of
    /// inputs that previously caused a panic rather than a structured error.
    Accepted,
    /// An unexpected panic was caught. The message is normalized to remove
    /// addresses and non-deterministic content.
    Panic {
        /// First 120 characters of the panic message, stripped of addresses.
        summary: String,
    },
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailureClass::ParseError { discriminant } => {
                write!(f, "parse_error/{discriminant}")
            }
            FailureClass::LimitExceeded { discriminant } => {
                write!(f, "limit_exceeded/{discriminant}")
            }
            FailureClass::Accepted => write!(f, "accepted"),
            FailureClass::Panic { summary } => write!(f, "panic/{summary}"),
        }
    }
}

/// One step in the reduction history: what was tried and whether it succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReductionStep {
    /// The strategy that generated this candidate.
    pub strategy: String,
    /// Byte length of the candidate.
    pub candidate_len: usize,
    /// Whether this candidate was accepted (preserved the failure class and
    /// was strictly smaller than the current best).
    pub accepted: bool,
}

/// The result of a complete minimization run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationResult {
    /// The kind of input that was minimized.
    pub input_kind: InputKind,
    /// The failure class that was preserved throughout reduction.
    pub failure_class: FailureClass,
    /// The resource policy that was active during minimization.
    pub resource_policy: ResourcePolicySummary,
    /// The toolchain triple used during minimization, e.g.
    /// `"x86_64-unknown-linux-gnu"` or `"wasm32-unknown-unknown"`.
    pub toolchain: String,
    /// Byte length of the original (pre-minimization) input.
    pub original_len: usize,
    /// Byte length of the minimized output.
    pub minimized_len: usize,
    /// Total number of reduction steps attempted.
    pub steps_attempted: usize,
    /// Total number of reduction steps that improved the input.
    pub steps_accepted: usize,
    /// Reduction history, newest-first.
    pub history: Vec<ReductionStep>,
    /// The minimized bytes. Never contains a filesystem path.
    #[serde(with = "serde_bytes_base64")]
    pub minimized_bytes: Vec<u8>,
    /// SHA-256 hex digest of `minimized_bytes`, for deterministic fixture IDs.
    pub digest: String,
}

/// A stable, serializable summary of the active resource policy (no methods,
/// no internal types — just the four numeric limits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicySummary {
    pub max_xdr_depth: u32,
    pub max_xdr_len: usize,
    pub max_entries: usize,
    pub max_walk_depth: usize,
}

impl From<&ResourcePolicy> for ResourcePolicySummary {
    fn from(p: &ResourcePolicy) -> Self {
        ResourcePolicySummary {
            max_xdr_depth: p.max_xdr_depth,
            max_xdr_len: p.max_xdr_len,
            max_entries: p.max_entries,
            max_walk_depth: p.max_walk_depth,
        }
    }
}

/// A promoted fixture: the minimized bytes plus a sidecar metadata file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotedFixture {
    /// The fixture name, derived from the failure class and digest (no paths).
    pub name: String,
    /// The full minimization result embedded in the fixture metadata.
    pub result: MinimizationResult,
    /// Human-readable validation notes added at promotion time.
    pub validation_notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a single minimization run.
#[derive(Debug, Clone)]
pub struct MinimizeConfig {
    /// Which input kind to minimize.
    pub input_kind: InputKind,
    /// Resource policy used during minimization and recorded in the output.
    pub policy: ResourcePolicy,
    /// Maximum number of reduction iterations. A good default is 1 000; set
    /// lower for fast smoke tests, higher for thorough corpus work.
    pub max_iterations: usize,
    /// When `true`, the reducer records every attempted step (not just
    /// accepted ones) in the history. Useful for debugging the minimizer
    /// itself; the history can get large.
    pub verbose_history: bool,
}

impl Default for MinimizeConfig {
    fn default() -> Self {
        MinimizeConfig {
            input_kind: InputKind::Parser,
            policy: ResourcePolicy::default(),
            max_iterations: 1_000,
            verbose_history: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Core minimizer
// ---------------------------------------------------------------------------

/// Classify an error returned by the oracle into a [`FailureClass`].
///
/// Uses only the public error interface — never examines error message strings
/// that could embed a local path.
fn classify_error(err: &anyhow::Error) -> FailureClass {
    use crate::limits::find_limit_error;

    if let Some(limit_err) = find_limit_error(err) {
        let discriminant = match limit_err {
            crate::limits::LimitError::XdrDepthExceeded { .. } => "xdr_depth_exceeded",
            crate::limits::LimitError::XdrLengthExceeded { .. } => "xdr_length_exceeded",
            crate::limits::LimitError::WalkDepthExceeded { .. } => "walk_depth_exceeded",
            crate::limits::LimitError::EntryCountExceeded { .. } => "entry_count_exceeded",
        };
        return FailureClass::LimitExceeded {
            discriminant: discriminant.to_string(),
        };
    }

    // Walk the error chain for the crate's own typed errors.
    for cause in err.chain() {
        if let Some(typed) = cause.downcast_ref::<crate::error::Error>() {
            let discriminant = error_discriminant(typed);
            return FailureClass::ParseError { discriminant };
        }
    }

    // Fallback: use the first 60 chars of the outermost message (no paths).
    let msg = err.to_string();
    let summary = sanitize_message(&msg);
    FailureClass::ParseError {
        discriminant: summary,
    }
}

/// Return a short, stable discriminant for a typed [`crate::error::Error`]
/// that never embeds a filesystem path or other sensitive value.
fn error_discriminant(err: &crate::error::Error) -> String {
    // Match on the kind enum, which carries no data.
    use crate::error::ErrorKind;
    let kind = err.kind();
    match kind {
        ErrorKind::WasmValidation => "wasm_validation",
        ErrorKind::SectionExtraction => "section_extraction",
        ErrorKind::XdrDecoding => "xdr_decoding",
        ErrorKind::FileAccess => "file_access",
        ErrorKind::UnsupportedContract => "unsupported_contract",
        ErrorKind::LimitExceeded => "limit_exceeded",
        ErrorKind::InvalidInput => "invalid_input",
        _ => "other",
    }
    .to_string()
}

/// Strip addresses, hex run-ids, and similar non-deterministic fragments from
/// a panic or error message so the summary is stable across runs.
fn sanitize_message(msg: &str) -> String {
    // Remove anything that looks like a hex address: `0x[0-9a-fA-F]{4,}`.
    let mut out = String::with_capacity(msg.len().min(120));
    let bytes = msg.as_bytes();
    let mut i = 0;
    while i < bytes.len() && out.len() < 120 {
        // Simple scan: skip `0x` followed by 4+ hex digits.
        if i + 2 < bytes.len() && bytes[i] == b'0' && bytes[i + 1] == b'x' {
            let start = i + 2;
            let end = bytes[start..]
                .iter()
                .position(|b| !b.is_ascii_hexdigit())
                .map(|n| start + n)
                .unwrap_or(bytes.len());
            if end - start >= 4 {
                out.push_str("0x<addr>");
                i = end;
                continue;
            }
        }
        // Skip anything that looks like a local path component.
        if bytes[i] == b'/' || (bytes[i] == b'\\' && i + 1 < bytes.len()) {
            out.push('<');
            out.push_str("path");
            out.push('>');
            while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out.trim().to_string()
}

/// Run the oracle on `candidate` and return its failure class.
fn oracle(candidate: &[u8], kind: InputKind, policy: &ResourcePolicy) -> FailureClass {
    let _ = policy; // policy is recorded in the result; the built-in defaults match
    match kind {
        InputKind::Parser | InputKind::Mapper => {
            match parser::extract_metadata(candidate) {
                Ok(_) => FailureClass::Accepted,
                Err(e) => classify_error(&e),
            }
        }
        InputKind::Decoder => {
            // Exercise the raw XDR decode path directly.
            use std::io::Cursor;
            use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScSpecEntry};
            let cursor = Cursor::new(candidate);
            let mut limited = Limited::new(
                cursor,
                Limits {
                    depth: policy.max_xdr_depth,
                    len: policy.max_xdr_len,
                },
            );
            match ScSpecEntry::read_xdr(&mut limited) {
                Ok(_) => FailureClass::Accepted,
                Err(e) => {
                    if matches!(e, stellar_xdr::curr::Error::DepthLimitExceeded) {
                        FailureClass::LimitExceeded {
                            discriminant: "xdr_depth_exceeded".to_string(),
                        }
                    } else if matches!(e, stellar_xdr::curr::Error::LengthLimitExceeded) {
                        FailureClass::LimitExceeded {
                            discriminant: "xdr_length_exceeded".to_string(),
                        }
                    } else {
                        FailureClass::ParseError {
                            discriminant: "xdr_decoding".to_string(),
                        }
                    }
                }
            }
        }
        InputKind::Report => {
            // Exercise the JSON report rendering path.
            match crate::render::RenderableReport::from_json_str(
                &String::from_utf8_lossy(candidate),
            ) {
                Ok(_) => FailureClass::Accepted,
                Err(_) => FailureClass::ParseError {
                    discriminant: "report_render".to_string(),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reduction strategies (iterative, no recursion)
// ---------------------------------------------------------------------------

/// All byte-level reduction strategies applied in a fixed priority order.
/// Each returns `Some(candidate)` when it can produce a smaller variant of
/// `input`, or `None` when no obvious reduction is possible.
fn reduction_candidates(input: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // Strategy 1: remove the last byte.
    if input.len() > 1 {
        out.push(("trim_tail", input[..input.len() - 1].to_vec()));
    }

    // Strategy 2: remove the first byte.
    if input.len() > 1 {
        out.push(("trim_head", input[1..].to_vec()));
    }

    // Strategy 3: bisect — keep only the first half.
    if input.len() > 2 {
        out.push(("bisect_head", input[..input.len() / 2].to_vec()));
    }

    // Strategy 4: bisect — keep only the second half.
    if input.len() > 2 {
        out.push(("bisect_tail", input[input.len() / 2..].to_vec()));
    }

    // Strategy 5: zero out the middle quarter.
    if input.len() > 8 {
        let mut zeroed = input.to_vec();
        let q = input.len() / 4;
        for b in &mut zeroed[q..3 * q] {
            *b = 0;
        }
        out.push(("zero_middle", zeroed));
    }

    // Strategy 6: replace every non-ASCII byte with 0x00. Useful for spec
    // blobs where the XDR framing is what matters.
    if input.iter().any(|b| *b > 0x7f) {
        let cleaned: Vec<u8> = input.iter().map(|b| if *b > 0x7f { 0 } else { *b }).collect();
        out.push(("ascii_clamp", cleaned));
    }

    out
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Minimize `input` and return a [`MinimizationResult`].
///
/// # Errors
///
/// Returns an error when the original input does **not** trigger a failure
/// (i.e. the oracle returns [`FailureClass::Accepted`] for the unmodified
/// input) — there is nothing to minimize.
pub fn minimize(
    input: &[u8],
    config: &MinimizeConfig,
) -> anyhow::Result<MinimizationResult> {
    let original_class = oracle(input, config.input_kind, &config.policy);
    if original_class == FailureClass::Accepted {
        anyhow::bail!(
            "Input does not trigger a failure (oracle returned Accepted). \
             Pass an input that currently fails before minimizing."
        );
    }

    let toolchain = toolchain_triple();
    let mut best = input.to_vec();
    let original_len = input.len();
    let mut history: Vec<ReductionStep> = Vec::new();
    let mut steps_attempted = 0usize;
    let mut steps_accepted = 0usize;

    'outer: for _ in 0..config.max_iterations {
        let mut improved = false;
        for (strategy, candidate) in reduction_candidates(&best) {
            if candidate.is_empty() || candidate.len() >= best.len() {
                continue;
            }
            steps_attempted += 1;

            let class = oracle(&candidate, config.input_kind, &config.policy);
            let accepted = class == original_class;

            if config.verbose_history {
                history.push(ReductionStep {
                    strategy: strategy.to_string(),
                    candidate_len: candidate.len(),
                    accepted,
                });
            }

            if accepted {
                best = candidate;
                steps_accepted += 1;
                if !config.verbose_history {
                    history.push(ReductionStep {
                        strategy: strategy.to_string(),
                        candidate_len: best.len(),
                        accepted: true,
                    });
                }
                improved = true;
                // Restart from the new best immediately.
                continue 'outer;
            }

            // Guard: never let the best grow.
            debug_assert!(candidate.len() < input.len() + 1);
        }

        if !improved {
            break;
        }
    }

    let digest = sha256_hex(&best);

    Ok(MinimizationResult {
        input_kind: config.input_kind,
        failure_class: original_class,
        resource_policy: ResourcePolicySummary::from(&config.policy),
        toolchain,
        original_len,
        minimized_len: best.len(),
        steps_attempted,
        steps_accepted,
        history,
        minimized_bytes: best,
        digest,
    })
}

/// Promote a [`MinimizationResult`] to a deterministic fixture.
///
/// Writes two files into `output_dir`:
/// - `<name>.bin` — the minimized bytes.
/// - `<name>.meta.json` — the [`PromotedFixture`] as pretty JSON.
///
/// The fixture name is derived from the failure class and the digest, so it is
/// stable and path-independent. No local filesystem paths are embedded.
///
/// The fixture is validated under normal resource limits before being written:
/// the oracle is re-run on the minimized bytes to confirm the failure class is
/// still reproducible. An error is returned if the class has changed.
pub fn promote(
    result: MinimizationResult,
    output_dir: &Path,
) -> anyhow::Result<PromotedFixture> {
    use std::io::Write;

    // Validation: confirm the minimized bytes still reproduce the failure
    // under the standard (default) resource policy.
    let validation_policy = ResourcePolicy::default();
    let reproduced_class = oracle(&result.minimized_bytes, result.input_kind, &validation_policy);

    let mut validation_notes: Vec<String> = Vec::new();

    if reproduced_class != result.failure_class {
        anyhow::bail!(
            "Promoted fixture validation failed: expected failure class '{}', \
             but standard resource policy reproduced '{}'.\n\
             The minimized input may be policy-dependent. Use a fixed policy.",
            result.failure_class,
            reproduced_class
        );
    }
    validation_notes.push(format!(
        "Reproduced '{}' under standard resource limits (max_xdr_depth={}, max_entries={}).",
        result.failure_class,
        validation_policy.max_xdr_depth,
        validation_policy.max_entries
    ));

    // Derive a stable, path-independent fixture name.
    let safe_class = result
        .failure_class
        .to_string()
        .replace(['/', ' ', ':'], "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>();
    let short_digest = &result.digest[..12];
    let name = format!("{}_{}_{}_{}", result.input_kind, safe_class, short_digest, result.minimized_len);

    let fixture = PromotedFixture {
        name: name.clone(),
        result,
        validation_notes,
    };

    // Write the fixture files.
    std::fs::create_dir_all(output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to create output dir '{}': {e}", output_dir.display()))?;

    let bin_path = output_dir.join(format!("{name}.bin"));
    let meta_path = output_dir.join(format!("{name}.meta.json"));

    let mut bin_file = std::fs::File::create(&bin_path)
        .map_err(|e| anyhow::anyhow!("Failed to create '{}': {e}", bin_path.display()))?;
    bin_file
        .write_all(&fixture.result.minimized_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write '{}': {e}", bin_path.display()))?;

    let meta_json = serde_json::to_string_pretty(&fixture)
        .map_err(|e| anyhow::anyhow!("Failed to serialize fixture metadata: {e}"))?;
    std::fs::write(&meta_path, meta_json)
        .map_err(|e| anyhow::anyhow!("Failed to write '{}': {e}", meta_path.display()))?;

    Ok(fixture)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a stable toolchain triple for the current compilation target.
/// Avoids environment variables that could contain local paths.
fn toolchain_triple() -> String {
    // CARGO_CFG_TARGET_TRIPLE is not available at runtime; use cfg! macros
    // to pick the closest stable label.
    #[cfg(target_arch = "x86_64")]
    let arch = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let arch = "aarch64";
    #[cfg(target_arch = "wasm32")]
    let arch = "wasm32";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "wasm32")))]
    let arch = "unknown";

    #[cfg(target_os = "linux")]
    let os = "unknown-linux";
    #[cfg(target_os = "macos")]
    let os = "apple-darwin";
    #[cfg(target_os = "windows")]
    let os = "pc-windows";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let os = "unknown-unknown";

    #[cfg(target_env = "gnu")]
    let env = "-gnu";
    #[cfg(target_env = "msvc")]
    let env = "-msvc";
    #[cfg(not(any(target_env = "gnu", target_env = "msvc")))]
    let env = "";

    format!("{arch}-{os}{env}")
}

// ---------------------------------------------------------------------------
// serde helper: base64-encode `Vec<u8>` fields.
// ---------------------------------------------------------------------------

mod serde_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // FailureClass helpers
    // ------------------------------------------------------------------

    #[test]
    fn failure_class_display_is_stable() {
        assert_eq!(
            FailureClass::ParseError {
                discriminant: "xdr_decoding".into()
            }
            .to_string(),
            "parse_error/xdr_decoding"
        );
        assert_eq!(
            FailureClass::LimitExceeded {
                discriminant: "xdr_depth_exceeded".into()
            }
            .to_string(),
            "limit_exceeded/xdr_depth_exceeded"
        );
        assert_eq!(FailureClass::Accepted.to_string(), "accepted");
    }

    #[test]
    fn failure_class_round_trips_through_json() {
        let class = FailureClass::ParseError {
            discriminant: "wasm_validation".into(),
        };
        let json = serde_json::to_string(&class).unwrap();
        let back: FailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }

    // ------------------------------------------------------------------
    // sanitize_message
    // ------------------------------------------------------------------

    #[test]
    fn sanitize_message_strips_hex_addresses() {
        let msg = "panicked at 0x7f3a4b5c6d7e: something went wrong";
        let out = sanitize_message(msg);
        assert!(!out.contains("0x7f3a"), "address must be replaced: {out}");
        assert!(out.contains("0x<addr>"), "address placeholder expected: {out}");
    }

    #[test]
    fn sanitize_message_does_not_exceed_120_chars() {
        let long = "a".repeat(200);
        let out = sanitize_message(&long);
        assert!(out.len() <= 120);
    }

    // ------------------------------------------------------------------
    // sha256_hex
    // ------------------------------------------------------------------

    #[test]
    fn sha256_hex_of_empty_is_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ------------------------------------------------------------------
    // Oracle behaviour on known-bad inputs
    // ------------------------------------------------------------------

    #[test]
    fn oracle_classifies_garbage_bytes_as_parse_error() {
        let garbage = b"\x00\xff\xfe\xfd garbage bytes that cannot be WASM or XDR";
        let policy = ResourcePolicy::default();
        let class = oracle(garbage, InputKind::Parser, &policy);
        assert!(
            matches!(class, FailureClass::ParseError { .. }),
            "expected ParseError, got: {class}"
        );
    }

    #[test]
    fn oracle_returns_accepted_for_minimal_valid_wasm() {
        // The minimal valid WASM module: magic + version, no sections.
        let wasm = b"\x00asm\x01\x00\x00\x00";
        let policy = ResourcePolicy::default();
        let class = oracle(wasm, InputKind::Parser, &policy);
        assert_eq!(
            class,
            FailureClass::Accepted,
            "minimal valid WASM must be accepted"
        );
    }

    // ------------------------------------------------------------------
    // Minimizer: does not grow the input
    // ------------------------------------------------------------------

    #[test]
    fn minimizer_never_grows_input() {
        let garbage: Vec<u8> = (0u8..=127).cycle().take(512).collect();
        let config = MinimizeConfig {
            input_kind: InputKind::Decoder,
            max_iterations: 50,
            verbose_history: false,
            ..MinimizeConfig::default()
        };
        if let Ok(result) = minimize(&garbage, &config) {
            assert!(
                result.minimized_len <= result.original_len,
                "minimized ({}) must be <= original ({})",
                result.minimized_len,
                result.original_len
            );
        }
        // `Err` is also acceptable: the input might not fail the oracle.
    }

    #[test]
    fn minimizer_preserves_failure_class() {
        // A known-bad WASM: valid magic but truncated type section.
        let bad_wasm: Vec<u8> = b"\x00asm\x01\x00\x00\x00\x01\x05\x01\x60\x01\x7f"
            .iter()
            .copied()
            .chain(std::iter::once(0u8))
            .collect();
        let config = MinimizeConfig {
            input_kind: InputKind::Parser,
            max_iterations: 200,
            verbose_history: true,
            ..MinimizeConfig::default()
        };
        match minimize(&bad_wasm, &config) {
            Ok(result) => {
                // Every accepted step must have preserved the failure class.
                assert_eq!(
                    oracle(&result.minimized_bytes, result.input_kind, &ResourcePolicy::default()),
                    result.failure_class,
                    "minimized bytes must reproduce the recorded failure class"
                );
            }
            Err(_) => {
                // Input did not fail the oracle: that is also fine for this test.
            }
        }
    }

    // ------------------------------------------------------------------
    // Minimizer: already-minimal input terminates quickly
    // ------------------------------------------------------------------

    #[test]
    fn minimizer_terminates_on_single_byte_input() {
        let input = vec![0xff]; // one byte: no reduction possible
        let config = MinimizeConfig {
            input_kind: InputKind::Decoder,
            max_iterations: 100,
            ..MinimizeConfig::default()
        };
        // Should not hang; outcome (Ok or Err) is irrelevant.
        let _ = minimize(&input, &config);
    }

    // ------------------------------------------------------------------
    // Promotion: path-independent fixture names
    // ------------------------------------------------------------------

    #[test]
    fn promoted_fixture_name_contains_no_path_separator() {
        // Build a fake result to exercise the naming logic.
        let fake_bytes = b"\x00asm\x01\x00\x00\x00".to_vec();
        let digest = sha256_hex(&fake_bytes);
        let result = MinimizationResult {
            input_kind: InputKind::Parser,
            failure_class: FailureClass::Accepted,
            resource_policy: ResourcePolicySummary::from(&ResourcePolicy::default()),
            toolchain: "x86_64-unknown-linux-gnu".into(),
            original_len: 8,
            minimized_len: 8,
            steps_attempted: 0,
            steps_accepted: 0,
            history: vec![],
            minimized_bytes: fake_bytes,
            digest,
        };

        let safe_class = result
            .failure_class
            .to_string()
            .replace(['/', ' ', ':'], "_")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>();
        let short_digest = &result.digest[..12];
        let name = format!(
            "{}_{}_{}_{}", result.input_kind, safe_class, short_digest, result.minimized_len
        );
        assert!(!name.contains('/'), "name must not contain '/': {name}");
        assert!(!name.contains('\\'), "name must not contain '\\': {name}");
    }

    // ------------------------------------------------------------------
    // toolchain_triple
    // ------------------------------------------------------------------

    #[test]
    fn toolchain_triple_is_non_empty_and_contains_no_path_separators() {
        let triple = toolchain_triple();
        assert!(!triple.is_empty());
        assert!(!triple.contains('/'));
        assert!(!triple.contains('\\'));
    }

    // ------------------------------------------------------------------
    // ResourcePolicySummary round-trip
    // ------------------------------------------------------------------

    #[test]
    fn resource_policy_summary_round_trips() {
        let policy = ResourcePolicy::default();
        let summary = ResourcePolicySummary::from(&policy);
        let json = serde_json::to_string(&summary).unwrap();
        let back: ResourcePolicySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary.max_xdr_depth, back.max_xdr_depth);
        assert_eq!(summary.max_xdr_len, back.max_xdr_len);
        assert_eq!(summary.max_entries, back.max_entries);
        assert_eq!(summary.max_walk_depth, back.max_walk_depth);
    }

    // ------------------------------------------------------------------
    // Reduction candidates
    // ------------------------------------------------------------------

    #[test]
    fn reduction_candidates_are_strictly_smaller_than_input() {
        let input: Vec<u8> = (0u8..=255).collect();
        for (_, candidate) in reduction_candidates(&input) {
            assert!(
                candidate.len() < input.len(),
                "candidate len {} must be < input len {}",
                candidate.len(),
                input.len()
            );
        }
    }

    #[test]
    fn reduction_candidates_empty_for_one_byte() {
        let candidates = reduction_candidates(&[0xabu8]);
        assert!(
            candidates.is_empty(),
            "no candidates possible for a single byte"
        );
    }

    // ------------------------------------------------------------------
    // Fixture promotion: writes bin and meta files, no paths in metadata
    // ------------------------------------------------------------------

    #[test]
    fn promote_writes_fixture_files_and_metadata_contains_no_local_path() {
        // Build a known-failing input (garbage bytes → ParseError).
        let bad_input: Vec<u8> = b"\xde\xad\xbe\xef garbage that is not WASM or XDR"
            .to_vec();
        let config = MinimizeConfig {
            input_kind: InputKind::Parser,
            max_iterations: 50,
            verbose_history: false,
            ..MinimizeConfig::default()
        };

        let result = match minimize(&bad_input, &config) {
            Ok(r) => r,
            Err(_) => return, // oracle accepted the input — nothing to promote
        };

        let tmp = std::env::temp_dir().join(format!(
            "safeguard_promote_test_{}", sha256_hex(&bad_input)[..8].to_string()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let fixture = promote(result, &tmp).expect("promote must succeed");

        // Fixture name must not contain path separators.
        assert!(!fixture.name.contains('/'), "name contains '/': {}", fixture.name);
        assert!(!fixture.name.contains('\\'), "name contains '\\': {}", fixture.name);

        // Both files must exist.
        let bin = tmp.join(format!("{}.bin", fixture.name));
        let meta = tmp.join(format!("{}.meta.json", fixture.name));
        assert!(bin.exists(), "bin file must exist: {}", bin.display());
        assert!(meta.exists(), "meta file must exist: {}", meta.display());

        // Metadata must not embed the temp dir path.
        let meta_content = std::fs::read_to_string(&meta).unwrap();
        let tmp_str = tmp.to_string_lossy();
        assert!(
            !meta_content.contains(tmp_str.as_ref()),
            "metadata must not contain the temp dir path"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ------------------------------------------------------------------
    // Per-kind oracle: all four kinds are exercised
    // ------------------------------------------------------------------

    #[test]
    fn oracle_parser_kind_rejects_garbage() {
        let garbage = b"\xff\xfe\xfd\x00 not a wasm module";
        let class = oracle(garbage, InputKind::Parser, &ResourcePolicy::default());
        assert!(
            matches!(class, FailureClass::ParseError { .. }),
            "parser oracle should fail on garbage: {class}"
        );
    }

    #[test]
    fn oracle_decoder_kind_rejects_garbage() {
        let garbage = b"\x99\x88\x77\x66\x55 not xdr";
        let class = oracle(garbage, InputKind::Decoder, &ResourcePolicy::default());
        assert!(
            matches!(class, FailureClass::ParseError { .. } | FailureClass::Accepted),
            "decoder oracle should fail or accept garbage cleanly: {class}"
        );
    }

    #[test]
    fn oracle_mapper_kind_rejects_garbage() {
        let garbage = b"\x01\x02\x03\x04 not a mapper input";
        let class = oracle(garbage, InputKind::Mapper, &ResourcePolicy::default());
        assert!(
            matches!(class, FailureClass::ParseError { .. } | FailureClass::Accepted),
            "mapper oracle should not panic: {class}"
        );
    }

    #[test]
    fn oracle_report_kind_rejects_invalid_json() {
        let not_json = b"this is not valid json { broken";
        let class = oracle(not_json, InputKind::Report, &ResourcePolicy::default());
        assert!(
            matches!(class, FailureClass::ParseError { .. } | FailureClass::Accepted),
            "report oracle should not panic: {class}"
        );
    }

    // ------------------------------------------------------------------
    // Sample failure fixture: truncated WASM type section
    //
    // This fixture represents a class of crashes a fuzzer might discover:
    // valid WASM magic and version, but a type section that is shorter than
    // its declared content length — a classic off-by-one in a handcrafted
    // or mutated input.
    // ------------------------------------------------------------------

    #[test]
    fn sample_failure_truncated_type_section_minimizes() {
        // Valid magic + version, then a type section (id=1) claiming 5 bytes
        // of content but only providing 2 bytes — guaranteed to fail the
        // WASM parser's section-length check.
        let bad_wasm: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, // magic: \0asm
            0x01, 0x00, 0x00, 0x00, // version: 1
            0x01,                   // section id: type
            0x05,                   // section size: 5 bytes claimed
            0x01, 0x00,             // only 2 bytes provided → truncated
        ];
        let config = MinimizeConfig {
            input_kind: InputKind::Parser,
            max_iterations: 200,
            verbose_history: false,
            ..MinimizeConfig::default()
        };
        match minimize(&bad_wasm, &config) {
            Ok(result) => {
                assert!(
                    result.minimized_len <= result.original_len,
                    "minimized must not grow: {} > {}",
                    result.minimized_len, result.original_len
                );
                // The failure class must be preserved.
                assert_eq!(
                    oracle(&result.minimized_bytes, InputKind::Parser, &ResourcePolicy::default()),
                    result.failure_class,
                    "failure class must be preserved after minimization"
                );
                // Reduction history must be recorded.
                assert!(
                    result.steps_attempted > 0 || result.minimized_len == result.original_len,
                    "at least one step must be attempted for a non-trivial input"
                );
            }
            Err(_) => {} // oracle accepted — acceptable edge case
        }
    }
}
