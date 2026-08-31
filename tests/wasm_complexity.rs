//! Integration and unit tests for the WASM complexity profiler (Issue #328).
//!
//! Coverage:
//! - Profile of a minimal (empty code section) WASM module.
//! - Profile of the v1/v2 fixture pair to confirm non-zero counts.
//! - Delta computation: absolute and percentage values.
//! - Budget enforcement: absolute limit, percentage limit, both together.
//! - Malformed / garbage WASM input handling (graceful error, no panic).
//! - Report snapshot: complexity fields appear in JSON output when a budget
//!   is provided.
//! - Complexity violations gate `is_safe` in the library API.
//! - No complexity section emitted when no budget is configured.

use std::path::PathBuf;

use soroban_upgrade_safeguard::wasm_complexity::{
    ComplexityBudgetConfig, ComplexityBudgetEntryFile, WasmComplexityDelta, WasmComplexityProfile,
    evaluate_complexity_budgets, profile_wasm,
};
use soroban_upgrade_safeguard::{CompareOptions, compare_wasm_bytes_with_options};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn read_wasm(name: &str) -> Vec<u8> {
    std::fs::read(wasm(name)).unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

/// Minimal valid WASM: magic + version, no sections.
fn minimal_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

/// Clearly invalid bytes — not a WASM module at all.
fn garbage_bytes() -> Vec<u8> {
    vec![0xFF, 0xFE, 0x00, 0x01, 0x42, 0xAB]
}

fn budget(metric: &str, limit: Option<i64>, pct: Option<f64>) -> ComplexityBudgetEntryFile {
    ComplexityBudgetEntryFile {
        metric: metric.to_string(),
        limit,
        pct_limit: pct,
    }
}

fn make_budget(entries: Vec<ComplexityBudgetEntryFile>) -> ComplexityBudgetConfig {
    ComplexityBudgetConfig::from_file_entries(entries)
        .expect("test budget config must be valid")
}

// ── Profile tests ─────────────────────────────────────────────────────────────

#[test]
fn profile_empty_module_has_zero_counts() {
    let profile = profile_wasm(&minimal_wasm()).expect("minimal WASM must profile cleanly");
    assert_eq!(profile.defined_functions, 0, "no functions in minimal module");
    assert_eq!(profile.total_instructions, 0, "no instructions in minimal module");
    assert!(profile.functions.is_empty(), "no function entries");
    // All family counts should be 0
    for (family, count) in &profile.by_family {
        assert_eq!(*count, 0, "family {family} must be 0 for empty module");
    }
}

#[test]
fn profile_v1_wasm_has_nonzero_functions_and_instructions() {
    let bytes = read_wasm("v1.wasm");
    let profile = profile_wasm(&bytes).expect("v1.wasm must profile cleanly");
    assert!(profile.defined_functions > 0, "v1.wasm must have at least one function");
    assert!(profile.total_instructions > 0, "v1.wasm must have instructions");
}

#[test]
fn profile_family_counts_sum_to_total_instructions() {
    let bytes = read_wasm("v1.wasm");
    let profile = profile_wasm(&bytes).expect("v1.wasm must profile");
    let family_sum: u64 = profile.by_family.values().sum();
    assert_eq!(
        family_sum, profile.total_instructions,
        "per-family counts must sum to total_instructions"
    );
}

#[test]
fn profile_malformed_wasm_returns_error() {
    let result = profile_wasm(&garbage_bytes());
    assert!(result.is_err(), "garbage bytes must fail to profile");
}

#[test]
fn profile_malformed_wasm_does_not_panic() {
    // Even extreme garbage must not panic
    let _ = profile_wasm(&garbage_bytes());
    let _ = profile_wasm(&[]);
    let _ = profile_wasm(&[0x00]);
}

#[test]
fn profile_all_families_present_in_by_family_map() {
    let profile = profile_wasm(&minimal_wasm()).expect("minimal must profile");
    let expected_families = [
        "arithmetic", "control", "calls", "memory", "comparison",
        "conversion", "reference", "simd", "other",
    ];
    for family in expected_families {
        assert!(
            profile.by_family.contains_key(family),
            "profile must contain family key '{family}'"
        );
    }
}

// ── Delta tests ───────────────────────────────────────────────────────────────

#[test]
fn delta_absolute_and_pct_computed_correctly() {
    let mut old = WasmComplexityProfile::default();
    old.defined_functions = 10;
    old.total_instructions = 1000;

    let mut new = WasmComplexityProfile::default();
    new.defined_functions = 12;
    new.total_instructions = 1200;

    let delta = WasmComplexityDelta::compute(&old, &new);
    assert_eq!(delta.defined_functions.absolute, 2);
    assert_eq!(delta.total_instructions.absolute, 200);
    // pct = (200 / 1000) * 100 = 20.0
    assert_eq!(delta.total_instructions.pct, Some(20.0));
}

#[test]
fn delta_pct_is_none_when_old_is_zero() {
    let old = WasmComplexityProfile::default(); // zeros
    let mut new = WasmComplexityProfile::default();
    new.total_instructions = 500;

    let delta = WasmComplexityDelta::compute(&old, &new);
    assert!(
        delta.total_instructions.pct.is_none(),
        "pct must be None when old is 0 (division by zero)"
    );
}

#[test]
fn delta_decrease_shows_negative_absolute() {
    let mut old = WasmComplexityProfile::default();
    old.total_instructions = 1000;
    let mut new = WasmComplexityProfile::default();
    new.total_instructions = 800;

    let delta = WasmComplexityDelta::compute(&old, &new);
    assert_eq!(delta.total_instructions.absolute, -200);
    assert_eq!(delta.total_instructions.pct, Some(-20.0));
}

#[test]
fn delta_is_deterministic_for_same_inputs() {
    let bytes = read_wasm("v1.wasm");
    let p1 = profile_wasm(&bytes).unwrap();
    let p2 = profile_wasm(&bytes).unwrap();
    let d1 = WasmComplexityDelta::compute(&p1, &p2);
    let d2 = WasmComplexityDelta::compute(&p1, &p2);
    assert_eq!(d1.total_instructions.absolute, d2.total_instructions.absolute);
    assert_eq!(d1.defined_functions.absolute, d2.defined_functions.absolute);
}

// ── Budget / violation tests ──────────────────────────────────────────────────

#[test]
fn absolute_limit_violation_detected() {
    let mut old = WasmComplexityProfile::default();
    old.total_instructions = 100;
    let mut new = WasmComplexityProfile::default();
    new.total_instructions = 200;

    let delta = WasmComplexityDelta::compute(&old, &new);
    let budget = make_budget(vec![budget("total_instructions", Some(150), None)]);
    let violations = evaluate_complexity_budgets(&delta, &budget.entries);
    assert_eq!(violations.len(), 1, "should have one violation");
    assert_eq!(violations[0].metric, "total_instructions");
    assert_eq!(violations[0].measured, 200);
    assert_eq!(violations[0].limit, Some(150));
}

#[test]
fn pct_limit_violation_detected() {
    let mut old = WasmComplexityProfile::default();
    old.total_instructions = 100;
    let mut new = WasmComplexityProfile::default();
    new.total_instructions = 130; // 30% growth

    let delta = WasmComplexityDelta::compute(&old, &new);
    let budget = make_budget(vec![budget("total_instructions", None, Some(20.0))]);
    let violations = evaluate_complexity_budgets(&delta, &budget.entries);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].pct_change.is_some());
    assert_eq!(violations[0].pct_limit, Some(20.0));
}

#[test]
fn no_violation_within_budget() {
    let mut old = WasmComplexityProfile::default();
    old.total_instructions = 100;
    let mut new = WasmComplexityProfile::default();
    new.total_instructions = 110; // 10% growth

    let delta = WasmComplexityDelta::compute(&old, &new);
    let budget = make_budget(vec![budget("total_instructions", Some(200), Some(20.0))]);
    let violations = evaluate_complexity_budgets(&delta, &budget.entries);
    assert!(violations.is_empty(), "no violations within budget");
}

#[test]
fn budget_config_rejects_negative_limit() {
    let raw = vec![budget("total_instructions", Some(-1), None)];
    assert!(ComplexityBudgetConfig::from_file_entries(raw).is_err());
}

#[test]
fn budget_config_rejects_missing_both_limits() {
    let raw = vec![budget("total_instructions", None, None)];
    assert!(ComplexityBudgetConfig::from_file_entries(raw).is_err());
}

#[test]
fn budget_config_rejects_unknown_metric() {
    let raw = vec![budget("gas_cost", Some(1000), None)];
    assert!(ComplexityBudgetConfig::from_file_entries(raw).is_err());
}

#[test]
fn budget_config_accepts_all_valid_metrics() {
    let metrics = [
        "total_instructions",
        "defined_functions",
        "arithmetic",
        "control",
        "calls",
        "memory",
        "comparison",
        "conversion",
        "reference",
        "simd",
        "other",
    ];
    for metric in metrics {
        let raw = vec![budget(metric, Some(99999), None)];
        assert!(
            ComplexityBudgetConfig::from_file_entries(raw).is_ok(),
            "metric '{metric}' must be accepted"
        );
    }
}

// ── Library API integration tests ─────────────────────────────────────────────

#[test]
fn complexity_violation_gates_is_safe() {
    let old = read_wasm("v1.wasm");
    let new = read_wasm("v2.wasm");

    // Set a limit of 1 instruction — guaranteed to be exceeded
    let budget = make_budget(vec![budget("total_instructions", Some(1), None)]);
    let report = compare_wasm_bytes_with_options(
        &old,
        &new,
        &CompareOptions {
            suppressions: None,
            explain: false,
            strict: false,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: Some(&budget),
        },
    )
    .expect("comparison must not error");

    assert!(
        !report.is_safe(),
        "exceeded complexity budget must make report unsafe"
    );
    assert!(
        !report.complexity_violations.is_empty(),
        "complexity_violations must be non-empty"
    );
    assert!(
        report.complexity_delta.is_some(),
        "complexity_delta must be present when budget is configured"
    );
}

#[test]
fn no_complexity_section_when_no_budget() {
    let old = read_wasm("v1.wasm");
    let new = read_wasm("v2.wasm");

    let report = compare_wasm_bytes_with_options(
        &old,
        &new,
        &CompareOptions {
            suppressions: None,
            explain: false,
            strict: false,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: None,
        },
    )
    .expect("comparison must not error");

    assert!(
        report.complexity_delta.is_none(),
        "complexity_delta must be None when no budget is configured"
    );
    assert!(
        report.complexity_violations.is_empty(),
        "complexity_violations must be empty when no budget is configured"
    );
}

#[test]
fn complexity_section_present_in_json_output_when_budget_set() {
    let old = read_wasm("v1.wasm");
    let new = read_wasm("v2.wasm");

    let budget = make_budget(vec![budget("total_instructions", Some(999_999_999), None)]);
    let report = compare_wasm_bytes_with_options(
        &old,
        &new,
        &CompareOptions {
            suppressions: None,
            explain: false,
            strict: false,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: Some(&budget),
        },
    )
    .expect("comparison must not error");

    let json_str = serde_json::to_string(&report.to_renderable())
        .expect("renderable must serialize to JSON");
    let json: serde_json::Value =
        serde_json::from_str(&json_str).expect("JSON must be valid");

    assert!(
        json.get("complexity_delta").is_some(),
        "JSON report must contain complexity_delta when budget is set"
    );
    assert!(
        json["complexity_delta"]["total_instructions"].is_object(),
        "complexity_delta must have total_instructions field"
    );
}

#[test]
fn text_output_contains_complexity_section_when_budget_set() {
    let old = read_wasm("v1.wasm");
    let new = read_wasm("v2.wasm");

    let budget = make_budget(vec![budget("total_instructions", Some(999_999_999), None)]);
    let report = compare_wasm_bytes_with_options(
        &old,
        &new,
        &CompareOptions {
            suppressions: None,
            explain: false,
            strict: false,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: Some(&budget),
        },
    )
    .expect("comparison must not error");

    let text = report.generate_summary_text(false);
    assert!(
        text.contains("WASM COMPLEXITY DELTA"),
        "text output must contain WASM COMPLEXITY DELTA section"
    );
    assert!(
        text.contains("Static analysis only"),
        "text output must contain the static-analysis disclaimer"
    );
    assert!(
        text.contains("total_instructions"),
        "text output must contain total_instructions metric"
    );
}

#[test]
fn markdown_output_contains_complexity_section_when_budget_set() {
    let old = read_wasm("v1.wasm");
    let new = read_wasm("v2.wasm");

    let budget = make_budget(vec![budget("total_instructions", Some(999_999_999), None)]);
    let report = compare_wasm_bytes_with_options(
        &old,
        &new,
        &CompareOptions {
            suppressions: None,
            explain: false,
            strict: false,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: Some(&budget),
        },
    )
    .expect("comparison must not error");

    let md = report.generate_summary_markdown();
    assert!(
        md.contains("WASM Complexity Delta"),
        "markdown must contain WASM Complexity Delta heading"
    );
    assert!(
        md.contains("Static analysis only"),
        "markdown must contain static-analysis disclaimer"
    );
}
