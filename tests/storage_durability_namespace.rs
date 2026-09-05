//! Integration tests for storage durability and namespace change detection.
//!
//! These tests exercise the cross-schema comparison introduced in issue #346.
//! They use the JSON schema fixtures under `tests/fixtures/storage_durability/`
//! and call the public library API directly (no CLI spawn).

use std::path::PathBuf;

use soroban_upgrade_safeguard::storage_inference::{Durability, StorageInference};
use soroban_upgrade_safeguard::storage_schema::{
    compare_storage_schemas, SchemaMismatch, StorageSchema,
};

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("storage_durability")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
}

fn load(name: &str) -> StorageSchema {
    StorageSchema::from_json(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

// ── Durability change detection ───────────────────────────────────────────────

#[test]
fn detects_persistent_to_temporary_durability_change() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "counter" changed from persistent → temporary
    let durability_findings: Vec<_> = cmp
        .cross_findings
        .iter()
        .filter(|f| matches!(f, SchemaMismatch::DurabilityChanged { .. }))
        .collect();

    assert!(
        !durability_findings.is_empty(),
        "expected at least one DurabilityChanged finding"
    );

    let counter_finding = durability_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::DurabilityChanged {
                declaration,
                old_durability: Durability::Persistent,
                new_durability: Durability::Temporary,
                ..
            } if declaration == "counter"
        )
    });
    assert!(
        counter_finding.is_some(),
        "expected counter to change from persistent to temporary"
    );
}

#[test]
fn detects_temporary_to_persistent_durability_change() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "session" changed from temporary → persistent
    let session_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::DurabilityChanged {
                declaration,
                old_durability: Durability::Temporary,
                new_durability: Durability::Persistent,
                ..
            } if declaration == "session"
        )
    });
    assert!(
        session_finding.is_some(),
        "expected session to change from temporary to persistent"
    );
}

#[test]
fn detects_instance_to_persistent_durability_change() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "config" changed from instance → persistent
    let config_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::DurabilityChanged {
                declaration,
                old_durability: Durability::Instance,
                new_durability: Durability::Persistent,
                ..
            } if declaration == "config"
        )
    });
    assert!(
        config_finding.is_some(),
        "expected config to change from instance to persistent"
    );
}

#[test]
fn unchanged_declaration_produces_no_durability_finding() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "stable" kept persistent → no finding expected
    let stable_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::DurabilityChanged { declaration, .. } if declaration == "stable"
        )
    });
    assert!(
        stable_finding.is_none(),
        "stable should not have a DurabilityChanged finding"
    );
}

#[test]
fn durability_changes_fail_compatibility_check() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    assert!(
        !cmp.is_compatible(),
        "schema comparison with durability changes must be incompatible"
    );
}

#[test]
fn compatible_schemas_produce_no_cross_findings() {
    let old = load("old_schema.json");
    let new = load("new_schema_compatible.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    assert!(
        cmp.cross_findings.is_empty(),
        "identical old/new schemas should produce no cross-schema findings"
    );
    // Per-side reconciliation is separate: with an empty `StorageInference`
    // every declared key is reported as unobserved, so the overall
    // `is_compatible()` verdict here is driven by the (absent) observations,
    // not by the schema comparison itself.
}

// ── Namespace change detection ────────────────────────────────────────────────

#[test]
fn detects_namespace_value_change() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "balance" changed from namespace "v1" → "v2"
    let balance_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "balance" && old_namespace == "v1" && new_namespace == "v2"
        )
    });
    assert!(
        balance_finding.is_some(),
        "expected namespace change on 'balance' from v1 to v2"
    );
}

#[test]
fn detects_namespace_removed() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "allowance" had namespace "token", now has none
    let allowance_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "allowance" && old_namespace == "token" && new_namespace.is_empty()
        )
    });
    assert!(
        allowance_finding.is_some(),
        "expected namespace removal on 'allowance'"
    );
}

#[test]
fn detects_namespace_added() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "unnamespaced" had no namespace, now has "new_ns"
    let finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "unnamespaced" && old_namespace.is_empty() && new_namespace == "new_ns"
        )
    });
    assert!(
        finding.is_some(),
        "expected namespace addition on 'unnamespaced'"
    );
}

#[test]
fn unchanged_namespace_produces_no_finding() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );

    // "meta" kept namespace "contract" on both sides — no finding
    let meta_finding = cmp.cross_findings.iter().find(|f| {
        matches!(
            f,
            SchemaMismatch::NamespaceChanged { declaration, .. } if declaration == "meta"
        )
    });
    assert!(
        meta_finding.is_none(),
        "unchanged namespace should not produce a finding"
    );
}

#[test]
fn namespace_changes_fail_compatibility_check() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    assert!(
        !cmp.is_compatible(),
        "schema comparison with namespace changes must be incompatible"
    );
}

// ── Output format tests ───────────────────────────────────────────────────────

#[test]
fn durability_change_is_in_text_output() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    let text = cmp.render_text();
    assert!(
        text.contains("cross-schema findings"),
        "text output should include the cross-schema findings section"
    );
    assert!(
        text.contains("counter"),
        "text output should name the affected declaration"
    );
}

#[test]
fn namespace_change_is_in_markdown_output() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    let md = cmp.render_markdown();
    assert!(
        md.contains("Cross-Schema Findings"),
        "markdown output should include the Cross-Schema Findings section"
    );
    assert!(
        md.contains("balance"),
        "markdown output should name the affected declaration"
    );
}

#[test]
fn durability_change_is_in_json_output() {
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    let json = cmp.to_json_value();
    assert_eq!(json["compatible"], false);
    let cross = json["cross_findings"].as_array().unwrap();
    assert!(!cross.is_empty(), "cross_findings array must be non-empty");
    // All cross findings should have a "kind" field
    for f in cross {
        assert!(
            f.get("kind").is_some(),
            "each cross finding must have a 'kind' field"
        );
    }
    // At least one finding should be "durability_changed"
    let has_durability_changed = cross
        .iter()
        .any(|f| f["kind"].as_str() == Some("durability_changed"));
    assert!(
        has_durability_changed,
        "JSON output must include durability_changed findings"
    );
}

#[test]
fn namespace_change_is_in_json_output() {
    let old = load("old_schema_with_namespaces.json");
    let new = load("new_schema_namespace_changed.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    let json = cmp.to_json_value();
    let cross = json["cross_findings"].as_array().unwrap();
    let has_namespace_changed = cross
        .iter()
        .any(|f| f["kind"].as_str() == Some("namespace_changed"));
    assert!(
        has_namespace_changed,
        "JSON output must include namespace_changed findings"
    );
}

// ── Suppression & policy integration ─────────────────────────────────────────

#[test]
fn cross_schema_findings_apply_to_safety_report() {
    use soroban_upgrade_safeguard::storage_schema::StorageSchema;
    use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};

    let old_wasm =
        std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"))
            .expect("read v1.wasm");
    let new_wasm =
        std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"))
            .expect("read v1.wasm (new)");

    let old_schema = load("old_schema.json");
    let new_schema = load("new_schema_durability_changed.json");

    let opts = CompareOptions {
        storage_schemas: Some((&old_schema, &new_schema)),
        strict: true,
        ..Default::default()
    };
    let report = compare_wasm_bytes_with_options(&old_wasm, &new_wasm, &opts)
        .expect("comparison should succeed");

    // With strict=true and durability changes, the report should be unsafe.
    assert!(
        !report.is_safe(),
        "durability changes with strict=true must produce an unsafe report"
    );

    // At least one finding should be in the "Storage Durability Changed" category.
    let has_category = report
        .findings_by_category()
        .contains_key("Storage Durability Changed");
    assert!(
        has_category,
        "report must include Storage Durability Changed category"
    );
}

#[test]
fn namespace_changes_apply_to_safety_report() {
    use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};

    let wasm = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"))
        .expect("read v1.wasm");

    let old_schema = load("old_schema_with_namespaces.json");
    let new_schema = load("new_schema_namespace_changed.json");

    let opts = CompareOptions {
        storage_schemas: Some((&old_schema, &new_schema)),
        strict: true,
        ..Default::default()
    };
    let report =
        compare_wasm_bytes_with_options(&wasm, &wasm, &opts).expect("comparison should succeed");

    assert!(
        !report.is_safe(),
        "namespace changes with strict=true must produce an unsafe report"
    );

    let has_category = report
        .findings_by_category()
        .contains_key("Storage Namespace Changed");
    assert!(
        has_category,
        "report must include Storage Namespace Changed category"
    );
}

#[test]
fn durability_change_can_be_suppressed() {
    use soroban_upgrade_safeguard::suppression::SuppressionConfig;
    use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};

    let wasm = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"))
        .expect("read v1.wasm");

    let old_schema = load("old_schema.json");
    let new_schema = load("new_schema_durability_changed.json");

    // Build a suppression config that acknowledges the durability change.
    let suppression_toml = r#"
[[suppress]]
category = "Storage Durability Changed"
target   = "counter (persistent → temporary)"
reason   = "Intentional migration to temporary storage in v2."
"#;
    let suppressions: SuppressionConfig =
        toml::from_str(suppression_toml).expect("parse suppression config");

    let opts = CompareOptions {
        storage_schemas: Some((&old_schema, &new_schema)),
        suppressions: Some(&suppressions),
        strict: true,
        ..Default::default()
    };
    let report =
        compare_wasm_bytes_with_options(&wasm, &wasm, &opts).expect("comparison should succeed");

    // The counter finding should be suppressed; others (session, config) are not.
    assert!(
        report.suppressed_count() >= 1,
        "at least the counter durability change should be suppressed"
    );
}

// ── Boundary tests ────────────────────────────────────────────────────────────

#[test]
fn empty_schemas_produce_no_cross_findings() {
    let empty = StorageSchema::default();
    let cmp = compare_storage_schemas(
        &empty,
        &StorageInference::default(),
        &empty,
        &StorageInference::default(),
    );
    assert!(cmp.cross_findings.is_empty());
    assert!(cmp.is_compatible());
}

#[test]
fn declaration_only_in_new_schema_produces_no_cross_finding() {
    // A new declaration that didn't exist before has nothing to compare against.
    let old = StorageSchema::default();
    let new = load("old_schema.json");
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    assert!(
        cmp.cross_findings.is_empty(),
        "new declarations without an old counterpart should not produce cross findings"
    );
}

#[test]
fn declaration_only_in_old_schema_produces_no_cross_finding() {
    // A removed declaration is handled by the reconciliation, not cross-comparison.
    let old = load("old_schema.json");
    let new = StorageSchema::default();
    let cmp = compare_storage_schemas(
        &old,
        &StorageInference::default(),
        &new,
        &StorageInference::default(),
    );
    assert!(
        cmp.cross_findings.is_empty(),
        "old declarations without a new counterpart should not produce cross findings"
    );
}

#[test]
fn schema_with_namespace_parses_from_toml() {
    let toml_input = r#"
[[declarations]]
name = "balance"
operation = "set"
durability = "persistent"
namespace = "v1"
"#;
    let schema = StorageSchema::from_toml(toml_input).expect("parse TOML with namespace");
    assert_eq!(schema.declarations[0].namespace.as_deref(), Some("v1"));
}

// ── Batch manifest test helper ────────────────────────────────────────────────

/// This test is intentionally kept as a library-only coverage check.
/// End-to-end batch manifest testing via the CLI binary is covered in
/// `tests/batch_tests.rs` once the binary is available.
#[test]
fn batch_manifest_with_durability_schemas_smoke() {
    // Verify that two schemas can be compared via compare_storage_schemas
    // with the same call pattern that the batch pipeline uses.
    let old = load("old_schema.json");
    let new = load("new_schema_durability_changed.json");
    let empty_inference = StorageInference::default();

    let cmp = compare_storage_schemas(&old, &empty_inference, &new, &empty_inference);

    // The comparison must surface the durability changes.
    assert!(!cmp.is_compatible());
    assert!(!cmp.cross_findings.is_empty());

    // Verify via JSON that the shape is correct for serialization to batch output.
    let json = cmp.to_json_value();
    assert_eq!(json["compatible"], false);
    let cross = json["cross_findings"].as_array().unwrap();
    assert!(
        cross
            .iter()
            .any(|f| f["kind"].as_str() == Some("durability_changed")),
        "cross_findings must contain a durability_changed entry in batch-compatible JSON"
    );
}
