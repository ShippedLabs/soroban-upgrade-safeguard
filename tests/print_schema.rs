// SPDX-License-Identifier: MIT

//! `print-schema` acceptance tests: the subcommand prints the JSON Schema for
//! the `--format json` report to stdout, requires no WASM inputs, and matches
//! the schema version the running binary writes into real reports.

use std::process::Command;

fn run_print_schema(extra_args: &[&str]) -> (String, String, Option<i32>) {
    let bin = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");
    let output = Command::new(bin)
        .args(["print-schema"])
        .args(extra_args)
        .output()
        .expect("failed to run print-schema");
    (
        String::from_utf8(output.stdout).expect("stdout is utf-8"),
        String::from_utf8(output.stderr).expect("stderr is utf-8"),
        output.status.code(),
    )
}

/// The subcommand runs with no WASM inputs, exits 0, and prints a valid JSON
/// Schema document.
#[test]
fn prints_a_valid_json_schema_with_no_inputs() {
    let (stdout, stderr, code) = run_print_schema(&[]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let schema: serde_json::Value =
        serde_json::from_str(&stdout).expect("print-schema output is valid JSON");

    let obj = schema.as_object().expect("schema is a JSON object");
    assert_eq!(
        obj.get("$schema").and_then(|v| v.as_str()),
        Some("http://json-schema.org/draft-07/schema#"),
        "output must identify itself as JSON Schema"
    );
    let props = obj
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("schema has top-level properties");
    for field in [
        "report_schema_version",
        "provenance",
        "is_safe",
        "counts",
        "findings_by_category",
    ] {
        assert!(props.contains_key(field), "schema is missing `{field}`");
    }
}

/// The schema describes the same shape version the binary embeds in reports.
/// A consumer fetching the schema from the running binary can validate the
/// report that same binary produces.
#[test]
fn schema_version_matches_the_report_shape_version() {
    let (stdout, stderr, code) = run_print_schema(&[]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let schema: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let version = schema
        .get("properties")
        .and_then(|p| p.get("report_schema_version"))
        .and_then(|v| v.get("default"))
        .and_then(|v| v.as_u64())
        .expect("report_schema_version property carries a default (the current version)");
    assert_eq!(
        version, 1,
        "bump this expectation with REPORT_SCHEMA_VERSION"
    );
}

/// The current `--format json` output validates against the schema this
/// binary prints. Both come from the same `serde` types, so the two must
/// never disagree.
#[test]
fn a_live_report_validates_against_the_printed_schema() {
    let dir = tempfile_dir();
    let old_wasm = dir.join("old.wasm");
    let new_wasm = dir.join("new.wasm");
    write_minimal_wasm(&old_wasm);
    std::fs::copy(&old_wasm, &new_wasm).expect("copy fixture");

    let bin = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");
    let run = Command::new(bin)
        .args([
            old_wasm.to_str().unwrap(),
            new_wasm.to_str().unwrap(),
            "--format",
            "json",
            "--no-timestamp",
        ])
        .env_remove("NO_COLOR")
        .output()
        .expect("comparison run");
    let stderr = String::from_utf8_lossy(&run.stderr).to_string();
    assert!(
        run.status.success() || run.status.code() == Some(1),
        "comparison failed unexpectedly: {stderr}"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&run.stdout).expect("report is valid JSON");

    let (schema_stdout, schema_stderr, code) = run_print_schema(&[]);
    assert_eq!(code, Some(0), "stderr: {schema_stderr}");

    let verdict = validate_draft07(&report, &schema_stdout);
    assert!(
        verdict.is_empty(),
        "live report does not satisfy the printed schema:\n{}",
        verdict.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--compact` prints the same document on one line.
#[test]
fn compact_flag_produces_a_single_line() {
    let (stdout, stderr, code) = run_print_schema(&["--compact"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("compact output is JSON");
    assert!(
        !stdout.trim_end().contains('\n'),
        "--compact output must be a single line (trailing newline aside)"
    );
    assert!(parsed.get("$schema").is_some());
}

// --- helpers ---------------------------------------------------------------

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("print-schema-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Write the smallest valid contract WASM: an empty module that exports
/// nothing. The tool must still produce a complete report for it.
fn write_minimal_wasm(path: &std::path::Path) {
    use std::io::Write;
    // Empty module header + version; every Soroban contract starts here.
    let wasm: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // \0asm
        0x01, 0x00, 0x00, 0x00, // version 1
    ];
    let mut f = std::fs::File::create(path).expect("create wasm fixture");
    f.write_all(wasm).expect("write wasm fixture");
}

/// Minimal recursive JSON Schema (draft-07) validator over `serde_json`
/// values — enough to check the properties the schema constrains without
/// adding a validator dependency to the build.
fn validate_draft07(instance: &serde_json::Value, schema_text: &str) -> Vec<String> {
    let schema: serde_json::Value = serde_json::from_str(schema_text).expect("schema is JSON");
    let mut errors = Vec::new();
    let root = schema.as_object().expect("schema root is an object");
    validate_object(instance, root, &schema, "$", &mut errors);
    errors
}

fn validate_object(
    instance: &serde_json::Value,
    schema_obj: &serde_json::Map<String, serde_json::Value>,
    root_schema: &serde_json::Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    // Resolve local $ref against $defs when present.
    if let Some(reference) = schema_obj.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(reference, root_schema) {
            if let Some(resolved_obj) = resolved.as_object() {
                validate_object(instance, resolved_obj, root_schema, path, errors);
            }
            return;
        }
    }
    if let Some(required) = schema_obj.get("required").and_then(|v| v.as_array()) {
        for field in required.iter().filter_map(|f| f.as_str()) {
            if instance.get(field).is_none() {
                errors.push(format!("{path}: missing required property `{field}`"));
            }
        }
    }
    if let Some(properties) = schema_obj.get("properties").and_then(|v| v.as_object()) {
        for (field, field_schema) in properties {
            if let Some(value) = instance.get(field) {
                validate_value(
                    value,
                    field_schema,
                    root_schema,
                    &format!("{path}.{field}"),
                    errors,
                );
            }
        }
    }
}

fn validate_value(
    instance: &serde_json::Value,
    schema: &serde_json::Value,
    root_schema: &serde_json::Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(schema_obj) = schema.as_object() else {
        return;
    };
    if let Some(reference) = schema_obj.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(reference, root_schema) {
            validate_value(instance, resolved, root_schema, path, errors);
            return;
        }
    }
    // anyOf: at least one branch must match. Used for conditionally-shaped
    // fields; checking required-keys of each branch is enough for this test.
    if let Some(any_of) = schema_obj.get("anyOf").and_then(|v| v.as_array()) {
        let matched = any_of.iter().any(|branch| {
            let mut branch_errors = Vec::new();
            validate_value(instance, branch, root_schema, path, &mut branch_errors);
            branch_errors.is_empty()
        });
        if !matched {
            errors.push(format!("{path}: value matches none of anyOf"));
        }
        return;
    }
    match instance {
        serde_json::Value::Object(map) => {
            validate_object(
                &serde_json::Value::Object(map.clone()),
                schema_obj,
                root_schema,
                path,
                errors,
            );
            if let Some(additional) = schema_obj.get("additionalProperties") {
                if additional == &serde_json::json!(false) {
                    if let Some(properties) =
                        schema_obj.get("properties").and_then(|v| v.as_object())
                    {
                        for key in map.keys() {
                            if !properties.contains_key(key) {
                                errors.push(format!("{path}: unexpected property `{key}`"));
                            }
                        }
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            if let Some(item_schema) = schema_obj.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_value(
                        item,
                        item_schema,
                        root_schema,
                        &format!("{path}[{index}]"),
                        errors,
                    );
                }
            }
        }
        serde_json::Value::String(text) => {
            if let Some(enum_values) = schema_obj.get("enum").and_then(|v| v.as_array()) {
                if !enum_values.contains(&serde_json::Value::String(text.clone())) {
                    errors.push(format!("{path}: `{text}` is not one of {enum_values:?}"));
                }
            }
        }
        _ => {}
    }
}

fn resolve_ref<'a>(reference: &str, root: &'a serde_json::Value) -> Option<&'a serde_json::Value> {
    let local = reference.strip_prefix("#/")?;
    let mut current = root;
    for segment in local.split('/') {
        current = current.get(segment)?;
    }
    Some(current)
}
