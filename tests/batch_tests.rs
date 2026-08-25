use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Helper to write manifest content to a temp file and return its path.
fn write_manifest(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).expect("failed to write manifest file");
    path
}

#[test]
fn batch_manifest_toml_mode_fails_and_exits_one() {
    // Generate a TOML manifest
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_test.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "batch run with breaking contract must exit 1");

    // Assert stdout/stderr output details
    assert!(
        stdout.contains("SOROBAN BATCH SAFETY REPORT"),
        "Missing batch report header"
    );
    assert!(
        stdout.contains("Overall Status: ❌ FAILED"),
        "Missing failed status"
    );
    assert!(
        stdout.contains("clean_contract: ✅ PASSED"),
        "Missing passed contract summary"
    );
    assert!(
        stdout.contains("breaking_contract: ❌ FAILED"),
        "Missing failed contract summary"
    );

    // Progress messages go to stdout in default text mode.
    assert!(
        stdout.contains("Loaded 2 pair(s) for comparison."),
        "Missing loading message"
    );
    assert!(
        stdout.contains("Comparing contract pair: clean_contract"),
        "Missing clean contract progress"
    );
    assert!(
        stdout.contains("Comparing contract pair: breaking_contract"),
        "Missing breaking contract progress"
    );
}

#[test]
fn batch_manifest_all_clean_exits_zero() {
    // Generate a TOML manifest with all clean pairs
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_1"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_2"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_clean.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 0, "batch run with all clean contracts must exit 0");
    assert!(
        stdout.contains("Overall Status: ✅ PASSED"),
        "Missing passed status"
    );
}

#[test]
fn batch_manifest_json_mode_json_output() {
    // Generate a JSON manifest
    let manifest_content = format!(
        r#"{{
            "pairs": [
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "clean_json"
                }},
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "breaking_json"
                }}
            ]
        }}"#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_test.json", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "batch run with breaking contract must exit 1");

    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 2);

    // Check results object
    let results = json["results"]
        .as_object()
        .expect("results must be an object");
    assert!(results.contains_key("clean_json"));
    assert!(results.contains_key("breaking_json"));

    assert_eq!(results["clean_json"]["is_safe"], Value::Bool(true));
    assert_eq!(results["breaking_json"]["is_safe"], Value::Bool(false));
}

#[test]
fn batch_json_overall_recommended_bump_is_the_most_severe_pair() {
    // Three pairs that individually recommend patch, minor, and major
    // respectively. The batch-level bump must be "major", the most severe
    // of the three, even though it appears last in the manifest.
    let manifest_content = format!(
        r#"{{
            "pairs": [
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "patch_pair"
                }},
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "minor_pair"
                }},
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "major_pair"
                }}
            ]
        }}"#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v3.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_bump_disagreement.json", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    let results = json["results"]
        .as_object()
        .expect("results must be an object");
    assert_eq!(results["patch_pair"]["recommended_bump"], "patch");
    assert_eq!(results["minor_pair"]["recommended_bump"], "minor");
    assert_eq!(results["major_pair"]["recommended_bump"], "major");

    assert_eq!(
        json["recommended_bump"], "major",
        "batch-level bump must be the most severe across all pairs"
    );
}

#[test]
fn batch_directory_scanning_fails_on_breaking_contract() {
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dir_test");
    let old_dir = tmp_dir.join("old");
    let new_dir = tmp_dir.join("new");

    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    // Copy fixtures:
    // a.wasm: clean (v1 -> v1)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.wasm")).expect("copy");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.wasm")).expect("copy");

    // b.wasm: breaking (v1 -> v2)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("b.wasm")).expect("copy");
    std::fs::copy(wasm("v2.wasm"), new_dir.join("b.wasm")).expect("copy");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1);
    assert!(stdout.contains("Overall Status: ❌ FAILED"));
    assert!(stdout.contains("a: ✅ PASSED"));
    assert!(stdout.contains("b: ❌ FAILED"));
}

#[test]
fn batch_conflicting_options_exit_with_error() {
    // 1. Both manifest and old-dir/new-dir
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            "dummy.toml",
            "--old-dir",
            "dummy_old",
            "--new-dir",
            "dummy_new",
        ])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "conflicting batch options must fail"
    );

    // 2. Positional args + manifest
    let output2 = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--manifest", "dummy.toml"])
        .output()
        .expect("failed to run binary");

    assert!(
        !output2.status.success(),
        "positional args + manifest must fail"
    );
}

#[test]
fn malformed_toml_manifest_surfaces_toml_error_detail() {
    // A .toml file with a deliberate syntax error (missing closing bracket).
    let bad_toml = r#"
[[pairs]
old = "v1.wasm"
new = "v2.wasm"
"#;
    let manifest_path = write_manifest("bad_manifest.toml", bad_toml);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_ne!(code, 0, "malformed TOML manifest must exit non-zero");
    // The TOML parser's own diagnostic must appear in the error chain.
    assert!(
        stderr.contains("TOML") || stderr.contains("toml") || stderr.contains("expected"),
        "Error output should contain the TOML parser's diagnostic, got: {stderr}"
    );
    // Must NOT fall through to the generic "as either TOML or JSON" message.
    assert!(
        !stderr.contains("as either TOML or JSON"),
        "Should not show generic both-format error for a .toml file, got: {stderr}"
    );
}

#[test]
fn malformed_json_manifest_surfaces_json_error_detail() {
    // A .json file with a deliberate syntax error (trailing comma).
    let bad_json = r#"{
  "pairs": [
    {
      "old": "v1.wasm",
      "new": "v2.wasm",
    }
  ]
}"#;
    let manifest_path = write_manifest("bad_manifest.json", bad_json);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_ne!(code, 0, "malformed JSON manifest must exit non-zero");
    // The JSON parser's own diagnostic (line/column) must appear.
    assert!(
        stderr.contains("JSON") || stderr.contains("json") || stderr.contains("line"),
        "Error output should contain the JSON parser's diagnostic, got: {stderr}"
    );
    // Must NOT fall through to the generic "as either TOML or JSON" message.
    assert!(
        !stderr.contains("as either TOML or JSON"),
        "Should not show generic both-format error for a .json file, got: {stderr}"
    );
}

#[test]
fn unknown_extension_manifest_shows_both_errors() {
    // A file with no recognised extension that is invalid in both formats.
    let garbage = "this is not toml or json @@@###";
    let manifest_path = write_manifest("bad_manifest.cfg", garbage);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_ne!(code, 0, "unrecognised-extension invalid manifest must exit non-zero");
    // Both parser errors should appear when the extension gives no hint.
    assert!(
        stderr.contains("TOML error") || stderr.contains("toml error"),
        "Should mention TOML error for unknown extension, got: {stderr}"
    );
    assert!(
        stderr.contains("JSON error") || stderr.contains("json error"),
        "Should mention JSON error for unknown extension, got: {stderr}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-contract dependency tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn direct_dependency_propagates_breaking_change() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[dependencies]]
        caller = "pool"
        callee = "token"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_direct.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["results"]["token"]["is_safe"], Value::Bool(false));
    assert_eq!(json["results"]["pool"]["is_safe"], Value::Bool(true));

    let cross_findings = json["cross_contract_findings"]["pool"]
        .as_array()
        .expect("pool must have cross-contract findings");
    assert!(!cross_findings.is_empty(), "pool must receive propagated findings from token");
    assert_eq!(cross_findings[0]["propagation_depth"], 1);
    assert_eq!(cross_findings[0]["changed_contract"], "token");
    assert_eq!(cross_findings[0]["affected_contract"], "pool");

    let code = output.status.code().expect("process terminated by signal");
    assert_eq!(code, 1);
}

#[test]
fn transitive_dependency_propagates_breaking_change() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "router"

        [[dependencies]]
        caller = "pool"
        callee = "token"

        [[dependencies]]
        caller = "router"
        callee = "pool"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_transitive.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["is_safe"], Value::Bool(false));

    let pool_cross = json["cross_contract_findings"]["pool"]
        .as_array()
        .expect("pool must have findings");
    let router_cross = json["cross_contract_findings"]["router"]
        .as_array()
        .expect("router must have findings");

    assert!(!pool_cross.is_empty(), "pool directly depends on token");
    assert!(!router_cross.is_empty(), "router transitively depends on token via pool");
    assert_eq!(pool_cross[0]["propagation_depth"], 1);
    assert_eq!(router_cross[0]["propagation_depth"], 2);
    assert_eq!(pool_cross[0]["changed_contract"], "token");
    assert_eq!(router_cross[0]["changed_contract"], "token");
}

#[test]
fn cyclic_dependency_terminates_and_reports() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "contract_a"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "contract_b"

        [[dependencies]]
        caller = "contract_a"
        callee = "contract_b"

        [[dependencies]]
        caller = "contract_b"
        callee = "contract_a"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_cyclic.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["is_safe"], Value::Bool(false));

    let dep_findings = json["dependency_findings"]
        .as_array()
        .expect("must have dependency findings");
    let cycle_finding = dep_findings.iter().find(|f| f["category"] == "Cyclic Contract Dependency");
    assert!(cycle_finding.is_some(), "must report the cycle");

    let cross_a = json["cross_contract_findings"]["contract_a"].as_array();
    let cross_b = json["cross_contract_findings"]["contract_b"].as_array();
    let total_cross = cross_a.map(|a| a.len()).unwrap_or(0)
        + cross_b.map(|b| b.len()).unwrap_or(0);
    assert!(total_cross > 0, "cycle must propagate findings");
    assert!(total_cross < 100, "cycle must not produce unbounded findings");
}

#[test]
fn missing_dependency_contract_reported() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[dependencies]]
        caller = "pool"
        callee = "oracle"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_missing.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["is_safe"], Value::Bool(false));

    let dep_findings = json["dependency_findings"]
        .as_array()
        .expect("must have dependency findings");
    let missing_finding = dep_findings.iter().find(|f| {
        f["category"] == "Missing Dependency Contract"
            && f["message"].as_str().unwrap_or("").contains("oracle")
    });
    assert!(missing_finding.is_some(), "must report missing oracle contract");
    assert_eq!(missing_finding.unwrap()["severity"], "warning");
}

#[test]
fn no_dependencies_means_no_cross_contract_findings() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_none.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["results"]["token"]["is_safe"], Value::Bool(false));
    assert_eq!(json["results"]["pool"]["is_safe"], Value::Bool(true));

    let cross_findings_obj = json["cross_contract_findings"].as_object();
    if let Some(obj) = cross_findings_obj {
        let pool_findings = obj.get("pool").and_then(|v| v.as_array());
        assert!(
            pool_findings.map(|a| a.is_empty()).unwrap_or(true),
            "pool has no dependencies so should have no cross-contract findings"
        );
    }
}

#[test]
fn text_output_displays_cross_contract_findings() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[dependencies]]
        caller = "pool"
        callee = "token"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_text.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap()])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(
        stdout.contains("Cross-Contract") || stdout.contains("cross-contract"),
        "text output must mention cross-contract findings"
    );
    assert!(
        stdout.contains("pool") && stdout.contains("token"),
        "text output must name both contracts"
    );
}

#[test]
fn markdown_output_includes_cross_contract_table() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[dependencies]]
        caller = "pool"
        callee = "token"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_md.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "markdown"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(
        stdout.contains("Cross-Contract") || stdout.contains("Dependency"),
        "markdown must have cross-contract section"
    );
    assert!(
        stdout.contains("|") && (stdout.contains("Affected") || stdout.contains("Changed")),
        "markdown must have a table with affected/changed columns"
    );
}

#[test]
fn strict_mode_fails_on_cross_contract_warnings() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "pool"

        [[dependencies]]
        caller = "pool"
        callee = "token"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("cross_contract_strict.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--format",
            "json",
            "--strict",
        ])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(json["strict"], Value::Bool(true));
    assert_eq!(json["is_safe"], Value::Bool(false));
}

// ─────────────────────────────────────────────────────────────────────────────
// Name-collision tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn duplicate_explicit_names_in_manifest_are_rejected() {
    // Two entries both named "token" — user wrote it deliberately, must error.
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "token"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("dup_explicit_names.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap()])
        .output()
        .expect("failed to run binary");

    // Must exit non-zero
    assert!(
        !output.status.success(),
        "duplicate explicit names must cause a non-zero exit"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    // Error message must name the duplicate
    assert!(
        stderr.contains("token") || stderr.contains("same explicit name"),
        "error must mention the duplicate name, got: {stderr}"
    );
}

#[test]
fn duplicate_derived_names_both_appear_in_json_output() {
    // Two pairs that both derive the name "v1" from the new WASM basename —
    // one clean (v1->v1), one breaking (v1->v2). Both must appear in results.
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(), // derived name: "v1"
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(), // also derived name: "v1" — collision
    );

    let manifest_path = write_manifest("dup_derived_names.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    let results = json["results"].as_object().expect("results must be an object");

    // Both pairs must appear — neither should silently overwrite the other
    assert_eq!(
        results.len(),
        2,
        "both pairs must appear in results, got keys: {:?}",
        results.keys().collect::<Vec<_>>()
    );

    // One entry must be "v1", the other "v1 (2)"
    assert!(results.contains_key("v1"), "first occurrence must be keyed as 'v1'");
    assert!(
        results.contains_key("v1 (2)"),
        "second occurrence must be keyed as 'v1 (2)', got keys: {:?}",
        results.keys().collect::<Vec<_>>()
    );
}

#[test]
fn duplicate_derived_names_both_appear_in_text_output() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("dup_derived_names_text.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap()])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    // Both keys must appear somewhere in the text report
    assert!(stdout.contains("v1"), "first pair must appear in text output");
    assert!(
        stdout.contains("v1 (2)"),
        "second pair must appear as 'v1 (2)' in text output"
    );
}

#[test]
fn total_pairs_matches_reported_results_count_with_collisions() {
    // Two pairs with derived-name collision — total_pairs must equal the number
    // of entries actually reported (2), not exceed it.
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("total_pairs_collision.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    let total_pairs = json["total_pairs"].as_u64().expect("total_pairs must be a number");
    let results_count = json["results"]
        .as_object()
        .expect("results must be an object")
        .len() as u64;
    let failed_count = json["failed"]
        .as_object()
        .expect("failed must be an object")
        .len() as u64;

    assert_eq!(
        total_pairs,
        results_count + failed_count,
        "total_pairs ({}) must equal results ({}) + failed ({})",
        total_pairs,
        results_count,
        failed_count
    );
}

#[test]
fn directory_scan_duplicate_basenames_both_appear() {
    // Create two subdirectory pairs that both have a file named token.wasm —
    // the canonical duplicate-basename scenario for directory scans.
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dup_basename_scan");
    let old_a = tmp.join("old_a");
    let new_a = tmp.join("new_a");
    let old_b = tmp.join("old_b");
    let new_b = tmp.join("new_b");

    for dir in [&old_a, &new_a, &old_b, &new_b] {
        std::fs::create_dir_all(dir).expect("create dir");
    }

    // Pair A: token.wasm clean (v1 → v1)
    std::fs::copy(wasm("v1.wasm"), old_a.join("token.wasm")).expect("copy");
    std::fs::copy(wasm("v1.wasm"), new_a.join("token.wasm")).expect("copy");

    // Pair B: token.wasm breaking (v1 → v2) — same basename in different dirs
    std::fs::copy(wasm("v1.wasm"), old_b.join("token.wasm")).expect("copy");
    std::fs::copy(wasm("v2.wasm"), new_b.join("token.wasm")).expect("copy");

    // Run pair A
    let out_a = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--old-dir", old_a.to_str().unwrap(),
            "--new-dir", new_a.to_str().unwrap(),
            "--format", "json",
        ])
        .output()
        .expect("failed to run binary");

    // Run pair B
    let out_b = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--old-dir", old_b.to_str().unwrap(),
            "--new-dir", new_b.to_str().unwrap(),
            "--format", "json",
        ])
        .output()
        .expect("failed to run binary");

    let json_a: Value = serde_json::from_str(
        &String::from_utf8(out_a.stdout).expect("utf8"),
    ).expect("valid JSON from pair A");
    let json_b: Value = serde_json::from_str(
        &String::from_utf8(out_b.stdout).expect("utf8"),
    ).expect("valid JSON from pair B");

    // Each individual dir-scan run has exactly one pair and one result
    assert_eq!(
        json_a["results"].as_object().unwrap().len(),
        1,
        "pair A must produce exactly one result"
    );
    assert_eq!(
        json_b["results"].as_object().unwrap().len(),
        1,
        "pair B must produce exactly one result"
    );

    // Pair A is clean, pair B breaks
    let a_key = json_a["results"].as_object().unwrap().keys().next().unwrap().clone();
    let b_key = json_b["results"].as_object().unwrap().keys().next().unwrap().clone();
    assert_eq!(json_a["results"][&a_key]["is_safe"], Value::Bool(true));
    assert_eq!(json_b["results"][&b_key]["is_safe"], Value::Bool(false));
}

#[test]
fn manifest_with_three_colliding_derived_names_disambiguates_all() {
    // Three pairs all deriving "v1" — must produce "v1", "v1 (2)", "v1 (3)".
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    );

    let manifest_path = write_manifest("triple_collision.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    let results = json["results"].as_object().expect("results must be an object");
    assert_eq!(results.len(), 3, "all three pairs must appear");
    assert!(results.contains_key("v1"), "first must be 'v1'");
    assert!(results.contains_key("v1 (2)"), "second must be 'v1 (2)'");
    assert!(results.contains_key("v1 (3)"), "third must be 'v1 (3)'");

    // total_pairs must equal the number of results
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// Case-insensitive extension tests (#179)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn directory_scan_matches_uppercase_wasm_extension() {
    // Verifies that files named *.WASM (uppercase) are collected the same as
    // *.wasm.  Before the fix, collect_wasm_files did a case-sensitive compare
    // and silently skipped uppercase extensions, reporting "No matching .wasm
    // contract pairs found" even when the directories were correct.
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("uppercase_ext_test");
    let old_dir = tmp.join("old");
    let new_dir = tmp.join("new");

    std::fs::create_dir_all(&old_dir).expect("create old dir");
    std::fs::create_dir_all(&new_dir).expect("create new dir");

    // Copy fixtures using an all-uppercase extension.
    std::fs::copy(wasm("v1.wasm"), old_dir.join("token.WASM")).expect("copy old");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("token.WASM")).expect("copy new");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    // The pair must be discovered — a "no matching pairs" error would mean the
    // extension was still being skipped.
    assert!(
        !stderr.contains("No matching .wasm contract pairs found"),
        "uppercase .WASM files must not be silently skipped, stderr: {stderr}"
    );

    // The run must exit cleanly (v1 → v1 is a safe upgrade).
    assert_eq!(code, 0, "clean v1→v1 pair with .WASM extension must exit 0");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");

    let results = json["results"].as_object().expect("results must be an object");
    assert_eq!(
        results.len(),
        1,
        "exactly one pair must be found for the uppercase .WASM files"
    );
    let result_key = results.keys().next().unwrap();
    assert_eq!(
        json["results"][result_key]["is_safe"],
        serde_json::Value::Bool(true),
        "clean v1→v1 pair must be safe"
    );
}

#[test]
fn directory_scan_mixed_case_extension_is_matched() {
    // Also covers mixed-case extensions such as .Wasm — any capitalisation must
    // be accepted alongside canonical .wasm files in the same directory.
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mixedcase_ext_test");
    let old_dir = tmp.join("old");
    let new_dir = tmp.join("new");

    std::fs::create_dir_all(&old_dir).expect("create old dir");
    std::fs::create_dir_all(&new_dir).expect("create new dir");

    // One canonical lowercase file and one mixed-case file in the same dirs.
    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.wasm")).expect("copy a old");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.wasm")).expect("copy a new");
    std::fs::copy(wasm("v1.wasm"), old_dir.join("b.Wasm")).expect("copy b old");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("b.Wasm")).expect("copy b new");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 0, "two clean pairs (mixed extensions) must exit 0");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");

    let results = json["results"].as_object().expect("results must be an object");
    assert_eq!(
        results.len(),
        2,
        "both .wasm and .Wasm files must be collected; got keys: {:?}",
        results.keys().collect::<Vec<_>>()
    );
}
