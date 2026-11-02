//! Integration tests for explicit diagnostics when a WASM file has no
//! `contractspecv0` custom section (#14).

use std::path::{Path, PathBuf};
use std::process::Command;

use soroban_upgrade_safeguard::{compare_wasm_bytes, compare_wasm_files, parser};
use stellar_xdr::curr::{
    Limits, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, StringM, VecM,
    WriteXdr,
};

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

fn fixture_wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn push_leb128(buf: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn minimal_wasm_without_contractspec() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

fn minimal_wasm_with_populated_contractspec_and_no_imports() -> Vec<u8> {
    let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: StringM::default(),
        name: "transfer".try_into().unwrap(),
        inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "amount".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        }])
        .unwrap(),
        outputs: VecM::try_from(vec![ScSpecTypeDef::Bool]).unwrap(),
    });
    let spec_bytes = entry
        .to_xdr(Limits::none())
        .expect("ScSpecEntry XDR encoding must succeed");

    let section_name = b"contractspecv0";
    let mut section_payload = Vec::new();
    push_leb128(&mut section_payload, section_name.len());
    section_payload.extend_from_slice(section_name);
    section_payload.extend_from_slice(&spec_bytes);

    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm.push(0); // custom section id
    push_leb128(&mut wasm, section_payload.len());
    wasm.extend_from_slice(&section_payload);
    wasm
}

struct CliRun {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_cli(args: &[&str]) -> CliRun {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to execute soroban-upgrade-safeguard");
    CliRun {
        stdout: String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr must be UTF-8"),
        code: output.status.code().expect("process terminated by signal"),
    }
}

#[test]
fn missing_vs_missing_warns_with_filenames_and_never_reports_no_changes() {
    let dir = temp_dir("missing-vs-missing");
    let old_path = dir.join("alpha_no_spec.wasm");
    let new_path = dir.join("beta_no_spec.wasm");
    std::fs::write(&old_path, minimal_wasm_without_contractspec()).unwrap();
    std::fs::write(&new_path, minimal_wasm_without_contractspec()).unwrap();

    let old_str = old_path.to_str().unwrap();
    let new_str = new_path.to_str().unwrap();

    // Text output
    let text_run = run_cli(&[old_str, new_str, "--format", "text"]);
    assert_eq!(text_run.code, 0, "stderr:\n{}", text_run.stderr);
    assert!(
        text_run.stderr.contains("alpha_no_spec.wasm")
            && text_run.stderr.contains("beta_no_spec.wasm")
            && text_run.stderr.contains("has no contractspecv0 section"),
        "stderr must warn naming both files, got:\n{}",
        text_run.stderr
    );
    assert!(
        text_run.stdout.contains("alpha_no_spec.wasm")
            && text_run.stdout.contains("beta_no_spec.wasm")
            && text_run.stdout.contains("has a contractspecv0 section"),
        "text report must name both missing-spec files, got:\n{}",
        text_run.stdout
    );
    assert!(
        text_run
            .stdout
            .contains("unavailable (missing contractspecv0 section)"),
        "text report must mark interface unavailable, got:\n{}",
        text_run.stdout
    );
    assert!(
        !text_run.stdout.contains("No relevant changes detected"),
        "text report must never claim no changes when spec is missing, got:\n{}",
        text_run.stdout
    );
    assert!(
        !text_run.stdout.contains("identical interface hash"),
        "text report must not claim identical interface hash when spec is missing, got:\n{}",
        text_run.stdout
    );

    // Markdown output
    let md_run = run_cli(&[old_str, new_str, "--format", "markdown"]);
    assert_eq!(md_run.code, 0, "stderr:\n{}", md_run.stderr);
    assert!(
        md_run.stdout.contains("> **Warning**:")
            && md_run.stdout.contains("alpha_no_spec.wasm")
            && md_run.stdout.contains("beta_no_spec.wasm"),
        "markdown report must surface warning naming both files, got:\n{}",
        md_run.stdout
    );
    assert!(
        md_run
            .stdout
            .contains("`unavailable (missing contractspecv0 section)`"),
        "markdown report must mark interface unavailable, got:\n{}",
        md_run.stdout
    );
    assert!(
        !md_run.stdout.contains("No relevant changes detected"),
        "markdown report must never claim no changes when spec is missing, got:\n{}",
        md_run.stdout
    );

    // JSON output + `render` subcommand round-trip
    let json_run = run_cli(&[old_str, new_str, "--format", "json"]);
    assert_eq!(json_run.code, 0, "stderr:\n{}", json_run.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&json_run.stdout).expect("valid JSON report");
    assert_eq!(parsed["is_safe"], true);
    assert_eq!(parsed["scope"]["exported_interface"], false);
    assert_eq!(parsed["scope"]["old_spec_section_count"], 0);
    assert_eq!(parsed["scope"]["new_spec_section_count"], 0);
    let missing = parsed["scope"]["missing_spec_sources"]
        .as_array()
        .expect("missing_spec_sources must be serialized when non-empty");
    assert_eq!(missing.len(), 2);
    assert!(missing[0].as_str().unwrap().contains("alpha_no_spec.wasm"));
    assert!(missing[1].as_str().unwrap().contains("beta_no_spec.wasm"));

    let saved_report = dir.join("saved_report.json");
    std::fs::write(&saved_report, &json_run.stdout).unwrap();
    let saved_str = saved_report.to_str().unwrap();

    let rendered_text = run_cli(&["render", saved_str, "--format", "text"]);
    assert_eq!(rendered_text.code, 0, "stderr:\n{}", rendered_text.stderr);
    assert!(rendered_text.stdout.contains("alpha_no_spec.wasm"));
    assert!(rendered_text.stdout.contains("beta_no_spec.wasm"));
    assert!(!rendered_text
        .stdout
        .contains("No relevant changes detected"));

    let rendered_md = run_cli(&["render", saved_str, "--format", "markdown"]);
    assert_eq!(rendered_md.code, 0, "stderr:\n{}", rendered_md.stderr);
    assert!(rendered_md.stdout.contains("alpha_no_spec.wasm"));
    assert!(rendered_md.stdout.contains("beta_no_spec.wasm"));
    assert!(!rendered_md.stdout.contains("No relevant changes detected"));

    // `--redact-paths` redacts directory components in `missing_spec_sources`
    let redacted_run = run_cli(&[old_str, new_str, "--format", "json", "--redact-paths"]);
    assert_eq!(redacted_run.code, 0);
    let redacted_json: serde_json::Value = serde_json::from_str(&redacted_run.stdout).unwrap();
    assert_eq!(
        redacted_json["scope"]["missing_spec_sources"],
        serde_json::json!([
            "<redacted>/alpha_no_spec.wasm",
            "<redacted>/beta_no_spec.wasm"
        ])
    );

    // GitHub Actions format emits an explicit `::warning::` annotation
    let gha_run = run_cli(&[old_str, new_str, "--format", "github-actions"]);
    assert_eq!(gha_run.code, 0);
    assert!(
        gha_run
            .stdout
            .contains("::warning::[Missing Contract Spec]")
            && gha_run.stdout.contains("alpha_no_spec.wasm")
            && gha_run.stdout.contains("beta_no_spec.wasm"),
        "github-actions output must emit warning annotation, got:\n{}",
        gha_run.stdout
    );
}

#[test]
fn missing_vs_populated_without_host_imports_fails_and_names_missing_file() {
    let dir = temp_dir("missing-vs-populated");
    let missing_path = dir.join("stripped_contract.wasm");
    let populated_path = dir.join("populated_no_imports.wasm");

    let missing_bytes = minimal_wasm_without_contractspec();
    let populated_bytes = minimal_wasm_with_populated_contractspec_and_no_imports();

    // Confirm our synthetic populated contract genuinely has zero host imports,
    // exercising the exact case where `Host Import Added` cannot catch it.
    let populated_meta = parser::extract_metadata(&populated_bytes).unwrap();
    assert!(populated_meta.host_imports.is_empty());
    assert_eq!(populated_meta.spec_section_count, 1);
    assert_eq!(populated_meta.spec.len(), 1);

    std::fs::write(&missing_path, &missing_bytes).unwrap();
    std::fs::write(&populated_path, &populated_bytes).unwrap();

    let missing_str = missing_path.to_str().unwrap();
    let populated_str = populated_path.to_str().unwrap();

    // Direction 1: missing (old) -> populated (new)
    let forward_text = run_cli(&[missing_str, populated_str, "--format", "text", "--explain"]);
    assert_eq!(
        forward_text.code, 1,
        "missing -> populated without host imports must fail, stdout:\n{}\nstderr:\n{}",
        forward_text.stdout, forward_text.stderr
    );
    assert!(
        forward_text.stderr.contains("stripped_contract.wasm")
            && forward_text
                .stderr
                .contains("has no contractspecv0 section"),
        "stderr must name stripped_contract.wasm, got:\n{}",
        forward_text.stderr
    );
    assert!(
        !forward_text
            .stderr
            .contains("populated_no_imports.wasm' has no contractspecv0"),
        "stderr must not claim populated_no_imports.wasm is missing spec, got:\n{}",
        forward_text.stderr
    );
    assert!(
        forward_text.stdout.contains("FAILED")
            && forward_text.stdout.contains("stripped_contract.wasm")
            && forward_text.stdout.contains("no contractspecv0"),
        "text output must fail and name stripped_contract.wasm, got:\n{}",
        forward_text.stdout
    );

    let forward_json_run = run_cli(&[missing_str, populated_str, "--format", "json"]);
    assert_eq!(forward_json_run.code, 1);
    let forward_json: serde_json::Value = serde_json::from_str(&forward_json_run.stdout).unwrap();
    assert_eq!(forward_json["is_safe"], false);
    assert_eq!(forward_json["axis_verdicts"]["call_abi"], "failed");
    assert_eq!(forward_json["scope"]["exported_interface"], true);
    assert_eq!(forward_json["scope"]["old_spec_section_count"], 0);
    assert_eq!(forward_json["scope"]["new_spec_section_count"], 1);
    let finding = &forward_json["findings_by_category"]["Missing Contract Spec"][0];
    assert_eq!(finding["rule_id"], "missing_contract_spec");
    assert_eq!(finding["severity"], "critical");
    assert!(finding["target"]
        .as_str()
        .unwrap()
        .contains("stripped_contract.wasm"));

    let forward_lib_files = compare_wasm_files(&missing_path, &populated_path).unwrap();
    assert!(!forward_lib_files.is_safe());
    assert!(forward_lib_files.critical_count() >= 1);

    let forward_lib_bytes = compare_wasm_bytes(&missing_bytes, &populated_bytes).unwrap();
    assert!(!forward_lib_bytes.is_safe());
    assert_eq!(
        forward_lib_bytes.scope.missing_spec_sources,
        vec!["old WASM".to_string()]
    );

    // Direction 2: populated (old) -> missing (new)
    let reverse_json_run = run_cli(&[populated_str, missing_str, "--format", "json"]);
    assert_eq!(reverse_json_run.code, 1);
    assert!(
        reverse_json_run.stderr.contains("stripped_contract.wasm")
            && reverse_json_run
                .stderr
                .contains("has no contractspecv0 section"),
        "stderr must name stripped_contract.wasm, got:\n{}",
        reverse_json_run.stderr
    );
    let reverse_json: serde_json::Value = serde_json::from_str(&reverse_json_run.stdout).unwrap();
    assert_eq!(reverse_json["is_safe"], false);
    assert_eq!(reverse_json["scope"]["old_spec_section_count"], 1);
    assert_eq!(reverse_json["scope"]["new_spec_section_count"], 0);
    let rev_finding = &reverse_json["findings_by_category"]["Missing Contract Spec"][0];
    assert_eq!(rev_finding["rule_id"], "missing_contract_spec");
    assert!(rev_finding["target"]
        .as_str()
        .unwrap()
        .contains("stripped_contract.wasm"));

    let reverse_lib_files = compare_wasm_files(&populated_path, &missing_path).unwrap();
    assert!(!reverse_lib_files.is_safe());
    let reverse_lib_bytes = compare_wasm_bytes(&populated_bytes, &missing_bytes).unwrap();
    assert!(!reverse_lib_bytes.is_safe());
    assert_eq!(
        reverse_lib_bytes.scope.missing_spec_sources,
        vec!["new WASM".to_string()]
    );
}

#[test]
fn real_contracts_comparison_is_unaffected() {
    let v1 = fixture_wasm("v1.wasm");
    let v2 = fixture_wasm("v2.wasm");
    let v1_str = Path::new(&v1).to_str().unwrap();
    let v2_str = Path::new(&v2).to_str().unwrap();

    // v1 vs v1 remains safe and continues to emit "No relevant changes detected"
    let same_text = run_cli(&[v1_str, v1_str, "--format", "text"]);
    assert_eq!(same_text.code, 0, "stderr:\n{}", same_text.stderr);
    assert!(!same_text.stderr.contains("has no contractspecv0 section"));
    assert!(same_text.stdout.contains("No relevant changes detected"));
    assert!(same_text
        .stdout
        .contains("unchanged (identical interface hash)"));

    let same_md = run_cli(&[v1_str, v1_str, "--format", "markdown"]);
    assert_eq!(same_md.code, 0);
    assert!(same_md.stdout.contains("No relevant changes detected"));

    let same_json_run = run_cli(&[v1_str, v1_str, "--format", "json"]);
    assert_eq!(same_json_run.code, 0);
    let same_json: serde_json::Value = serde_json::from_str(&same_json_run.stdout).unwrap();
    assert_eq!(same_json["is_safe"], true);
    assert_eq!(same_json["scope"]["exported_interface"], true);
    assert_eq!(same_json["scope"]["old_spec_section_count"], 1);
    assert_eq!(same_json["scope"]["new_spec_section_count"], 1);
    assert!(
        same_json["scope"].get("missing_spec_sources").is_none(),
        "missing_spec_sources must be omitted when empty"
    );

    // v1 vs v2 detects normal breaking changes without spurious missing-spec diagnostics
    let diff_json_run = run_cli(&[v1_str, v2_str, "--format", "json"]);
    assert_eq!(diff_json_run.code, 1);
    assert!(!diff_json_run
        .stderr
        .contains("has no contractspecv0 section"));
    let diff_json: serde_json::Value = serde_json::from_str(&diff_json_run.stdout).unwrap();
    assert_eq!(diff_json["is_safe"], false);
    assert!(diff_json["findings_by_category"]
        .get("Missing Contract Spec")
        .is_none());
}
