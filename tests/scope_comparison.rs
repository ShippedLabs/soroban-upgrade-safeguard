//! Integration and library tests for `--scope` / `ComparisonScope` (#261).

use serde_json::Value;
use soroban_upgrade_safeguard::{
    compare_wasm_bytes_with_options, CompareOptions, ComparisonScope, ScopeArea,
};
use std::path::PathBuf;
use std::process::Command;
use stellar_xdr::curr::{
    Limits, ScEnvMetaEntry, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSymbol, StringM, VecM, WriteXdr,
};

fn uleb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn wasm_string(s: &str) -> Vec<u8> {
    let mut out = uleb(s.len() as u32);
    out.extend_from_slice(s.as_bytes());
    out
}

fn wasm_section(id: u8, body: Vec<u8>) -> Vec<u8> {
    let mut section = vec![id];
    section.extend(uleb(body.len() as u32));
    section.extend(body);
    section
}

fn wasm_custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = wasm_string(name);
    body.extend_from_slice(payload);
    wasm_section(0x00, body)
}

fn build_soroban_wasm_with_max_mem(
    protocol: u32,
    max_mem_pages: u32,
    entries: &[ScSpecEntry],
) -> Vec<u8> {
    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

    // Memory section (id = 5): 1 memory with limits [1, max_mem_pages].
    let mut mem_body = uleb(1);
    mem_body.push(0x01); // has maximum
    mem_body.extend(uleb(1));
    mem_body.extend(uleb(max_mem_pages));
    wasm.extend(wasm_section(0x05, mem_body));

    let env_entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion((protocol as u64) << 32);
    let env_bytes = env_entry.to_xdr(Limits::none()).unwrap();
    wasm.extend(wasm_custom_section("contractenvmetav0", &env_bytes));

    let mut spec_bytes = Vec::new();
    for entry in entries {
        spec_bytes.extend(entry.to_xdr(Limits::none()).unwrap());
    }
    wasm.extend(wasm_custom_section("contractspecv0", &spec_bytes));
    wasm
}

fn build_soroban_wasm(protocol: u32, entries: &[ScSpecEntry]) -> Vec<u8> {
    build_soroban_wasm_with_max_mem(protocol, 16, entries)
}

fn sym(s: &str) -> ScSymbol {
    s.try_into().unwrap()
}

fn str_m<const N: u32>(s: &str) -> StringM<N> {
    s.try_into().unwrap()
}

fn vec_m<T: Clone, const N: u32>(items: Vec<T>) -> VecM<T, N> {
    items.try_into().unwrap()
}

fn fn_entry(name: &str, inputs: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
    let params = inputs
        .iter()
        .map(|(n, ty)| ScSpecFunctionInputV0 {
            doc: str_m(""),
            name: str_m(n),
            type_: ty.clone(),
        })
        .collect();
    ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: str_m(""),
        name: sym(name),
        inputs: vec_m(params),
        outputs: vec_m(vec![]),
    })
}

fn struct_entry(name: &str, fields: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
    let f = fields
        .iter()
        .map(|(n, ty)| ScSpecUdtStructFieldV0 {
            doc: str_m(""),
            name: str_m(n),
            type_: ty.clone(),
        })
        .collect();
    ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: str_m(""),
        lib: str_m(""),
        name: str_m(name),
        fields: vec_m(f),
    })
}

fn event_entry(name: &str, fields: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
    assert!(
        name.to_ascii_lowercase().contains("event"),
        "event struct fixture name must contain 'event'"
    );
    struct_entry(name, fields)
}

fn error_enum_entry(name: &str, cases: &[(&str, u32)]) -> ScSpecEntry {
    let c = cases
        .iter()
        .map(|(n, val)| ScSpecUdtErrorEnumCaseV0 {
            doc: str_m(""),
            name: str_m(n),
            value: *val,
        })
        .collect();
    ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
        doc: str_m(""),
        lib: str_m(""),
        name: str_m(name),
        cases: vec_m(c),
    })
}

fn write_tmp_bytes(name: &str, bytes: &[u8]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to execute binary");
    (
        out.status.code().expect("terminated by signal"),
        String::from_utf8(out.stdout).expect("invalid utf8 stdout"),
        String::from_utf8(out.stderr).expect("invalid utf8 stderr"),
    )
}

#[test]
fn scope_parsing_covers_all_areas_aliases_and_errors() {
    let empty: [&str; 0] = [];
    let default_scope = ComparisonScope::from_cli_tokens(&empty).unwrap();
    assert!(default_scope.is_full());
    assert!(default_scope.excluded_areas().is_empty());
    assert_eq!(
        default_scope.included_names(),
        vec!["functions", "types", "events", "errors", "env"]
    );

    let explicit_all = ComparisonScope::from_cli_tokens(&["ALL".to_string()]).unwrap();
    assert_eq!(default_scope, explicit_all);

    let aliased = ComparisonScope::from_cli_tokens(&[
        "storage".to_string(),
        "error-enums,environment".to_string(),
    ])
    .unwrap();
    assert!(!aliased.is_full());
    assert!(aliased.includes(ScopeArea::Types));
    assert!(aliased.includes(ScopeArea::Errors));
    assert!(aliased.includes(ScopeArea::Env));
    assert!(!aliased.includes(ScopeArea::Functions));
    assert!(!aliased.includes(ScopeArea::Events));
    assert_eq!(aliased.included_names(), vec!["types", "errors", "env"]);
    assert_eq!(aliased.excluded_names(), vec!["functions", "events"]);

    let err_unknown = ComparisonScope::from_cli_tokens(&["bogus".to_string()]).unwrap_err();
    assert!(
        err_unknown.contains("Unknown comparison scope 'bogus'"),
        "{err_unknown}"
    );
    assert!(err_unknown.contains("functions"), "{err_unknown}");

    let err_mixed_all =
        ComparisonScope::from_cli_tokens(&["all,functions".to_string()]).unwrap_err();
    assert!(err_mixed_all.contains("Cannot combine"), "{err_mixed_all}");
}

#[test]
fn multi_area_breaking_upgrade_isolates_each_scope_area() {
    let old_entries = vec![
        fn_entry("transfer", &[("amount", ScSpecTypeDef::I128)]),
        struct_entry(
            "AccountState",
            &[
                ("owner", ScSpecTypeDef::Address),
                ("balance", ScSpecTypeDef::I128),
            ],
        ),
        event_entry("TransferEvent", &[("amount", ScSpecTypeDef::I128)]),
        error_enum_entry("ContractErr", &[("Unauthorized", 1), ("Paused", 2)]),
    ];
    // Break all 5 areas in the candidate:
    // 1. Function `transfer` removed ("Function Removed")
    // 2. Struct `AccountState` drops field `balance` ("Struct Field Removed")
    // 3. Event `TransferEvent` removed ("Event Definition Removed")
    // 4. Error enum `ContractErr` drops variant `Paused` ("Error Enum Case Removed")
    // 5. Protocol downgraded 21 -> 20 ("Environment") + max memory lowered 16 -> 8 ("Memory Limits Changed")
    let new_entries = vec![
        struct_entry("AccountState", &[("owner", ScSpecTypeDef::Address)]),
        error_enum_entry("ContractErr", &[("Unauthorized", 1)]),
    ];

    let old_wasm = build_soroban_wasm_with_max_mem(21, 16, &old_entries);
    let new_wasm = build_soroban_wasm_with_max_mem(20, 8, &new_entries);
    let old_path = write_tmp_bytes("multi/old.wasm", &old_wasm);
    let new_path = write_tmp_bytes("multi/new.wasm", &new_wasm);
    let old_s = old_path.to_str().unwrap();
    let new_s = new_path.to_str().unwrap();

    let all_cats = [
        "Function Removed",
        "Struct Field Removed",
        "Event Definition Removed",
        "Error Enum Case Removed",
        "Environment",
        "Memory Limits Changed",
    ];

    // Unscoped run catches all 5 areas and omits scoped metadata keys.
    let (code_full, out_full, _) = run_cli(&[old_s, new_s, "--format", "json", "--no-timestamp"]);
    assert_eq!(code_full, 1);
    let json_full: Value = serde_json::from_str(&out_full).unwrap();
    for cat in all_cats {
        assert!(
            json_full["findings_by_category"][cat].is_array(),
            "unscoped run should report '{cat}', got: {json_full}"
        );
    }
    assert!(json_full["scope"].get("included_areas").is_none());
    assert!(json_full["scope"].get("excluded_areas").is_none());

    // `--scope all` matches unscoped behavior.
    let (code_all, out_all, _) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "all",
        "--format",
        "json",
        "--no-timestamp",
    ]);
    assert_eq!(code_all, 1);
    let json_all: Value = serde_json::from_str(&out_all).unwrap();
    assert_eq!(
        json_full["findings_by_category"],
        json_all["findings_by_category"]
    );
    assert!(json_all["scope"].get("included_areas").is_none());

    // Check each single area in isolation.
    let cases: &[(&str, &[&str])] = &[
        ("functions", &["Function Removed"]),
        ("types", &["Struct Field Removed"]),
        ("storage", &["Struct Field Removed"]),
        ("events", &["Event Definition Removed"]),
        ("errors", &["Error Enum Case Removed"]),
        ("error-enums", &["Error Enum Case Removed"]),
        ("env", &["Environment", "Memory Limits Changed"]),
        ("environment", &["Environment", "Memory Limits Changed"]),
    ];
    for (flag_val, expected_cats) in cases {
        let (code, out, stderr) = run_cli(&[
            old_s, new_s, "--scope", flag_val, "--strict", "--format", "json",
        ]);
        assert_eq!(
            code, 1,
            "--scope {flag_val} should fail, stderr: {stderr}, out: {out}"
        );
        let json: Value = serde_json::from_str(&out).unwrap();
        for expected_cat in *expected_cats {
            assert!(
                json["findings_by_category"][*expected_cat].is_array(),
                "--scope {flag_val} must report '{expected_cat}', got: {json}"
            );
        }
        for other in all_cats {
            if !expected_cats.contains(&other) {
                assert!(
                    json["findings_by_category"].get(other).is_none(),
                    "--scope {flag_val} must NOT report '{other}', got: {json}"
                );
            }
        }
    }

    // Comma-separated vs repeated flags produce identical results.
    let (_, out_comma, _) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "functions,events",
        "--format",
        "json",
        "--no-timestamp",
    ]);
    let (_, out_repeat, _) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "FUNCTIONS",
        "--scope",
        "Events",
        "--format",
        "json",
        "--no-timestamp",
    ]);
    let json_comma: Value = serde_json::from_str(&out_comma).unwrap();
    let json_repeat: Value = serde_json::from_str(&out_repeat).unwrap();
    assert_eq!(json_comma, json_repeat);
}

#[test]
fn scoped_pass_exits_zero_and_prominently_reports_exclusions_across_formats() {
    // Candidate removes exported function `admin_reset` and drops an error enum
    // case, while storage struct `VaultState` and event `DepositEvent` stay intact.
    let old_entries = vec![
        fn_entry("admin_reset", &[]),
        struct_entry("VaultState", &[("total", ScSpecTypeDef::I128)]),
        event_entry("DepositEvent", &[("amount", ScSpecTypeDef::I128)]),
        error_enum_entry("VaultErr", &[("Locked", 1), ("Overflow", 2)]),
    ];
    let new_entries = vec![
        struct_entry("VaultState", &[("total", ScSpecTypeDef::I128)]),
        event_entry("DepositEvent", &[("amount", ScSpecTypeDef::I128)]),
        error_enum_entry("VaultErr", &[("Locked", 1)]),
    ];

    let old_wasm = build_soroban_wasm(20, &old_entries);
    let new_wasm = build_soroban_wasm(20, &new_entries);
    let old_path = write_tmp_bytes("scoped_pass/old.wasm", &old_wasm);
    let new_path = write_tmp_bytes("scoped_pass/new.wasm", &new_wasm);
    let old_s = old_path.to_str().unwrap();
    let new_s = new_path.to_str().unwrap();

    // Unscoped fails with exit code 1.
    let (unscoped_code, _, _) = run_cli(&[old_s, new_s]);
    assert_eq!(unscoped_code, 1);

    // Scoped to `types,events` passes with exit code 0 across all formats!
    let json_file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("scoped_pass/report.json");
    let json_out_arg = format!("json:{}", json_file.display());
    let (code_text, out_text, stderr_text) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "types,events",
        "--output",
        &json_out_arg,
        "--format",
        "text",
    ]);
    assert_eq!(code_text, 0, "stderr: {stderr_text}\nstdout: {out_text}");
    assert!(
        out_text.contains("[SCOPED COMPARISON ACTIVE]"),
        "{out_text}"
    );
    assert!(
        out_text.contains("PASSED (Scoped check only — excluded areas were NOT analyzed)"),
        "{out_text}"
    );
    assert!(
        out_text.contains(
            "SCOPED COMPARISON: Excluded from analysis and verdict: functions, errors, env (checked only: types, events)"
        ),
        "{out_text}"
    );
    assert!(
        out_text.contains(
            "No relevant changes detected within the selected scope areas (excluded areas were not checked)."
        ),
        "{out_text}"
    );

    // `--plain` / `--ascii` also preserve the scoped notice cleanly.
    let (code_plain, out_plain, _) = run_cli(&[old_s, new_s, "--scope", "types,events", "--plain"]);
    assert_eq!(code_plain, 0);
    assert!(
        out_plain.contains("[SCOPED COMPARISON ACTIVE]"),
        "{out_plain}"
    );
    assert!(
        out_plain.contains("[WARNING]  SCOPED COMPARISON: Excluded from analysis and verdict: functions, errors, env"),
        "{out_plain}"
    );

    // JSON report carries `is_safe: true` and explicit included/excluded arrays.
    let saved_json_raw = std::fs::read_to_string(&json_file).unwrap();
    let saved_json: Value = serde_json::from_str(&saved_json_raw).unwrap();
    assert_eq!(saved_json["is_safe"], true);
    assert_eq!(saved_json["total_findings"], 0);
    assert_eq!(
        saved_json["scope"]["included_areas"],
        serde_json::json!(["types", "events"])
    );
    assert_eq!(
        saved_json["scope"]["excluded_areas"],
        serde_json::json!(["functions", "errors", "env"])
    );

    // Markdown output prominently warns about excluded areas.
    let (code_md, out_md, _) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "types,events",
        "--format",
        "markdown",
    ]);
    assert_eq!(code_md, 0);
    assert!(
        out_md.contains("PASSED (Scoped check only — excluded areas were NOT analyzed)"),
        "{out_md}"
    );
    assert!(
        out_md.contains(
            "**Scoped Comparison**: Excluded from analysis and verdict: `functions, errors, env` (checked only: `types, events`)."
        ),
        "{out_md}"
    );

    // GitHub Actions output emits a `::warning::[Scoped Comparison]` annotation.
    let (code_gha, out_gha, _) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "types,events",
        "--format",
        "github-actions",
    ]);
    assert_eq!(code_gha, 0);
    assert!(
        out_gha.contains(
            "::warning::[Scoped Comparison] Excluded from analysis and verdict: functions, errors, env (checked only: types, events)"
        ),
        "{out_gha}"
    );

    // Re-rendering the saved JSON report via `render` preserves the scoped notice.
    let json_file_s = json_file.to_str().unwrap();
    let (render_code, render_md, _) = run_cli(&["render", json_file_s, "--format", "markdown"]);
    assert_eq!(render_code, 0);
    assert!(
        render_md.contains("**Scoped Comparison**: Excluded from analysis and verdict"),
        "{render_md}"
    );
}

#[test]
fn scope_interacts_coherently_with_min_severity_and_suppressions() {
    // Breaking function removal (Critical) + Protocol 20 -> 21 upgrade (Warning).
    let old_wasm = build_soroban_wasm(
        20,
        &[fn_entry("transfer", &[("amount", ScSpecTypeDef::I128)])],
    );
    let new_wasm = build_soroban_wasm(21, &[]);
    let old_path = write_tmp_bytes("interact/old.wasm", &old_wasm);
    let new_path = write_tmp_bytes("interact/new.wasm", &new_wasm);
    let old_s = old_path.to_str().unwrap();
    let new_s = new_path.to_str().unwrap();

    // `--min-severity critical` only hides warning text; warning count is still >= 1.
    let (_, unscoped_min_sev, _) = run_cli(&[
        old_s,
        new_s,
        "--min-severity",
        "critical",
        "--format",
        "json",
    ]);
    let json_min_sev: Value = serde_json::from_str(&unscoped_min_sev).unwrap();
    assert!(
        json_min_sev["counts"]["warning"].as_u64().unwrap() >= 1,
        "{json_min_sev}"
    );

    // `--scope functions` skips env at the diff stage: warning count is 0.
    let (_, scoped_fn, _) = run_cli(&[old_s, new_s, "--scope", "functions", "--format", "json"]);
    let json_scoped_fn: Value = serde_json::from_str(&scoped_fn).unwrap();
    assert_eq!(json_scoped_fn["counts"]["warning"], 0);
    assert_eq!(json_scoped_fn["counts"]["critical"], 1);

    // Suppressing the function removal while scoping to `functions` yields a
    // passing scoped run with `suppressed_count == 1`.
    let config_path = write_tmp_bytes(
        "interact/safeguard.toml",
        br#"
[[suppress]]
category = "Function Removed"
target = "transfer"
reason = "Intentional v2 entrypoint rename"
"#,
    );
    let (code_sup, out_sup, stderr_sup) = run_cli(&[
        old_s,
        new_s,
        "--scope",
        "functions",
        "--config",
        config_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code_sup, 0, "stderr: {stderr_sup}\nout: {out_sup}");
    let json_sup: Value = serde_json::from_str(&out_sup).unwrap();
    assert_eq!(json_sup["is_safe"], true);
    assert_eq!(json_sup["suppressed_count"], 1);
    assert_eq!(
        json_sup["scope"]["included_areas"],
        serde_json::json!(["functions"])
    );
}

#[test]
fn scope_works_in_library_api_lockfile_batch_and_show_config() {
    let old_wasm = build_soroban_wasm(
        20,
        &[
            fn_entry("transfer", &[("amount", ScSpecTypeDef::I128)]),
            struct_entry("State", &[("count", ScSpecTypeDef::U64)]),
        ],
    );
    // Function removed, struct unchanged.
    let new_wasm = build_soroban_wasm(
        20,
        &[struct_entry("State", &[("count", ScSpecTypeDef::U64)])],
    );

    // 1. Library API (`CompareOptions::scope`).
    let scoped_opts = CompareOptions {
        scope: ComparisonScope::from_cli_tokens(&["types".to_string()]).unwrap(),
        ..Default::default()
    };
    let lib_report = compare_wasm_bytes_with_options(&old_wasm, &new_wasm, &scoped_opts).unwrap();
    assert!(lib_report.is_safe());
    assert_eq!(lib_report.total_findings(), 0);
    assert!(lib_report.scope().is_scoped());

    // 2. Interface lockfile mode with `--scope types` passes; `--scope functions` fails.
    let old_path = write_tmp_bytes("modes/old.wasm", &old_wasm);
    let new_path = write_tmp_bytes("modes/new.wasm", &new_wasm);
    let lock_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("modes/interface.lock.json");
    let (lock_code, _, lock_err) = run_cli(&[
        "lockfile",
        old_path.to_str().unwrap(),
        "--output",
        lock_path.to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(lock_code, 0, "lockfile failed: {lock_err}");

    let (lf_types_code, _, _) = run_cli(&[
        new_path.to_str().unwrap(),
        "--interface-lockfile",
        lock_path.to_str().unwrap(),
        "--scope",
        "types",
    ]);
    assert_eq!(lf_types_code, 0);

    let (lf_fn_code, _, _) = run_cli(&[
        new_path.to_str().unwrap(),
        "--interface-lockfile",
        lock_path.to_str().unwrap(),
        "--scope",
        "functions",
    ]);
    assert_eq!(lf_fn_code, 1);

    // 3. Batch manifest mode with `--scope types`.
    let manifest_toml = format!(
        "[[pairs]]\nname = \"vault\"\nold = {:?}\nnew = {:?}\n",
        old_path.to_str().unwrap(),
        new_path.to_str().unwrap()
    );
    let manifest_path = write_tmp_bytes("modes/manifest.toml", manifest_toml.as_bytes());
    let (batch_code, batch_json_str, batch_err) = run_cli(&[
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--scope",
        "types",
        "--format",
        "json",
    ]);
    assert_eq!(batch_code, 0, "batch stderr: {batch_err}");
    let batch_json: Value = serde_json::from_str(&batch_json_str).unwrap();
    assert_eq!(batch_json["is_safe"], true);
    assert_eq!(batch_json["included_areas"], serde_json::json!(["types"]));
    assert_eq!(
        batch_json["excluded_areas"],
        serde_json::json!(["functions", "events", "errors", "env"])
    );

    let (batch_txt_code, batch_txt, _) = run_cli(&[
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--scope",
        "types",
        "--format",
        "text",
    ]);
    assert_eq!(batch_txt_code, 0);
    assert!(
        batch_txt.contains("[SCOPED COMPARISON ACTIVE]"),
        "{batch_txt}"
    );

    // 4. `--show-config` reflects `--scope`.
    let (sc_code, sc_out, _) = run_cli(&[
        "--show-config",
        "--scope",
        "functions,events",
        "--format",
        "json",
    ]);
    assert_eq!(sc_code, 0);
    let sc_json: Value = serde_json::from_str(&sc_out).unwrap();
    assert_eq!(
        sc_json["output"]["scope"]["value"],
        serde_json::json!(["functions", "events"])
    );
    assert_eq!(sc_json["output"]["scope"]["source"], "cli");

    // 5. Invalid `--scope` fails immediately with a clear error message.
    let (bad_code, _, bad_err) = run_cli(&[
        old_path.to_str().unwrap(),
        new_path.to_str().unwrap(),
        "--scope",
        "not-a-real-area",
    ]);
    assert_ne!(bad_code, 0);
    assert!(
        bad_err.contains("Unknown comparison scope 'not-a-real-area'"),
        "{bad_err}"
    );
}
