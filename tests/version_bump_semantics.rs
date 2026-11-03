// SPDX-License-Identifier: MIT

//! End-to-end coverage for change-based, suppression-aware SemVer bump derivation.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use soroban_upgrade_safeguard::category::{ChangeKind, FindingCategory};
use soroban_upgrade_safeguard::diff::{DiffReport, Finding, Severity};
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::suppression::SuppressionConfig;
use soroban_upgrade_safeguard::{
    compare_wasm_bytes_with_options, CompareOptions, UpgradeChangeProfile,
};
use stellar_xdr::curr::{
    Limited, Limits, ScEnvMetaEntry, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0,
    ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    WriteXdr,
};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("version-bump-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

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

fn wasm_custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = wasm_string(name);
    body.extend_from_slice(payload);
    let mut section = vec![0x00];
    section.extend(uleb(body.len() as u32));
    section.extend(body);
    section
}

fn build_wasm(entries: &[ScSpecEntry], env_version: Option<(u32, u32)>) -> Vec<u8> {
    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

    if !entries.is_empty() {
        let cursor = Cursor::new(Vec::new());
        let mut limited = Limited::new(cursor, Limits::none());
        for entry in entries {
            entry.write_xdr(&mut limited).expect("encode spec entry");
        }
        let spec_bytes = limited.inner.into_inner();
        wasm.extend(wasm_custom_section("contractspecv0", &spec_bytes));
    }

    if let Some((protocol, pre_release)) = env_version {
        let packed = ((protocol as u64) << 32) | (pre_release as u64);
        let env_entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(packed);
        let env_bytes = env_entry.to_xdr(Limits::none()).expect("encode env meta");
        wasm.extend(wasm_custom_section("contractenvmetav0", &env_bytes));
    }

    wasm
}

fn fn_entry(name: &str, doc: &str, params: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
    let inputs: Vec<ScSpecFunctionInputV0> = params
        .iter()
        .map(|(pname, pty)| ScSpecFunctionInputV0 {
            doc: "".try_into().unwrap(),
            name: (*pname).try_into().unwrap(),
            type_: pty.clone(),
        })
        .collect();
    ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: doc.try_into().unwrap(),
        name: name.try_into().unwrap(),
        inputs: inputs.try_into().unwrap(),
        outputs: Vec::<ScSpecTypeDef>::new().try_into().unwrap(),
    })
}

fn struct_entry(name: &str, doc: &str, fields: &[(&str, ScSpecTypeDef)]) -> ScSpecEntry {
    let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
        .iter()
        .map(|(fname, fty)| ScSpecUdtStructFieldV0 {
            doc: "".try_into().unwrap(),
            name: (*fname).try_into().unwrap(),
            type_: fty.clone(),
        })
        .collect();
    ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: doc.try_into().unwrap(),
        lib: "".try_into().unwrap(),
        name: name.try_into().unwrap(),
        fields: xdr_fields.try_into().unwrap(),
    })
}

fn enum_entry(name: &str, doc: &str, cases: &[(&str, u32)]) -> ScSpecEntry {
    let xdr_cases: Vec<ScSpecUdtEnumCaseV0> = cases
        .iter()
        .map(|(cname, val)| ScSpecUdtEnumCaseV0 {
            doc: "".try_into().unwrap(),
            name: (*cname).try_into().unwrap(),
            value: *val,
        })
        .collect();
    ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
        doc: doc.try_into().unwrap(),
        lib: "".try_into().unwrap(),
        name: name.try_into().unwrap(),
        cases: xdr_cases.try_into().unwrap(),
    })
}

fn run_cli_json(old: &Path, new: &Path, extra_args: &[&str]) -> (Value, i32) {
    let output = bin()
        .arg(old)
        .arg(new)
        .args(["--format", "json", "--no-timestamp"])
        .args(extra_args)
        .output()
        .expect("run CLI");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8(output.stdout).expect("valid utf-8 stdout");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON stdout: {e}\nstdout: {stdout}\nstderr: {stderr}"));
    let code = output.status.code().expect("exit code");
    (json, code)
}

#[test]
fn all_suppressed_breaking_upgrade_never_contradicts_safe_verdict() {
    let dir = temp_dir("all-suppressed");
    let old_wasm = build_wasm(
        &[
            fn_entry(
                "transfer",
                "transfer tokens",
                &[("amount", ScSpecTypeDef::U64)],
            ),
            fn_entry("legacy_init", "old initializer", &[]),
            struct_entry("State", "state", &[("balance", ScSpecTypeDef::U64)]),
        ],
        Some((21, 0)),
    );
    let new_wasm = build_wasm(
        &[
            fn_entry(
                "transfer",
                "transfer tokens",
                &[("amount", ScSpecTypeDef::U64)],
            ),
            struct_entry("State", "state", &[("balance", ScSpecTypeDef::I128)]),
        ],
        Some((21, 0)),
    );

    let old_path = dir.join("old.wasm");
    let new_path = dir.join("new.wasm");
    let cfg_path = dir.join(".safeguard.toml");
    std::fs::write(&old_path, &old_wasm).unwrap();
    std::fs::write(&new_path, &new_wasm).unwrap();

    // Unsuppressed baseline: unsafe and major.
    let (unsuppressed_json, unsuppressed_code) = run_cli_json(&old_path, &new_path, &[]);
    assert_eq!(unsuppressed_code, 1);
    assert_eq!(unsuppressed_json["is_safe"], false);
    assert_eq!(unsuppressed_json["recommended_bump"], "major");
    assert_eq!(
        unsuppressed_json["bump_rationale"]["change_profile"],
        "breaking"
    );

    // Suppress both breaking findings (including the CallAbi function removal).
    let toml = r#"
[[suppress]]
category = "Function Removed"
target = "legacy_init"
reason = "Dropped deprecated initializer after v2 cutover."

[[suppress]]
category = "Struct Field Type Changed"
target = "State.balance"
reason = "Temporary state wiped during deployment window."
"#;
    std::fs::write(&cfg_path, toml).unwrap();

    let cfg = SuppressionConfig::from_toml_str(toml).unwrap();
    let lib_report = compare_wasm_bytes_with_options(
        &old_wasm,
        &new_wasm,
        &CompareOptions {
            suppressions: Some(&cfg),
            ..CompareOptions::default()
        },
    )
    .unwrap();
    assert!(lib_report.is_safe());
    assert_eq!(lib_report.recommended_bump(), "minor");
    assert_eq!(
        lib_report.upgrade_change_profile(),
        UpgradeChangeProfile::SuppressedBreaking
    );

    let (json, code) = run_cli_json(
        &old_path,
        &new_path,
        &["--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(code, 0);
    assert_eq!(json["is_safe"], true);
    assert_eq!(json["recommended_bump"], "minor");
    assert_eq!(
        json["bump_rationale"]["change_profile"],
        "suppressed_breaking"
    );
    assert_eq!(json["bump_rationale"]["active_breaking_count"], 0);
    assert_eq!(json["bump_rationale"]["suppressed_breaking_count"], 2);
    assert!(json["recommended_bump_reason"]
        .as_str()
        .unwrap()
        .contains("acknowledged via suppression"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn partially_suppressed_upgrades_distinguish_remaining_active_break_from_additive() {
    let dir = temp_dir("partial-suppressed");
    let old_wasm = build_wasm(
        &[fn_entry("alpha", "", &[]), fn_entry("beta", "", &[])],
        None,
    );
    let new_two_breaks = build_wasm(&[], None);
    let new_break_plus_additive = build_wasm(
        &[fn_entry("alpha", "", &[]), fn_entry("gamma", "", &[])],
        None,
    );

    let old_path = dir.join("old.wasm");
    let new_breaks_path = dir.join("new_breaks.wasm");
    let new_mixed_path = dir.join("new_mixed.wasm");
    let cfg_path = dir.join("partial.toml");
    std::fs::write(&old_path, &old_wasm).unwrap();
    std::fs::write(&new_breaks_path, &new_two_breaks).unwrap();
    std::fs::write(&new_mixed_path, &new_break_plus_additive).unwrap();
    std::fs::write(
        &cfg_path,
        r#"
[[suppress]]
category = "Function Removed"
target = "beta"
reason = "Intentional removal of beta."
"#,
    )
    .unwrap();

    // 1 suppressed break (`beta`) + 1 active break (`alpha`) -> unsafe & major.
    let (json_a, code_a) = run_cli_json(
        &old_path,
        &new_breaks_path,
        &["--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(code_a, 1);
    assert_eq!(json_a["is_safe"], false);
    assert_eq!(json_a["recommended_bump"], "major");
    assert_eq!(json_a["bump_rationale"]["change_profile"], "breaking");
    assert_eq!(json_a["bump_rationale"]["active_breaking_count"], 1);
    assert_eq!(json_a["bump_rationale"]["suppressed_breaking_count"], 1);

    // 1 suppressed break (`beta`) + 1 active additive (`gamma`) -> safe & minor.
    let (json_b, code_b) = run_cli_json(
        &old_path,
        &new_mixed_path,
        &["--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(code_b, 0);
    assert_eq!(json_b["is_safe"], true);
    assert_eq!(json_b["recommended_bump"], "minor");
    assert_eq!(
        json_b["bump_rationale"]["change_profile"],
        "suppressed_breaking"
    );
    assert_eq!(json_b["bump_rationale"]["active_breaking_count"], 0);
    assert_eq!(json_b["bump_rationale"]["suppressed_breaking_count"], 1);
    assert_eq!(json_b["bump_rationale"]["additive_count"], 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn purely_additive_is_distinguishable_from_migration_requiring_and_verified_migration() {
    let dir = temp_dir("additive-vs-migration");
    let old_wasm = build_wasm(
        &[
            fn_entry("ping", "", &[]),
            struct_entry("State", "", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Mode", "", &[("Normal", 0)]),
        ],
        Some((21, 0)),
    );

    // Purely additive: new function + new enum case.
    let additive_wasm = build_wasm(
        &[
            fn_entry("ping", "", &[]),
            fn_entry("pong", "", &[]),
            struct_entry("State", "", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Mode", "", &[("Normal", 0), ("Paused", 1)]),
        ],
        Some((21, 0)),
    );

    // Migration-requiring warning: appended field on existing struct.
    let appended_field_wasm = build_wasm(
        &[
            fn_entry("ping", "", &[]),
            struct_entry(
                "State",
                "",
                &[
                    ("balance", ScSpecTypeDef::U64),
                    ("last_updated", ScSpecTypeDef::U64),
                ],
            ),
            enum_entry("Mode", "", &[("Normal", 0)]),
        ],
        Some((21, 0)),
    );

    // Breaking field type change resolved via verified `[[migration]]`.
    let migrated_type_wasm = build_wasm(
        &[
            fn_entry("ping", "", &[]),
            struct_entry("State", "", &[("balance", ScSpecTypeDef::I128)]),
            enum_entry("Mode", "", &[("Normal", 0)]),
        ],
        Some((21, 0)),
    );

    let old_path = dir.join("old.wasm");
    let additive_path = dir.join("additive.wasm");
    let appended_path = dir.join("appended.wasm");
    let migrated_path = dir.join("migrated.wasm");
    let migration_cfg_path = dir.join("migration.toml");
    std::fs::write(&old_path, &old_wasm).unwrap();
    std::fs::write(&additive_path, &additive_wasm).unwrap();
    std::fs::write(&appended_path, &appended_field_wasm).unwrap();
    std::fs::write(&migrated_path, &migrated_type_wasm).unwrap();
    std::fs::write(
        &migration_cfg_path,
        r#"
[[migration]]
id = "v2-widen-balance"
description = "Rewrites State.balance from u64 to i128 before reads."
migrates = ["State"]
runs_before_read = true

  [[migration.covers]]
  category = "Struct Field Type Changed"
  target = "State.balance"
"#,
    )
    .unwrap();

    let (additive_json, additive_code) = run_cli_json(&old_path, &additive_path, &[]);
    assert_eq!(additive_code, 0);
    assert_eq!(additive_json["is_safe"], true);
    assert_eq!(additive_json["recommended_bump"], "minor");
    assert_eq!(
        additive_json["bump_rationale"]["change_profile"],
        "additive"
    );
    assert_eq!(additive_json["bump_rationale"]["additive_count"], 2);
    assert_eq!(
        additive_json["bump_rationale"]["migration_requiring_count"],
        0
    );
    assert!(additive_json["recommended_bump_reason"]
        .as_str()
        .unwrap()
        .contains("no data migration required"));

    let (appended_json, appended_code) = run_cli_json(&old_path, &appended_path, &[]);
    assert_eq!(appended_code, 0);
    assert_eq!(appended_json["is_safe"], true);
    assert_eq!(appended_json["recommended_bump"], "minor");
    assert_eq!(
        appended_json["bump_rationale"]["change_profile"],
        "migration_requiring"
    );
    assert_eq!(
        appended_json["bump_rationale"]["migration_requiring_count"],
        1
    );
    assert_ne!(
        additive_json["bump_rationale"]["change_profile"],
        appended_json["bump_rationale"]["change_profile"]
    );

    let (migrated_json, migrated_code) = run_cli_json(
        &old_path,
        &migrated_path,
        &["--config", migration_cfg_path.to_str().unwrap()],
    );
    assert_eq!(migrated_code, 0);
    assert_eq!(migrated_json["is_safe"], true);
    assert_eq!(migrated_json["recommended_bump"], "minor");
    assert_eq!(
        migrated_json["bump_rationale"]["change_profile"],
        "migration_requiring"
    );
    assert_eq!(
        migrated_json["bump_rationale"]["migrated_breaking_count"],
        1
    );
    assert_eq!(migrated_json["bump_rationale"]["active_breaking_count"], 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn identical_cosmetic_and_environment_metadata_changes_yield_patch() {
    let dir = temp_dir("patch-profiles");
    let base_wasm = build_wasm(
        &[
            fn_entry("ping", "v1 fn doc", &[]),
            struct_entry("State", "v1 struct doc", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Status", "v1 enum doc", &[("Ok", 0)]),
        ],
        Some((21, 0)),
    );
    let doc_changed_wasm = build_wasm(
        &[
            fn_entry("ping", "v2 fn doc", &[]),
            struct_entry("State", "v2 struct doc", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Status", "v2 enum doc", &[("Ok", 0)]),
        ],
        Some((21, 0)),
    );
    let env_upgraded_wasm = build_wasm(
        &[
            fn_entry("ping", "v1 fn doc", &[]),
            struct_entry("State", "v1 struct doc", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Status", "v1 enum doc", &[("Ok", 0)]),
        ],
        Some((22, 0)),
    );
    // Protocol downgrade in `contractenvmetav0` emits `Environment` with `Critical`
    // display severity, yet never gates `is_safe` and must remain `patch`.
    let env_downgraded_wasm = build_wasm(
        &[
            fn_entry("ping", "v1 fn doc", &[]),
            struct_entry("State", "v1 struct doc", &[("balance", ScSpecTypeDef::U64)]),
            enum_entry("Status", "v1 enum doc", &[("Ok", 0)]),
        ],
        Some((20, 0)),
    );

    let base_path = dir.join("base.wasm");
    let doc_path = dir.join("doc.wasm");
    let env_up_path = dir.join("env_up.wasm");
    let env_down_path = dir.join("env_down.wasm");
    let suppress_doc_path = dir.join("suppress_doc.toml");
    std::fs::write(&base_path, &base_wasm).unwrap();
    std::fs::write(&doc_path, &doc_changed_wasm).unwrap();
    std::fs::write(&env_up_path, &env_upgraded_wasm).unwrap();
    std::fs::write(&env_down_path, &env_downgraded_wasm).unwrap();
    std::fs::write(
        &suppress_doc_path,
        r#"
[[suppress]]
category = "Function Documentation Changed"
target = "ping"
reason = "Doc refresh"

[[suppress]]
category = "Struct Documentation Changed"
target = "State"
reason = "Doc refresh"

[[suppress]]
category = "Enum Documentation Changed"
target = "Status"
reason = "Doc refresh"
"#,
    )
    .unwrap();

    // Identical interface & metadata -> `patch` (`identical`).
    let (identical_json, identical_code) = run_cli_json(&base_path, &base_path, &[]);
    assert_eq!(identical_code, 0);
    assert_eq!(identical_json["is_safe"], true);
    assert_eq!(identical_json["recommended_bump"], "patch");
    assert_eq!(
        identical_json["bump_rationale"]["change_profile"],
        "identical"
    );

    // Documentation-only Info findings -> `patch` (`cosmetic`), unsuppressed & suppressed.
    let (doc_json, doc_code) = run_cli_json(&base_path, &doc_path, &[]);
    assert_eq!(doc_code, 0);
    assert_eq!(doc_json["recommended_bump"], "patch");
    assert_eq!(doc_json["bump_rationale"]["change_profile"], "cosmetic");
    assert_eq!(doc_json["bump_rationale"]["cosmetic_count"], 3);

    let (suppressed_doc_json, suppressed_doc_code) = run_cli_json(
        &base_path,
        &doc_path,
        &["--config", suppress_doc_path.to_str().unwrap()],
    );
    assert_eq!(suppressed_doc_code, 0);
    assert_eq!(suppressed_doc_json["recommended_bump"], "patch");
    assert_eq!(
        suppressed_doc_json["bump_rationale"]["change_profile"],
        "cosmetic"
    );

    // Environment metadata changes (Warning & Critical severities) -> `patch` (`cosmetic`).
    for env_path in [&env_up_path, &env_down_path] {
        let (env_json, env_code) = run_cli_json(&base_path, env_path, &[]);
        assert_eq!(env_code, 0);
        assert_eq!(env_json["is_safe"], true);
        assert_eq!(env_json["recommended_bump"], "patch");
        assert_eq!(env_json["bump_rationale"]["change_profile"], "cosmetic");
        assert_eq!(env_json["bump_rationale"]["env_metadata_changed"], true);
    }

    // Zero findings with `env_metadata_changed = true` -> `patch` (`cosmetic`).
    let zero_finding_env = SafetyReport::noop(64, 64).with_env_metadata_changed(true);
    assert_eq!(zero_finding_env.total_findings(), 0);
    assert!(zero_finding_env.is_safe());
    assert_eq!(zero_finding_env.recommended_bump(), "patch");
    assert_eq!(
        zero_finding_env.upgrade_change_profile(),
        UpgradeChangeProfile::Cosmetic
    );
    assert!(zero_finding_env.bump_rationale().env_metadata_changed);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bump_derives_from_change_kind_not_overridden_display_severity() {
    let empty_spec = soroban_upgrade_safeguard::spec::ContractSpec::default();

    // Even if `Function Added` carries `Warning` display severity, its structural
    // ChangeKind remains `Additive`, not `MigrationRequiring`.
    let additive_diff = DiffReport {
        findings: vec![Finding {
            severity: Severity::Warning,
            axes: Vec::new(),
            category: FindingCategory::FunctionAdded.as_str().to_string(),
            message: "added".to_string(),
            type_name: None,
            target: Some("new_fn".to_string()),
            change: None,
            root_target: None,
        }],
    };
    let additive_report = SafetyReport::new_with_specs(&additive_diff, &empty_spec, &empty_spec);
    assert_eq!(
        FindingCategory::FunctionAdded.change_kind(),
        ChangeKind::Additive
    );
    assert_eq!(
        additive_report.upgrade_change_profile(),
        UpgradeChangeProfile::Additive
    );
    assert_eq!(additive_report.recommended_bump(), "minor");

    // Even if `Struct Field Added` carries `Info` display severity, its structural
    // ChangeKind remains `MigrationRequiring`.
    let migration_diff = DiffReport {
        findings: vec![Finding {
            severity: Severity::Info,
            axes: Vec::new(),
            category: FindingCategory::StructFieldAdded.as_str().to_string(),
            message: "appended".to_string(),
            type_name: Some("State".to_string()),
            target: Some("State.extra".to_string()),
            change: None,
            root_target: None,
        }],
    };
    let migration_report = SafetyReport::new_with_specs(&migration_diff, &empty_spec, &empty_spec);
    assert_eq!(
        migration_report.upgrade_change_profile(),
        UpgradeChangeProfile::MigrationRequiring
    );
    assert_eq!(migration_report.recommended_bump(), "minor");
}

#[test]
fn strict_mode_fails_gate_on_warnings_without_escalating_bump_to_major() {
    let dir = temp_dir("strict-mode");
    let old_wasm = build_wasm(
        &[
            fn_entry("legacy", "", &[]),
            struct_entry("State", "", &[("balance", ScSpecTypeDef::U64)]),
        ],
        None,
    );
    let warning_plus_suppressed_break = build_wasm(
        &[struct_entry(
            "State",
            "",
            &[
                ("balance", ScSpecTypeDef::U64),
                ("nonce", ScSpecTypeDef::U64),
            ],
        )],
        None,
    );

    let old_path = dir.join("old.wasm");
    let new_path = dir.join("new.wasm");
    let cfg_path = dir.join("suppress_legacy.toml");
    std::fs::write(&old_path, &old_wasm).unwrap();
    std::fs::write(&new_path, &warning_plus_suppressed_break).unwrap();
    std::fs::write(
        &cfg_path,
        r#"
[[suppress]]
category = "Function Removed"
target = "legacy"
reason = "Legacy entrypoint retired."
"#,
    )
    .unwrap();

    // Non-strict: safe + minor.
    let (normal_json, normal_code) = run_cli_json(
        &old_path,
        &new_path,
        &["--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(normal_code, 0);
    assert_eq!(normal_json["is_safe"], true);
    assert_eq!(normal_json["recommended_bump"], "minor");

    // Strict: warning fails the gate (`is_safe = false`), yet `recommended_bump`
    // stays `"minor"` even with a suppressed breaking finding in the same run.
    let (strict_json, strict_code) = run_cli_json(
        &old_path,
        &new_path,
        &["--strict", "--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(strict_code, 1);
    assert_eq!(strict_json["is_safe"], false);
    assert_eq!(strict_json["strict"], true);
    assert_eq!(strict_json["recommended_bump"], "minor");
    assert_eq!(
        strict_json["bump_rationale"]["change_profile"],
        "migration_requiring"
    );
    assert_eq!(strict_json["bump_rationale"]["strict_gate_failed"], true);
    assert_eq!(strict_json["bump_rationale"]["active_breaking_count"], 0);
    assert_eq!(
        strict_json["bump_rationale"]["suppressed_breaking_count"],
        1
    );
    assert!(strict_json["recommended_bump_reason"]
        .as_str()
        .unwrap()
        .contains("strict mode failed safety gate"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ungated_event_axis_caps_bump_at_minor_until_gated() {
    let empty_spec = soroban_upgrade_safeguard::spec::ContractSpec::default();
    let event_break = DiffReport {
        findings: vec![Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: FindingCategory::EventSchemaRemoved.as_str().to_string(),
            message: "event removed".to_string(),
            type_name: Some("TransferEvent".to_string()),
            target: Some("TransferEvent.amount".to_string()),
            change: None,
            root_target: None,
        }],
    };

    // Default policy leaves `EventIndexer` ungated -> `is_safe = true` -> `"minor"`.
    let default_report = SafetyReport::with_suppressions_with_specs(
        &event_break,
        &SuppressionConfig::default(),
        false,
        false,
        &empty_spec,
        &empty_spec,
        None,
    );
    assert!(default_report.is_safe());
    assert_eq!(default_report.recommended_bump(), "minor");
    assert_eq!(
        default_report.upgrade_change_profile(),
        UpgradeChangeProfile::SuppressedBreaking
    );
    assert_eq!(default_report.bump_rationale().ungated_breaking_count, 1);

    // Gating `EventIndexer` flips `is_safe = false` -> `"major"`.
    let gated_cfg = SuppressionConfig::from_toml_str(
        r#"
[policy]
gate_event_indexer = true
"#,
    )
    .unwrap();
    let gated_report = SafetyReport::with_suppressions_with_specs(
        &event_break,
        &gated_cfg,
        false,
        false,
        &empty_spec,
        &empty_spec,
        None,
    );
    assert!(!gated_report.is_safe());
    assert_eq!(gated_report.recommended_bump(), "major");
    assert_eq!(
        gated_report.upgrade_change_profile(),
        UpgradeChangeProfile::Breaking
    );
}

#[test]
fn print_schema_documents_bump_rationale_fields() {
    let output = bin()
        .args(["print-schema"])
        .output()
        .expect("run print-schema");
    assert!(output.status.success());
    let schema: Value = serde_json::from_slice(&output.stdout).expect("valid schema JSON");
    let props = schema["properties"].as_object().expect("properties object");
    assert!(props.contains_key("recommended_bump"));
    assert!(props.contains_key("recommended_bump_reason"));
    assert!(props.contains_key("bump_rationale"));
    let defs = schema["definitions"]
        .as_object()
        .expect("definitions object");
    assert!(defs.contains_key("BumpRationale"));
    assert!(defs.contains_key("UpgradeChangeProfile"));
}

#[test]
fn batch_mode_rolls_up_per_pair_bumps_coherently() {
    let dir = temp_dir("batch-rollup");
    let v1 = build_wasm(&[fn_entry("ping", "v1", &[])], None);
    let v1_additive = build_wasm(
        &[fn_entry("ping", "v1", &[]), fn_entry("pong", "v2", &[])],
        None,
    );
    let v1_breaking = build_wasm(&[], None);

    let v1_path = dir.join("v1.wasm");
    let v1_copy_path = dir.join("v1_copy.wasm");
    let additive_path = dir.join("additive.wasm");
    let breaking_path = dir.join("breaking.wasm");
    let suppress_path = dir.join("suppress_ping.toml");
    std::fs::write(&v1_path, &v1).unwrap();
    std::fs::write(&v1_copy_path, &v1).unwrap();
    std::fs::write(&additive_path, &v1_additive).unwrap();
    std::fs::write(&breaking_path, &v1_breaking).unwrap();
    std::fs::write(
        &suppress_path,
        r#"
[[suppress]]
category = "Function Removed"
target = "ping"
reason = "Accepted in batch migration."
"#,
    )
    .unwrap();

    // 1. Clean batch (identical + additive) -> overall safe, recommended_bump = "minor" (`additive`).
    let clean_manifest = dir.join("clean_manifest.toml");
    std::fs::write(
        &clean_manifest,
        r#"
[[pairs]]
name = "core"
old = "v1.wasm"
new = "v1_copy.wasm"

[[pairs]]
name = "router"
old = "v1.wasm"
new = "additive.wasm"
"#,
    )
    .unwrap();

    let clean_out = bin()
        .current_dir(&dir)
        .args([
            "--manifest",
            clean_manifest.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        clean_out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&clean_out.stdout),
        String::from_utf8_lossy(&clean_out.stderr)
    );
    let clean_json: Value = serde_json::from_slice(&clean_out.stdout).unwrap();
    assert_eq!(clean_json["is_safe"], true);
    assert_eq!(clean_json["recommended_bump"], "minor");
    assert_eq!(clean_json["bump_rationale"]["change_profile"], "additive");
    assert_eq!(clean_json["bump_rationale"]["minor_pairs"], 1);
    assert_eq!(clean_json["bump_rationale"]["patch_pairs"], 1);
    assert_eq!(clean_json["bump_rationale"]["major_pairs"], 0);

    // 2. All-suppressed breaking pair + identical pair -> overall safe, recommended_bump = "minor".
    let suppressed_manifest = dir.join("suppressed_manifest.toml");
    std::fs::write(
        &suppressed_manifest,
        r#"
[[pairs]]
name = "core"
old = "v1.wasm"
new = "v1_copy.wasm"

[[pairs]]
name = "legacy"
old = "v1.wasm"
new = "breaking.wasm"
config = "suppress_ping.toml"
"#,
    )
    .unwrap();

    let sup_out = bin()
        .current_dir(&dir)
        .args([
            "--manifest",
            suppressed_manifest.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(sup_out.status.code(), Some(0));
    let sup_json: Value = serde_json::from_slice(&sup_out.stdout).unwrap();
    assert_eq!(sup_json["is_safe"], true);
    assert_eq!(sup_json["recommended_bump"], "minor");
    assert_eq!(
        sup_json["bump_rationale"]["change_profile"],
        "suppressed_breaking"
    );

    // 3. Active breaking pair + additive pair -> overall unsafe, recommended_bump = "major".
    let breaking_manifest = dir.join("breaking_manifest.toml");
    std::fs::write(
        &breaking_manifest,
        r#"
[[pairs]]
name = "router"
old = "v1.wasm"
new = "additive.wasm"

[[pairs]]
name = "broken"
old = "v1.wasm"
new = "breaking.wasm"
"#,
    )
    .unwrap();

    let brk_out = bin()
        .current_dir(&dir)
        .args([
            "--manifest",
            breaking_manifest.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(brk_out.status.code(), Some(1));
    let brk_json: Value = serde_json::from_slice(&brk_out.stdout).unwrap();
    assert_eq!(brk_json["is_safe"], false);
    assert_eq!(brk_json["recommended_bump"], "major");
    assert_eq!(brk_json["bump_rationale"]["change_profile"], "breaking");
    assert_eq!(brk_json["bump_rationale"]["major_pairs"], 1);
    assert_eq!(brk_json["bump_rationale"]["minor_pairs"], 1);

    // 4. Errored pair (missing WASM) + identical pair -> overall unsafe, conservative "major".
    let errored_manifest = dir.join("errored_manifest.toml");
    std::fs::write(
        &errored_manifest,
        r#"
[[pairs]]
name = "core"
old = "v1.wasm"
new = "v1_copy.wasm"

[[pairs]]
name = "unreadable"
old = "v1.wasm"
new = "does_not_exist.wasm"
"#,
    )
    .unwrap();

    let err_out = bin()
        .current_dir(&dir)
        .args([
            "--manifest",
            errored_manifest.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(err_out.status.code(), Some(1));
    let err_json: Value = serde_json::from_slice(&err_out.stdout).unwrap();
    assert_eq!(err_json["is_safe"], false);
    assert_eq!(err_json["recommended_bump"], "major");
    assert_eq!(err_json["bump_rationale"]["errored_pairs"], 1);

    let _ = std::fs::remove_dir_all(&dir);
}
