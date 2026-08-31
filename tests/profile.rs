//! Integration tests for named policy profiles, exercised end-to-end through
//! [`ResolvedConfig::resolve`] the same way the CLI would use them.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use soroban_upgrade_safeguard::config::{Args, OutputFormat, ResolvedConfig};

// Shared with tests/config.rs's lock in spirit; a separate static keeps this
// file independent (env vars are process-global, so tests touching them must
// still be serialized within *this* file).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn clear_safeguard_env() {
    for var in [
        "SAFEGUARD_PROFILE",
        "SAFEGUARD_STRICT",
        "SAFEGUARD_EXPLAIN",
        "SAFEGUARD_NO_COLOR",
        "NO_COLOR",
        "SAFEGUARD_FORMAT",
        "SAFEGUARD_MAX_XDR_DEPTH",
        "SAFEGUARD_MAX_XDR_LEN",
        "SAFEGUARD_MAX_ENTRIES",
        "SAFEGUARD_MAX_WALK_DEPTH",
        "SAFEGUARD_MAX_SUPPRESSIONS",
    ] {
        env::remove_var(var);
    }
}

fn base_args(config_path: PathBuf) -> Args {
    Args {
        wasm_paths: vec![PathBuf::from("old.wasm"), PathBuf::from("new.wasm")],
        config: Some(config_path),
        ..Args::default()
    }
}

fn write_config(name: &str, contents: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path
}

// ── Compatibility ────────────────────────────────────────────────────────────

#[test]
fn compatibility_no_profiles_table_behaves_as_before() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_compat_no_table.toml",
        r#"
        strict = true
        format = "json"
        "#,
    );

    let resolved = ResolvedConfig::resolve(base_args(config_path)).unwrap();
    assert_eq!(resolved.format, OutputFormat::Json);
    assert!(resolved.strict);
    assert_eq!(resolved.profile.selected, None);
    assert!(resolved.profile.chain.is_empty());
}

#[test]
fn compatibility_profiles_table_present_but_unselected_is_inert() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_compat_unselected.toml",
        r#"
        strict = false

        [profiles.pr]
        strict = true
        format = "json"
        "#,
    );

    // No `--profile`, no `SAFEGUARD_PROFILE`, no `default_profile`: the
    // `[profiles.pr]` table must not affect the resolved settings at all.
    let resolved = ResolvedConfig::resolve(base_args(config_path)).unwrap();
    assert_eq!(resolved.format, OutputFormat::Text);
    assert!(!resolved.strict);
    assert_eq!(resolved.profile.selected, None);
}

// ── Precedence ───────────────────────────────────────────────────────────────

#[test]
fn precedence_selected_profile_beats_base_config() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_precedence_base.toml",
        r#"
        format = "text"

        [profiles.release]
        format = "json"
        "#,
    );

    let args = Args {
        profile: Some("release".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.format, OutputFormat::Json);
    assert_eq!(resolved.profile.selected.as_deref(), Some("release"));
}

#[test]
fn precedence_cli_beats_selected_profile() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_precedence_cli.toml",
        r#"
        [profiles.release]
        format = "json"
        "#,
    );

    let args = Args {
        profile: Some("release".to_string()),
        format: OutputFormat::Markdown,
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.format, OutputFormat::Markdown);
}

#[test]
fn precedence_default_profile_used_when_no_cli_flag() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_default_profile.toml",
        r#"
        default_profile = "pr"

        [profiles.pr]
        strict = true
        "#,
    );

    let resolved = ResolvedConfig::resolve(base_args(config_path)).unwrap();
    assert!(resolved.strict);
    assert_eq!(resolved.profile.selected.as_deref(), Some("pr"));
}

#[test]
fn precedence_cli_profile_flag_beats_default_profile() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_cli_beats_default.toml",
        r#"
        default_profile = "pr"

        [profiles.pr]
        strict = true

        [profiles.dev]
        strict = false
        "#,
    );

    let args = Args {
        profile: Some("dev".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.profile.selected.as_deref(), Some("dev"));
    // `dev` cannot un-set the base config's default (false), and doesn't try to.
    assert!(!resolved.strict);
}

#[test]
fn precedence_strict_escalates_across_profile_and_base() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_strict_escalate.toml",
        r#"
        strict = true

        [profiles.relaxed]
        strict = false
        "#,
    );

    let args = Args {
        profile: Some("relaxed".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    // The base configuration's `strict = true` cannot be weakened by a profile.
    assert!(resolved.strict);
}

#[test]
fn precedence_gating_gate_is_valued_and_can_be_turned_off_by_a_profile() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_gating_valued.toml",
        r#"
        [gating]
        gate_call_abi = true

        [profiles.quiet]
        [profiles.quiet.gating]
        gate_call_abi = false
        "#,
    );

    let args = Args {
        profile: Some("quiet".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    // Unlike `strict`, a gate is valued: the more specific layer wins outright.
    assert!(!resolved.gating.gate_call_abi);
}

// ── Cycle / depth ────────────────────────────────────────────────────────────

#[test]
fn cycle_self_inheritance_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_cycle_self.toml",
        r#"
        [profiles.loopy]
        inherits = "loopy"
        "#,
    );

    let args = Args {
        profile: Some("loopy".to_string()),
        ..base_args(config_path)
    };
    let err = ResolvedConfig::resolve(args).unwrap_err();
    assert!(err.to_string().contains("cycle"));
}

#[test]
fn cycle_indirect_inheritance_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_cycle_indirect.toml",
        r#"
        [profiles.a]
        inherits = "b"
        [profiles.b]
        inherits = "a"
        "#,
    );

    let args = Args {
        profile: Some("a".to_string()),
        ..base_args(config_path)
    };
    let err = ResolvedConfig::resolve(args).unwrap_err();
    assert!(err.to_string().contains("cycle"));
}

#[test]
fn missing_selected_profile_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_missing_selected.toml",
        r#"
        [profiles.pr]
        strict = true
        "#,
    );

    let args = Args {
        profile: Some("does-not-exist".to_string()),
        ..base_args(config_path)
    };
    let err = ResolvedConfig::resolve(args).unwrap_err();
    assert!(err.to_string().contains("does-not-exist"));
}

// ── Batch: several profile selections against one shared file ──────────────

#[test]
fn batch_each_profile_in_a_shared_file_resolves_independently() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_batch_shared_file.toml",
        r#"
        [[suppress]]
        category = "Function Removed"
        target   = "legacy_init"
        reason   = "Deprecated initializer dropped after the v2 cutover."

        [profiles.dev]
        format = "text"

        [profiles.pr]
        inherits = "dev"
        strict   = true

        [profiles.release]
        inherits = "pr"
        format   = "json"

        [profiles.emergency]
        inherits         = "release"
        max_suppressions = 50
        "#,
    );

    let expectations: &[(&str, OutputFormat, bool, Option<usize>)] = &[
        ("dev", OutputFormat::Text, false, None),
        ("pr", OutputFormat::Text, true, None),
        ("release", OutputFormat::Json, true, None),
        ("emergency", OutputFormat::Json, true, Some(50)),
    ];

    for (name, format, strict, max_suppressions) in expectations {
        let args = Args {
            profile: Some((*name).to_string()),
            ..base_args(config_path.clone())
        };
        let resolved = ResolvedConfig::resolve(args).unwrap();
        assert_eq!(resolved.format, *format, "profile {name}: format");
        assert_eq!(resolved.strict, *strict, "profile {name}: strict");
        assert_eq!(
            resolved.suppressions.max_suppressions, *max_suppressions,
            "profile {name}: max_suppressions"
        );
        // Suppression records are shared by every profile, unaffected by selection.
        assert_eq!(
            resolved.suppressions.rules().len(),
            1,
            "profile {name}: rules"
        );
    }
}

// ── Provenance ───────────────────────────────────────────────────────────────

#[test]
fn provenance_records_chain_and_per_field_origin() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_provenance.toml",
        r#"
        format = "text"

        [profiles.dev]
        [profiles.pr]
        inherits = "dev"
        strict   = true
        "#,
    );

    let args = Args {
        profile: Some("pr".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();

    assert_eq!(resolved.profile.selected.as_deref(), Some("pr"));
    assert_eq!(
        resolved.profile.chain,
        vec!["dev".to_string(), "pr".to_string()]
    );

    // `format` was set only at the base configuration; no profile touched it.
    assert_eq!(resolved.profile.format.value, OutputFormat::Text);
    assert_eq!(format!("{}", resolved.profile.format.origin), "base config");

    // `strict` was set on `pr` itself.
    assert!(resolved.profile.strict.value);
    assert_eq!(
        format!("{}", resolved.profile.strict.origin),
        "profile 'pr'"
    );

    // Untouched fields fall back to the built-in default and say so.
    assert_eq!(
        format!("{}", resolved.profile.limits.max_walk_depth.origin),
        "built-in"
    );
}

#[test]
fn provenance_serializes_to_json() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let config_path = write_config(
        "profile_provenance_json.toml",
        r#"
        [profiles.pr]
        strict = true
        "#,
    );

    let args = Args {
        profile: Some("pr".to_string()),
        ..base_args(config_path)
    };
    let resolved = ResolvedConfig::resolve(args).unwrap();
    let json = serde_json::to_value(&resolved.profile).unwrap();
    assert_eq!(json["selected"], "pr");
    assert_eq!(json["chain"], serde_json::json!(["pr"]));
    assert_eq!(json["strict"]["value"], true);
    assert_eq!(json["strict"]["origin"], "profile 'pr'");
}

// ── Example configuration ───────────────────────────────────────────────────

#[test]
fn example_profiles_config_parses_and_resolves_every_profile() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let example =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".safeguard.profiles.example.toml");
    assert!(
        example.exists(),
        "expected the shipped example at {}",
        example.display()
    );

    for name in ["dev", "pr", "release", "emergency"] {
        let args = Args {
            profile: Some(name.to_string()),
            ..base_args(example.clone())
        };
        let resolved = ResolvedConfig::resolve(args)
            .unwrap_or_else(|e| panic!("profile '{name}' failed to resolve: {e}"));
        assert_eq!(resolved.profile.selected.as_deref(), Some(name));
    }

    // `default_profile = "dev"` in the example: a bare invocation picks it up.
    let resolved = ResolvedConfig::resolve(base_args(example)).unwrap();
    assert_eq!(resolved.profile.selected.as_deref(), Some("dev"));
}

// ── Checked-in local development profile ─────────────────────────────────────
//
// Smoke tests for the .safeguard.dev.toml profile shipped with the repo.
// This proves from a clean checkout that the profile (1) parses as a valid
// suppression/profiles config, (2) resolves every declared named profile,
// (3) auto-selects 'dev' via default_profile, and (4) runs against the
// documented v1/v2 fixture WASMs without error through the library entry
// point — exactly the workflow documented in the profile's header comments.

#[test]
fn dev_profile_parses_declared_profiles_and_defaults_to_dev() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".safeguard.dev.toml");
    assert!(
        dev_path.exists(),
        "expected the checked-in dev profile at {}",
        dev_path.display()
    );

    for name in ["dev", "pr", "golden"] {
        let args = Args {
            profile: Some(name.to_string()),
            ..base_args(dev_path.clone())
        };
        let resolved = ResolvedConfig::resolve(args)
            .unwrap_or_else(|e| panic!("dev profile '{name}' failed to resolve: {e}"));
        assert_eq!(resolved.profile.selected.as_deref(), Some(name));
    }

    let resolved = ResolvedConfig::resolve(base_args(dev_path)).unwrap();
    assert_eq!(
        resolved.profile.selected.as_deref(),
        Some("dev"),
        "default_profile must auto-select 'dev' on a bare dev-profile load"
    );
    assert!(resolved.explain, "dev profile root must enable explain");
    assert_eq!(resolved.format, OutputFormat::Text);
}

#[test]
fn dev_profile_runs_against_documented_v1_v2_fixture_clean_checkout_smoke() {
    use soroban_upgrade_safeguard::{compare_wasm_files_with_options, CompareOptions};

    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dev_path = repo.join(".safeguard.dev.toml");
    let old_wasm = repo.join("tests").join("wasm").join("v1.wasm");
    let new_wasm = repo.join("tests").join("wasm").join("v2.wasm");

    assert!(dev_path.exists(), "dev profile must be checked in");
    assert!(
        old_wasm.exists(),
        "v1 fixture missing: {}",
        old_wasm.display()
    );
    assert!(
        new_wasm.exists(),
        "v2 fixture missing: {}",
        new_wasm.display()
    );

    let args = Args {
        wasm_paths: vec![old_wasm.clone(), new_wasm.clone()],
        config: Some(dev_path),
        ..Args::default()
    };
    let resolved = ResolvedConfig::resolve(args)
        .expect("resolving CLI args against the dev profile must succeed");
    assert_eq!(resolved.profile.selected.as_deref(), Some("dev"));

    let opts = CompareOptions {
        suppressions: Some(&resolved.suppressions),
        explain: resolved.explain,
        strict: resolved.strict,
        storage_schemas: None,
        lineage_store: None,
        contract: None,
    };
    let report = compare_wasm_files_with_options(&old_wasm, &new_wasm, &opts)
        .expect("comparing v1 vs v2 with the dev profile must not error");
    // Smoke: the report must be structurally well-formed (totals add up).
    assert_eq!(
        report.total_findings(),
        report.critical_count() + report.warning_count() + report.info_count(),
        "finding counts must sum consistently with the dev-profile run"
    );
}
