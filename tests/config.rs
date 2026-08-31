#![allow(clippy::bool_assert_comparison)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use soroban_upgrade_safeguard::config::{Args, OutputFormat, ResolvedConfig, RunMode};
use soroban_upgrade_safeguard::limits::ResourcePolicy;

// Global lock to serialize test execution and prevent environment variable race conditions
static ENV_LOCK: Mutex<()> = Mutex::new(());

// Helper to clear environment variables that might interfere with tests.
fn clear_safeguard_env() {
    let vars = [
        "SAFEGUARD_STRICT",
        "SAFEGUARD_EXPLAIN",
        "SAFEGUARD_NO_COLOR",
        "NO_COLOR",
        "SAFEGUARD_FORMAT",
        "SAFEGUARD_CONTRACT_ID",
        "SAFEGUARD_RPC_URL",
        "SAFEGUARD_MANIFEST",
        "SAFEGUARD_OLD_DIR",
        "SAFEGUARD_NEW_DIR",
        "SAFEGUARD_WASM_PATHS",
        "SAFEGUARD_MAX_XDR_DEPTH",
        "SAFEGUARD_MAX_XDR_LEN",
        "SAFEGUARD_MAX_ENTRIES",
        "SAFEGUARD_MAX_WALK_DEPTH",
        "SAFEGUARD_MAX_SUPPRESSIONS",
        "SAFEGUARD_ALLOW_TARGETLESS",
    ];
    for var in &vars {
        env::remove_var(var);
    }
}

#[test]
fn test_default_config_resolution() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // Default arguments
    let args = Args {
        wasm_paths: vec![PathBuf::from("old.wasm"), PathBuf::from("new.wasm")],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: None,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(
        resolved.wasm_paths,
        vec![PathBuf::from("old.wasm"), PathBuf::from("new.wasm")]
    );
    assert_eq!(resolved.format, OutputFormat::Text);
    assert_eq!(resolved.explain, false);
    assert_eq!(resolved.strict, false);
    assert_eq!(resolved.no_color, false);
    assert_eq!(
        resolved.policy.max_xdr_depth,
        ResourcePolicy::default().max_xdr_depth
    );
}

#[test]
fn test_cli_overrides_env_and_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_cli_overrides.toml");

    fs::write(
        &config_path,
        r#"
        strict = false
        explain = false
        [limits]
        max_xdr_depth = 10
        "#,
    )
    .unwrap();

    // Env vars set values to false/low limits
    env::set_var("SAFEGUARD_STRICT", "false");
    env::set_var("SAFEGUARD_EXPLAIN", "false");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "20");

    // CLI overrides everything to true / high limits
    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Json,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: true, // CLI wins (true)
        strict: true,  // CLI wins (true)
        no_color: true,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: Some(30), // CLI wins (30)
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.policy.max_xdr_depth, 30);

    clear_safeguard_env();
}

#[test]
fn test_env_overrides_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_env_overrides.toml");

    fs::write(
        &config_path,
        r#"
        strict = false
        explain = false
        [limits]
        max_xdr_depth = 10
        "#,
    )
    .unwrap();

    // Env vars set values
    env::set_var("SAFEGUARD_STRICT", "true");
    env::set_var("SAFEGUARD_EXPLAIN", "true");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "20");

    // CLI has None/false, so Env overrides File
    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Json,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.policy.max_xdr_depth, 20);

    clear_safeguard_env();
}

#[test]
fn test_relative_path_resolution() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_relative_paths.toml");

    // Write config file with relative paths
    fs::write(
        &config_path,
        r#"
        manifest = "manifest_rel.toml"
        old_dir = "old_rel"
        new_dir = "new_rel"
        wasm_paths = ["a.wasm", "b.wasm"]
        "#,
    )
    .unwrap();

    let parent = config_path.parent().unwrap().canonicalize().unwrap();

    // Create dummy files/directories so canonicalize succeeds
    fs::write(parent.join("manifest_rel.toml"), "").unwrap();
    fs::create_dir_all(parent.join("old_rel")).unwrap();
    fs::create_dir_all(parent.join("new_rel")).unwrap();
    fs::write(parent.join("a.wasm"), "").unwrap();
    fs::write(parent.join("b.wasm"), "").unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();

    assert_eq!(
        resolved.manifest.unwrap().canonicalize().unwrap(),
        parent.join("manifest_rel.toml").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.old_dir.unwrap().canonicalize().unwrap(),
        parent.join("old_rel").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.new_dir.unwrap().canonicalize().unwrap(),
        parent.join("new_rel").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.wasm_paths[0].canonicalize().unwrap(),
        parent.join("a.wasm").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.wasm_paths[1].canonicalize().unwrap(),
        parent.join("b.wasm").canonicalize().unwrap()
    );
}

#[test]
fn test_mode_resolutions() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. Local Mode
    let config_local = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("a.wasm"), PathBuf::from("b.wasm")],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert_eq!(
        config_local.validate_and_resolve_mode().unwrap(),
        RunMode::Local
    );

    // 2. RPC Mode
    let config_rpc = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: Some("C123".to_string()),
        rpc_url: Some("http://localhost".to_string()),
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert_eq!(
        config_rpc.validate_and_resolve_mode().unwrap(),
        RunMode::Rpc
    );

    // 3. Manifest Mode
    let config_manifest = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: Some(PathBuf::from("manifest.toml")),
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert_eq!(
        config_manifest.validate_and_resolve_mode().unwrap(),
        RunMode::Manifest
    );

    // 4. DirScan Mode
    let config_dir = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: Some(PathBuf::from("old")),
        new_dir: Some(PathBuf::from("new")),
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert_eq!(
        config_dir.validate_and_resolve_mode().unwrap(),
        RunMode::DirScan
    );
}

#[test]
fn test_invalid_mode_combinations() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // Manifest and DirScan specified together
    let config_conflict = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: Some(PathBuf::from("manifest.toml")),
        old_dir: Some(PathBuf::from("old")),
        new_dir: Some(PathBuf::from("new")),
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert!(config_conflict.validate_and_resolve_mode().is_err());

    // RPC missing rpc_url
    let config_missing_rpc = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: Some("C123".to_string()),
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert!(config_missing_rpc.validate_and_resolve_mode().is_err());

    // Local missing old WASM path
    let config_missing_wasm = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
        ..ResolvedConfig::default()
    };
    assert!(config_missing_wasm.validate_and_resolve_mode().is_err());
}

#[test]
fn test_unknown_fields_rejection() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_unknown_fields.toml");

    // TOML config file with unknown keys
    fs::write(
        &config_path,
        r#"
        strict = false
        unknown_key_name_invalid = "hello"
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    assert!(ResolvedConfig::resolve(args).is_err());
}

#[test]
fn test_env_parsing_edge_cases() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. SAFEGUARD_WASM_PATHS contains spaces and empty elements
    env::set_var("SAFEGUARD_WASM_PATHS", "  a.wasm , ,  b.wasm ");
    // 2. Limits env vars contain non-integers (should be ignored / fallback to defaults)
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "notaninteger");
    // 3. Boolean env vars contain garbage (should fallback to false)
    env::set_var("SAFEGUARD_STRICT", "garbage");
    // 4. SAFEGUARD_FORMAT contains garbage (should fallback to default)
    env::set_var("SAFEGUARD_FORMAT", "yaml");

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: None,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(
        resolved.wasm_paths,
        vec![PathBuf::from("a.wasm"), PathBuf::from("b.wasm")]
    );
    assert_eq!(
        resolved.policy.max_xdr_depth,
        ResourcePolicy::default().max_xdr_depth
    );
    assert_eq!(resolved.strict, false);
    assert_eq!(resolved.format, OutputFormat::Text);

    clear_safeguard_env();
}

#[test]
fn test_file_config_partial_deserialization() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_partial_deserialization.toml");

    fs::write(
        &config_path,
        r#"
        no_color = true
        [limits]
        max_entries = 555
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.policy.max_entries, 555);
    // Other values should fall back to default
    assert_eq!(
        resolved.policy.max_xdr_depth,
        ResourcePolicy::default().max_xdr_depth
    );
}

#[test]
fn test_partial_file_config_uses_documented_defaults() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_partial_defaults.toml");

    fs::write(&config_path, "strict = true\n").unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();

    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.format, OutputFormat::Text);
    assert_eq!(resolved.explain, false);
    assert_eq!(resolved.no_color, false);
    assert_eq!(resolved.contract_id, None);
    assert_eq!(resolved.rpc_url, None);
    assert_eq!(resolved.manifest, None);
    assert_eq!(resolved.old_dir, None);
    assert_eq!(resolved.new_dir, None);
    assert_eq!(resolved.suppressions.max_suppressions, None);
    assert_eq!(resolved.suppressions.allow_targetless, None);
    assert_eq!(
        resolved.policy.max_xdr_depth,
        ResourcePolicy::default().max_xdr_depth
    );
    assert_eq!(
        resolved.policy.max_xdr_len,
        ResourcePolicy::default().max_xdr_len
    );
    assert_eq!(
        resolved.policy.max_entries,
        ResourcePolicy::default().max_entries
    );
    assert_eq!(
        resolved.policy.max_walk_depth,
        ResourcePolicy::default().max_walk_depth
    );

    clear_safeguard_env();
}

#[test]
fn test_verdict_settings_mapping() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_verdict_settings.toml");

    fs::write(
        &config_path,
        r#"
        max_suppressions = 999
        allow_targetless = true
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: true,
        strict: true,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: Some(15),
        max_xdr_len: Some(8888),
        max_entries: Some(777),
        max_walk_depth: Some(66),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    let diff_report = soroban_upgrade_safeguard::diff::DiffReport::default();
    let report = soroban_upgrade_safeguard::report::SafetyReport::with_suppressions(
        &diff_report,
        &resolved.suppressions,
        resolved.explain,
        resolved.strict,
        &resolved.policy,
    );

    assert_eq!(report.settings.strict, true);
    assert_eq!(report.settings.explain, true);
    assert_eq!(report.settings.max_suppressions, Some(999));
    assert_eq!(report.settings.allow_targetless, Some(true));
    assert_eq!(report.settings.max_xdr_depth, 15);
    assert_eq!(report.settings.max_xdr_len, 8888);
    assert_eq!(report.settings.max_entries, 777);
    assert_eq!(report.settings.max_walk_depth, 66);
}

#[test]
fn test_env_vars_precedence_layering() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. Env vars overrides defaults and files config
    env::set_var("SAFEGUARD_STRICT", "true");
    env::set_var("SAFEGUARD_EXPLAIN", "true");
    env::set_var("SAFEGUARD_NO_COLOR", "true");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "150");
    env::set_var("SAFEGUARD_MAX_XDR_LEN", "50000");
    env::set_var("SAFEGUARD_MAX_ENTRIES", "2000");
    env::set_var("SAFEGUARD_MAX_WALK_DEPTH", "250");
    env::set_var("SAFEGUARD_MAX_SUPPRESSIONS", "35");
    env::set_var("SAFEGUARD_ALLOW_TARGETLESS", "true");

    let args = Args {
        wasm_paths: vec![],
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.policy.max_xdr_depth, 150);
    assert_eq!(resolved.policy.max_xdr_len, 50000);
    assert_eq!(resolved.policy.max_entries, 2000);
    assert_eq!(resolved.policy.max_walk_depth, 250);
    assert_eq!(resolved.suppressions.max_suppressions, Some(35));
    assert_eq!(resolved.suppressions.allow_targetless, Some(true));

    // 2. CLI flags override environment variables
    env::set_var("SAFEGUARD_STRICT", "false");
    env::set_var("SAFEGUARD_EXPLAIN", "false");
    env::set_var("SAFEGUARD_NO_COLOR", "false");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "100");

    let args_override = Args {
        wasm_paths: vec![],
        strict: true,
        explain: true,
        no_color: true,
        max_xdr_depth: Some(180),
        max_xdr_len: Some(60000),
        max_entries: Some(3000),
        max_walk_depth: Some(350),
        ..Args::default()
    };

    let resolved_override = ResolvedConfig::resolve(args_override).unwrap();
    assert_eq!(resolved_override.strict, true); // CLI overrides env (false -> true)
    assert_eq!(resolved_override.explain, true); // CLI overrides env (false -> true)
    assert_eq!(resolved_override.no_color, true); // CLI overrides env (false -> true)
    assert_eq!(resolved_override.policy.max_xdr_depth, 180); // CLI overrides env (100 -> 180)
    assert_eq!(resolved_override.policy.max_xdr_len, 60000); // CLI overrides env
    assert_eq!(resolved_override.policy.max_entries, 3000); // CLI overrides env
    assert_eq!(resolved_override.policy.max_walk_depth, 350); // CLI overrides env

    clear_safeguard_env();
}

#[test]
fn test_suppressions_expired_rule_validation() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_expired_rule.toml");

    fs::write(
        &config_path,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target = "ConfigData.threshold"
        author = "Alice"
        expiry = "2020-01-01" # expired long ago
        reason = "Legacy deprecation"
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        config: Some(config_path),
        ..Args::default()
    };

    // Resolving config with expired rule should fail validation
    let resolved_err = ResolvedConfig::resolve(args);
    assert!(
        resolved_err.is_err(),
        "Expected error due to expired suppression rule"
    );
    let err_msg = format!("{:?}", resolved_err.err().unwrap());
    assert!(
        err_msg.contains("expired") || err_msg.contains("Expiry"),
        "Error message should mention expiration, got: {}",
        err_msg
    );
}

#[test]
fn test_suppressions_fingerprint_mismatch_validation() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_fingerprint.toml");

    fs::write(
        &config_path,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target = "ConfigData.threshold"
        author = "Alice"
        expiry = "2030-12-31"
        fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
        reason = "Intentional"
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        config: Some(config_path),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.suppressions.rules.len(), 1);

    // Simulate finding matching category and target but different fingerprint
    let finding = soroban_upgrade_safeguard::diff::Finding {
        category: "Struct Field Removed".to_string(),
        type_name: Some("ConfigData".to_string()),
        target: Some("ConfigData.threshold".to_string()),
        message: "Field threshold removed".to_string(),
        severity: soroban_upgrade_safeguard::diff::Severity::Critical,
        axes: Vec::new(),
        change: None,
        root_target: None,
    };

    let matching_rule = resolved.suppressions.matching_rule(&finding);
    assert!(
        matching_rule.is_none(),
        "Rule with mismatched fingerprint should not match the finding"
    );
}

#[test]
fn test_rpc_expected_hash_validation() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let args = Args {
        wasm_paths: vec![],
        expected_wasm_hash: Some("a1b2c3d4e5f6".to_string()),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(
        resolved.expected_wasm_hash,
        Some("a1b2c3d4e5f6".to_string())
    );
}

#[test]
fn test_manifest_relative_paths() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_manifest_paths.toml");

    fs::write(
        &config_path,
        r#"
        manifest = "subdir/manifest.toml"
        "#,
    )
    .unwrap();

    let subdir = temp_dir.join("subdir");
    fs::create_dir_all(&subdir).unwrap();
    fs::write(subdir.join("manifest.toml"), "pairs = []").unwrap();

    let args = Args {
        wasm_paths: vec![],
        config: Some(config_path.clone()),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    let expected = config_path
        .parent()
        .unwrap()
        .join("subdir/manifest.toml")
        .canonicalize()
        .unwrap();
    assert_eq!(resolved.manifest.unwrap().canonicalize().unwrap(), expected);
}

#[test]
fn test_env_vars_mapping_exhaustive() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    env::set_var("SAFEGUARD_FORMAT", "markdown");
    env::set_var("SAFEGUARD_EXPLAIN", "1");
    env::set_var("SAFEGUARD_STRICT", "1");
    env::set_var("SAFEGUARD_NO_COLOR", "1");
    env::set_var("SAFEGUARD_MANIFEST", "manifest_env.toml");
    env::set_var("SAFEGUARD_OLD_DIR", "old_dir_env");
    env::set_var("SAFEGUARD_NEW_DIR", "new_dir_env");
    env::set_var("SAFEGUARD_WASM_PATHS", "env_a.wasm,env_b.wasm");
    env::set_var("SAFEGUARD_CONTRACT_ID", "C_ENV");
    env::set_var("SAFEGUARD_RPC_URL", "http://env_rpc");

    let args = Args {
        wasm_paths: vec![],
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.format, OutputFormat::Markdown);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.manifest, Some(PathBuf::from("manifest_env.toml")));
    assert_eq!(resolved.old_dir, Some(PathBuf::from("old_dir_env")));
    assert_eq!(resolved.new_dir, Some(PathBuf::from("new_dir_env")));
    assert_eq!(
        resolved.wasm_paths,
        vec![PathBuf::from("env_a.wasm"), PathBuf::from("env_b.wasm")]
    );
    assert_eq!(resolved.contract_id, Some("C_ENV".to_string()));
    assert_eq!(resolved.rpc_url, Some("http://env_rpc".to_string()));

    clear_safeguard_env();
}

#[test]
fn test_resolved_config_debug_serialize() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let resolved = ResolvedConfig::default();

    // Verify Debug representation
    let debug_str = format!("{:?}", resolved);
    assert!(debug_str.contains("ResolvedConfig"));

    // Verify serialization logic
    let serialized = serde_json::to_string(&resolved).unwrap();
    assert!(serialized.contains("wasm_paths"));
    assert!(serialized.contains("contract_id"));
    assert!(serialized.contains("rpc_url"));
}

#[test]
fn test_config_file_resolution_missing_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    let args = Args {
        wasm_paths: vec![],
        config: Some(PathBuf::from("nonexistent_config_file_12345.toml")),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args);
    assert!(
        resolved.is_err(),
        "Expected error when specifying a nonexistent configuration file"
    );
}

#[test]
fn test_args_validation_clashing_options() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. Contract ID and Manifest specified together
    let config_clash_1 = ResolvedConfig {
        manifest: Some(PathBuf::from("manifest.toml")),
        contract_id: Some("C123".to_string()),
        ..ResolvedConfig::default()
    };
    assert!(config_clash_1.validate_and_resolve_mode().is_err());

    // 2. RPC URL and Old Dir specified together
    let config_clash_2 = ResolvedConfig {
        old_dir: Some(PathBuf::from("old")),
        rpc_url: Some("http://localhost".to_string()),
        ..ResolvedConfig::default()
    };
    assert!(config_clash_2.validate_and_resolve_mode().is_err());
}

#[test]
fn test_suppressions_expiry_date_bounds() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_date_bounds.toml");

    // Test a malformed date format
    fs::write(
        &config_path,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target = "ConfigData.threshold"
        author = "Alice"
        expiry = "not-a-date"
        reason = "Invalid format"
        "#,
    )
    .unwrap();

    let args = Args {
        wasm_paths: vec![],
        config: Some(config_path.clone()),
        ..Args::default()
    };

    let resolved = ResolvedConfig::resolve(args);
    assert!(resolved.is_err(), "Expected error on malformed date string");

    // Test a valid future leap-year date
    fs::write(
        &config_path,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target = "ConfigData.threshold"
        author = "Alice"
        expiry = "2028-02-29" # Leap year day
        reason = "Valid leap day"
        "#,
    )
    .unwrap();

    let args_leap = Args {
        wasm_paths: vec![],
        config: Some(config_path),
        ..Args::default()
    };

    let resolved_leap = ResolvedConfig::resolve(args_leap).unwrap();
    assert_eq!(resolved_leap.suppressions.rules.len(), 1);
}

#[test]
fn test_parse_policy_config_defaults() {
    use soroban_upgrade_safeguard::suppression::SuppressionConfig;
    let toml_str = r#"
        [[suppress]]
        category = "Struct Field Removed"
        reason = "Acknowledge"
    "#;
    let config = SuppressionConfig::from_toml_str(toml_str).unwrap();
    assert!(config.policy.gate_storage_layout);
    assert!(config.policy.gate_call_abi);
    assert!(!config.policy.gate_event_indexer);
    assert!(!config.policy.gate_source_level);
}

#[test]
fn test_parse_custom_policy_config() {
    use soroban_upgrade_safeguard::suppression::SuppressionConfig;
    let toml_str = r#"
        [policy]
        gate_storage_layout = false
        gate_call_abi = false
        gate_event_indexer = true
        gate_source_level = true
    "#;
    let config = SuppressionConfig::from_toml_str(toml_str).unwrap();
    assert!(!config.policy.gate_storage_layout);
    assert!(!config.policy.gate_call_abi);
    assert!(config.policy.gate_event_indexer);
    assert!(config.policy.gate_source_level);
}
