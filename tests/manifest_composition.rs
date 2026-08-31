//! Integration tests for composable batch manifests: `include`, `[defaults]`,
//! and per-pair overrides.
//!
//! These drive the compiled binary rather than the library, because the whole
//! point of the feature is what a CI invocation sees: the exit code, the
//! provenance in the batch JSON, and the quality of the error when a manifest is
//! wrong. Unit-level precedence coverage lives in `src/manifest.rs`.
//!
//! The checked-in fixtures give three verdicts to compose with:
//!
//! - `v1 -> v1` safe
//! - `v1 -> v2` breaking (3 criticals)
//! - `v1 -> v3` warning-only: passes normally, fails under `--strict`

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// A fresh directory for one test. Includes require real directory trees, so
/// each test gets its own root, isolated by process id.
fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

/// Write `contents` to `dir/name`, creating parent directories as needed.
fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

/// Copy the fixture WASMs into `dir` so manifests can reference them by bare
/// file name and exercise `base_dir` / relative-path anchoring.
fn stage_wasm(dir: &Path) {
    std::fs::create_dir_all(dir).expect("failed to create wasm dir");
    for name in ["v1.wasm", "v2.wasm", "v3.wasm"] {
        std::fs::copy(wasm(name), dir.join(name)).expect("failed to copy fixture wasm");
    }
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout was not valid JSON ({e}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Run the binary with `args`, from `cwd` when given.
fn run_in(cwd: Option<&Path>, args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let output = command.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code().expect("process terminated by signal"),
    }
}

/// Run a manifest in JSON mode, deterministically.
fn run_manifest(manifest: &Path, extra: &[&str]) -> Run {
    let mut args = vec![
        "--manifest",
        manifest.to_str().unwrap(),
        "--format",
        "json",
        "--no-timestamp",
    ];
    args.extend_from_slice(extra);
    run_in(None, &args)
}

/// The `{value, origin}` pair for one setting of one named pair.
fn setting<'a>(json: &'a Value, pair_name: &str, path: &[&str]) -> &'a Value {
    let pair = json["manifest"]["pairs"]
        .as_array()
        .expect("manifest.pairs must be an array")
        .iter()
        .find(|p| p["name"] == pair_name)
        .unwrap_or_else(|| panic!("no pair named '{pair_name}' in manifest provenance"));
    let mut node = &pair["settings"];
    for key in path {
        node = &node[*key];
    }
    node
}

fn origin_of(json: &Value, pair_name: &str, path: &[&str]) -> String {
    setting(json, pair_name, path)["origin"]
        .as_str()
        .expect("origin must be a string")
        .to_string()
}

fn result<'a>(json: &'a Value, pair_name: &str) -> &'a Value {
    json["results"]
        .as_array()
        .expect("results must be an ordered array")
        .iter()
        .find(|entry| entry["name"] == pair_name)
        .and_then(|entry| entry.get("report"))
        .unwrap_or_else(|| panic!("no result named '{pair_name}'"))
}

// ── Composition ──────────────────────────────────────────────────────────────

#[test]
fn nested_includes_compose_depth_first() {
    let dir = temp_dir("mc-nested");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "b.toml",
        &format!(
            r#"
            [defaults]
            base_dir = {:?}

            [[pairs]]
            old  = "v1.wasm"
            new  = "v1.wasm"
            name = "b"
            "#,
            dir.join("wasm").to_str().unwrap()
        ),
    );
    write(
        &dir,
        "a.toml",
        &format!(
            r#"
            include = ["b.toml"]

            [defaults]
            base_dir = {:?}

            [[pairs]]
            old  = "v1.wasm"
            new  = "v1.wasm"
            name = "a"
            "#,
            dir.join("wasm").to_str().unwrap()
        ),
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["a.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "all pairs are safe\nstderr:\n{}", run.stderr);

    let json = run.json();
    assert_eq!(json["total_pairs"], 3);

    // Composed order is depth-first: a file's includes before its own pairs.
    let names: Vec<&str> = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["b", "a", "root"]);

    // Every contributing file is listed, in first-visit order.
    let sources: Vec<String> = json["manifest"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            Path::new(s.as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    assert_eq!(sources, vec!["b.toml", "a.toml", "root.toml"]);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["name"], "b");
    assert_eq!(results[1]["name"], "a");
    assert_eq!(results[2]["name"], "root");
}

#[test]
fn pair_beats_root_defaults_beats_included_defaults() {
    let dir = temp_dir("mc-override");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "common/policy.toml",
        r#"
        [defaults.policy]
        gate_event_indexer = true
        gate_source_level  = true
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["common/policy.toml"]

        [defaults]
        base_dir = "wasm"

        [defaults.policy]
        gate_source_level = false

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "inherits"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "overrides"

        [pairs.policy]
        gate_event_indexer = false
        "#,
    );

    let json = run_manifest(&root, &[]).json();

    // Included fragment wins where nothing later speaks.
    assert_eq!(
        setting(&json, "inherits", &["policy", "gate_event_indexer"])["value"],
        true
    );
    assert!(
        origin_of(&json, "inherits", &["policy", "gate_event_indexer"]).ends_with("policy.toml")
    );

    // Root [defaults] beats the included fragment.
    assert_eq!(
        setting(&json, "inherits", &["policy", "gate_source_level"])["value"],
        false
    );
    assert!(origin_of(&json, "inherits", &["policy", "gate_source_level"]).ends_with("root.toml"));

    // A pair field beats root [defaults].
    assert_eq!(
        setting(&json, "overrides", &["policy", "gate_event_indexer"])["value"],
        false
    );
    assert!(
        origin_of(&json, "overrides", &["policy", "gate_event_indexer"]).ends_with("root.toml")
    );

    // Untouched settings report the built-in default honestly.
    assert_eq!(
        origin_of(&json, "inherits", &["policy", "gate_storage_layout"]),
        "built-in"
    );
}

// ── Escalation vs valued ─────────────────────────────────────────────────────

#[test]
fn strict_escalates_per_pair_and_cli_strict_cannot_be_disabled() {
    let dir = temp_dir("mc-escalation");
    stage_wasm(&dir.join("wasm"));

    // `v1 -> v3` is warning-only: it passes normally and fails under --strict,
    // so `strict` is observable in the exit code rather than only in provenance.
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"
        strict   = false

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "lenient"
        "#,
    );
    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "warning-only pair passes without strict");

    // A pair may escalate on its own.
    let strict_pair = write(
        &dir,
        "strict_pair.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v3.wasm"
        name   = "picky"
        strict = true
        "#,
    );
    let run = run_manifest(&strict_pair, &[]);
    assert_eq!(
        run.code, 1,
        "a pair-level strict must fail the warning-only pair"
    );
    assert!(origin_of(&run.json(), "picky", &["strict"]).ends_with("strict_pair.toml"));

    // --strict is an escalation: `strict = false` in the manifest cannot weaken it.
    let run = run_manifest(&root, &["--strict"]);
    assert_eq!(
        run.code, 1,
        "manifest strict=false must not be able to disable --strict"
    );
    assert_eq!(origin_of(&run.json(), "lenient", &["strict"]), "cli");
    assert_eq!(setting(&run.json(), "lenient", &["strict"])["value"], true);
}

#[test]
fn a_gate_can_be_turned_off_because_gates_are_valued_not_escalation() {
    let dir = temp_dir("mc-gate-off");
    stage_wasm(&dir.join("wasm"));

    // `v1 -> v2` breaks the call ABI. Ungating that axis is the whole point of
    // `[policy]`, so unlike `strict` it must be able to move in both directions.
    let gated = write(
        &dir,
        "gated.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );
    assert_eq!(
        run_manifest(&gated, &[]).code,
        1,
        "call-ABI break fails by default"
    );

    let ungated = write(
        &dir,
        "ungated.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"

        [pairs.policy]
        gate_call_abi       = false
        gate_storage_layout = false
        "#,
    );
    let run = run_manifest(&ungated, &[]);
    assert_eq!(run.code, 0, "ungating the failing axes must pass the run");

    let json = run.json();
    assert_eq!(
        setting(&json, "token", &["policy", "gate_call_abi"])["value"],
        false
    );
    // The findings are still reported — ungating changes the verdict, not visibility.
    assert_eq!(result(&json, "token")["counts"]["critical"], 3);
}

#[test]
fn per_pair_config_applies_only_to_its_own_pair() {
    let dir = temp_dir("mc-per-pair-config");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "token.safeguard.toml",
        r#"
        [[suppress]]
        category = "Event Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        reason   = "Reviewed: indexers already updated."

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "Planned re-init for the v2 migration."

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Reviewed."
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v2.wasm"
        name   = "suppressed"
        config = "token.safeguard.toml"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "unsuppressed"
        "#,
    );

    let run = run_manifest(&root, &[]);
    let json = run.json();

    // The config applies to the pair that named it. Suppressed findings stay
    // counted and visible — suppression flips the verdict, not the tally.
    assert_eq!(result(&json, "suppressed")["counts"]["critical"], 3);
    assert_eq!(result(&json, "suppressed")["suppressed_count"], 3);
    assert_eq!(result(&json, "suppressed")["is_safe"], true);

    // ...and not to its sibling, which sees the same three findings unsuppressed.
    assert_eq!(result(&json, "unsuppressed")["counts"]["critical"], 3);
    assert_eq!(result(&json, "unsuppressed")["suppressed_count"], 0);
    assert_eq!(result(&json, "unsuppressed")["is_safe"], false);

    // One pair still failing keeps the batch verdict failing.
    assert_eq!(run.code, 1);
    assert_eq!(json["is_safe"], false);

    assert!(origin_of(&json, "suppressed", &["config"]).ends_with("root.toml"));
    assert_eq!(origin_of(&json, "unsuppressed", &["config"]), "built-in");
}

// ── Path resolution ──────────────────────────────────────────────────────────

#[test]
fn relative_paths_anchor_on_the_defining_file_not_the_cwd() {
    let dir = temp_dir("mc-paths");
    stage_wasm(&dir.join("wasm"));

    // The fragment sits one level down and reaches back up with `../wasm`.
    write(
        &dir,
        "fragments/pool.toml",
        r#"
        [defaults]
        base_dir = "../wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/pool.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    // Run from a directory that is *not* the manifest's, so a CWD-relative
    // implementation would fail to find any fixture.
    let elsewhere = temp_dir("mc-paths-cwd");
    let run = run_in(
        Some(&elsewhere),
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--format",
            "json",
            "--no-timestamp",
        ],
    );
    assert_eq!(
        run.code, 0,
        "manifest must resolve relative to its own file\nstderr:\n{}",
        run.stderr
    );

    let json = run.json();
    let pairs = json["manifest"]["pairs"].as_array().unwrap();
    for pair in pairs {
        let old = pair["old"].as_str().unwrap();
        assert!(
            Path::new(old).is_absolute() && Path::new(old).exists(),
            "resolved path must exist: {old}"
        );
    }
}

#[test]
fn root_base_dir_does_not_reach_into_an_included_fragment() {
    let dir = temp_dir("mc-base-scope");
    stage_wasm(&dir.join("pool_artifacts"));
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "fragments/pool.toml",
        r#"
        [defaults]
        base_dir = "../pool_artifacts"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/pool.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    let json = run_manifest(&root, &[]).json();
    let pairs = json["manifest"]["pairs"].as_array().unwrap();
    let pool = pairs.iter().find(|p| p["name"] == "pool").unwrap();
    let root_pair = pairs.iter().find(|p| p["name"] == "root").unwrap();

    // `base_dir` is file-scoped: the fragment keeps its own anchoring so it stays
    // relocatable, and the root's `base_dir` governs only the root's own pairs.
    assert!(
        pool["old"].as_str().unwrap().contains("pool_artifacts"),
        "fragment lost its own base_dir: {}",
        pool["old"]
    );
    assert!(
        root_pair["old"].as_str().unwrap().contains("wasm"),
        "root pair lost the root base_dir: {}",
        root_pair["old"]
    );
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[test]
fn duplicate_pair_names_fail_before_anything_runs() {
    let dir = temp_dir("mc-duplicate");
    stage_wasm(&dir.join("wasm"));
    let reports = dir.join("reports");

    write(
        &dir,
        "frag.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["frag.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Duplicate contract name 'token'"),
        "error must name the collision: {combined}"
    );
    // Both sides of the collision are named, so the fix is obvious.
    assert!(
        combined.contains("frag.toml"),
        "missing first file: {combined}"
    );
    assert!(
        combined.contains("root.toml"),
        "missing second file: {combined}"
    );

    // Detection runs ahead of execution, so no partial reports hit disk.
    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

// ── Pair IDs ─────────────────────────────────────────────────────────────────

#[test]
fn explicit_pair_id_is_accepted_in_a_toml_manifest_and_appears_in_batch_json() {
    let dir = temp_dir("mc-id-toml");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "Token (v1, safe)"
        id   = "token-safe"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();

    let entry = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "Token (v1, safe)")
        .expect("result entry must be present");
    assert_eq!(entry["id"], "token-safe");

    let pair = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "Token (v1, safe)")
        .expect("manifest pair provenance must be present");
    assert_eq!(pair["id"], "token-safe");
}

#[test]
fn explicit_pair_id_is_accepted_in_a_json_manifest() {
    let dir = temp_dir("mc-id-json");
    stage_wasm(&dir.join("wasm"));
    let manifest = serde_json::json!({
        "defaults": { "base_dir": "wasm" },
        "pairs": [
            { "old": "v1.wasm", "new": "v1.wasm", "name": "token", "id": "token-1" }
        ]
    })
    .to_string();
    let root = write(&dir, "root.json", &manifest);

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();
    let entry = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "token")
        .expect("result entry must be present");
    assert_eq!(entry["id"], "token-1");
}

#[test]
fn omitted_pair_id_falls_back_deterministically_to_the_resolved_name() {
    let dir = temp_dir("mc-id-fallback");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();
    let entry = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "token")
        .expect("result entry must be present");
    // No `id` set -> falls back to the resolved `name`.
    assert_eq!(entry["id"], "token");
}

#[test]
fn duplicate_pair_ids_fail_before_anything_runs() {
    let dir = temp_dir("mc-id-duplicate");
    stage_wasm(&dir.join("wasm"));
    let reports = dir.join("reports");

    write(
        &dir,
        "frag.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token-a"
        id   = "shared"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["frag.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token-b"
        id   = "shared"
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Duplicate pair id 'shared'"),
        "error must name the collision: {combined}"
    );
    assert!(
        combined.contains("frag.toml"),
        "missing first file: {combined}"
    );
    assert!(
        combined.contains("root.toml"),
        "missing second file: {combined}"
    );

    // Detection runs ahead of execution, so no partial reports hit disk.
    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

#[test]
fn duplicate_pair_ids_fail_in_a_json_manifest_too() {
    let dir = temp_dir("mc-id-duplicate-json");
    stage_wasm(&dir.join("wasm"));
    let manifest = serde_json::json!({
        "defaults": { "base_dir": "wasm" },
        "pairs": [
            { "old": "v1.wasm", "new": "v1.wasm", "name": "token-a", "id": "shared" },
            { "old": "v1.wasm", "new": "v2.wasm", "name": "token-b", "id": "shared" }
        ]
    })
    .to_string();
    let root = write(&dir, "root.json", &manifest);

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Duplicate pair id 'shared'"),
        "error must name the collision: {combined}"
    );
}

#[test]
fn invalid_pair_id_is_rejected_before_anything_runs() {
    let dir = temp_dir("mc-id-invalid");
    stage_wasm(&dir.join("wasm"));
    let reports = dir.join("reports");
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"
        id   = "not a valid id!"
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Invalid pair id 'not a valid id!'"),
        "error must name the offending id: {combined}"
    );
    assert!(
        combined.contains(root.file_name().unwrap().to_str().unwrap())
            || combined.contains("root.toml"),
        "error should name the source manifest: {combined}"
    );

    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

#[test]
fn empty_pair_id_is_rejected() {
    let dir = temp_dir("mc-id-empty");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old = "v1.wasm"
        new = "v1.wasm"
        id  = ""
        "#,
    );

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(combined.contains("Invalid pair id"), "got: {combined}");
}

#[test]
fn explain_manifest_reports_pair_ids() {
    let dir = temp_dir("mc-id-explain");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"
        id   = "token-1"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--explain-manifest"],
    );
    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("token-1"),
        "explain-manifest output should show the resolved id: {}",
        run.stdout
    );
}

#[test]
fn include_cycle_reports_the_chain_and_writes_nothing() {
    let dir = temp_dir("mc-cycle");
    let reports = dir.join("reports");

    write(&dir, "b.toml", r#"include = ["a.toml"]"#);
    write(&dir, "a.toml", r#"include = ["b.toml"]"#);
    let root = write(&dir, "root.toml", r#"include = ["a.toml"]"#);

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("include cycle"),
        "must identify the cycle: {combined}"
    );
    assert!(combined.contains('→'), "must print the chain: {combined}");
    assert!(combined.contains("a.toml") && combined.contains("b.toml"));
    assert!(
        !reports.exists(),
        "no output may be written for an unresolvable manifest"
    );
}

#[test]
fn include_depth_cap_is_enforced_at_nine_and_allows_eight() {
    let dir = temp_dir("mc-depth");
    stage_wasm(&dir.join("wasm"));

    // `level0` is the root, so a chain ending at `level{n}` has depth n.
    let build_chain = |prefix: &str, deepest: usize| {
        for level in 0..=deepest {
            let contents = if level == deepest {
                format!(
                    r#"
                    [defaults]
                    base_dir = {:?}

                    [[pairs]]
                    old  = "v1.wasm"
                    new  = "v1.wasm"
                    name = "deep"
                    "#,
                    dir.join("wasm").to_str().unwrap()
                )
            } else {
                format!("include = [\"{prefix}{}.toml\"]", level + 1)
            };
            write(&dir, &format!("{prefix}{level}.toml"), &contents);
        }
        dir.join(format!("{prefix}0.toml"))
    };

    let ok_root = build_chain("ok", 8);
    let run = run_manifest(&ok_root, &[]);
    assert_eq!(
        run.code, 0,
        "a chain exactly at the cap must resolve\nstderr:\n{}",
        run.stderr
    );

    let deep_root = build_chain("deep", 9);
    let run = run_in(None, &["--manifest", deep_root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("maximum depth"),
        "must explain the cap: {combined}"
    );
}

#[test]
fn unknown_fields_are_rejected_wherever_they_appear() {
    let dir = temp_dir("mc-unknown");
    stage_wasm(&dir.join("wasm"));

    let cases = [
        // Top level.
        (
            "root_typo.toml",
            r#"
            includes = ["other.toml"]

            [[pairs]]
            old = "wasm/v1.wasm"
            new = "wasm/v1.wasm"
            "#,
            "includes",
        ),
        // Inside [defaults].
        (
            "defaults_typo.toml",
            r#"
            [defaults]
            strictt = true

            [[pairs]]
            old = "wasm/v1.wasm"
            new = "wasm/v1.wasm"
            "#,
            "strictt",
        ),
        // On a pair.
        (
            "pair_typo.toml",
            r#"
            [[pairs]]
            old     = "wasm/v1.wasm"
            new     = "wasm/v1.wasm"
            explainn = true
            "#,
            "explainn",
        ),
    ];

    for (file, contents, typo) in cases {
        let path = write(&dir, file, contents);
        let run = run_in(None, &["--manifest", path.to_str().unwrap()]);
        assert_eq!(run.code, 1, "{file} must fail");
        let combined = format!("{}{}", run.stdout, run.stderr);
        assert!(
            combined.contains(typo),
            "error for {file} must name '{typo}': {combined}"
        );
    }
}

#[test]
fn a_typo_in_an_included_fragment_is_rejected_and_names_the_fragment() {
    let dir = temp_dir("mc-unknown-fragment");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "fragments/bad.toml",
        r#"
        [defaults]
        base_dirr = "wasm"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/bad.toml"]

        [[pairs]]
        old = "wasm/v1.wasm"
        new = "wasm/v1.wasm"
        "#,
    );

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("base_dirr"),
        "must name the typo: {combined}"
    );
    assert!(
        combined.contains("bad.toml"),
        "must name the fragment that holds it: {combined}"
    );
}

#[test]
fn malformed_manifest_reports_both_parser_errors_with_position() {
    let dir = temp_dir("mc-parse-error");
    let root = write(&dir, "root.toml", "[[pairs]\nold = \"a.wasm\"\n");

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    // The old message was just "as either TOML or JSON", with both errors
    // discarded — undebuggable once includes multiply the candidate files.
    assert!(
        combined.contains("TOML error:"),
        "missing TOML error: {combined}"
    );
    assert!(
        combined.contains("JSON error:"),
        "missing JSON error: {combined}"
    );
    assert!(
        combined.contains("line 1"),
        "the TOML error must carry a position: {combined}"
    );
}

#[test]
fn a_missing_include_names_the_referring_file() {
    let dir = temp_dir("mc-missing-include");
    let root = write(&dir, "root.toml", r#"include = ["nope.toml"]"#);

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("nope.toml"),
        "must name the target: {combined}"
    );
    assert!(
        combined.contains("root.toml"),
        "must name the referrer: {combined}"
    );
}

// ── Backward compatibility ───────────────────────────────────────────────────

#[test]
fn a_flat_toml_manifest_behaves_exactly_as_before() {
    let dir = temp_dir("mc-compat-toml");

    // No [defaults], no include, absolute paths — the pre-composition form.
    let root = write(
        &dir,
        "root.toml",
        &format!(
            r#"
            [[pairs]]
            old  = {:?}
            new  = {:?}
            name = "clean_contract"

            [[pairs]]
            old  = {:?}
            new  = {:?}
            name = "breaking_contract"
            "#,
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v2.wasm").to_str().unwrap(),
        ),
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(json["total_pairs"], 2);
    assert_eq!(json["is_safe"], false);
    assert_eq!(result(&json, "clean_contract")["is_safe"], true);
    assert_eq!(result(&json, "breaking_contract")["counts"]["critical"], 3);
}

#[test]
fn a_flat_json_manifest_behaves_exactly_as_before() {
    let dir = temp_dir("mc-compat-json");

    let root = write(
        &dir,
        "root.json",
        &serde_json::json!({
            "pairs": [
                { "old": wasm("v1.wasm"), "new": wasm("v1.wasm"), "name": "clean" },
                { "old": wasm("v1.wasm"), "new": wasm("v2.wasm"), "name": "breaking" },
            ]
        })
        .to_string(),
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(json["total_pairs"], 2);
    assert_eq!(result(&json, "clean")["is_safe"], true);
    assert_eq!(result(&json, "breaking")["counts"]["critical"], 3);
}

#[test]
fn a_manifest_declaring_dependencies_still_parses() {
    let dir = temp_dir("mc-compat-deps");
    stage_wasm(&dir.join("wasm"));

    // `[[dependencies]]` has been documented in `src/dependency.rs` since before
    // it was parseable. Adding deny_unknown_fields must not turn a manifest
    // written from those docs into a hard error, so the block is accepted and
    // reported — propagation stays unwired.
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"

        [[dependencies]]
        caller    = "pool"
        callee    = "token"
        functions = ["transfer", "balance"]
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);

    let json = run.json();
    let deps = json["manifest"]["dependencies"].as_array().unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0]["caller"], "pool");
    assert_eq!(deps[0]["callee"], "token");
    assert!(deps[0]["defined_in"]
        .as_str()
        .unwrap()
        .ends_with("root.toml"));
}

#[test]
fn directory_scan_mode_is_unaffected_and_emits_no_manifest_block() {
    let dir = temp_dir("mc-dirscan");
    let old_dir = dir.join("old");
    let new_dir = dir.join("new");
    std::fs::create_dir_all(&old_dir).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();
    std::fs::copy(wasm("v1.wasm"), old_dir.join("token.wasm")).unwrap();
    std::fs::copy(wasm("v2.wasm"), new_dir.join("token.wasm")).unwrap();

    let run = run_in(
        None,
        &[
            "--old-dir",
            old_dir.to_str().unwrap(),
            "--new-dir",
            new_dir.to_str().unwrap(),
            "--format",
            "json",
            "--no-timestamp",
        ],
    );
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(result(&json, "token")["counts"]["critical"], 3);
    // There is no composition to describe, so the key is absent rather than empty.
    assert!(
        json.get("manifest").is_none(),
        "directory scans must not emit a manifest block"
    );
}

// ── --explain-manifest ───────────────────────────────────────────────────────

#[test]
fn explain_manifest_resolves_without_comparing_anything() {
    let dir = temp_dir("mc-explain");
    // Deliberately do NOT stage the WASM files: resolution must not need them.
    write(
        &dir,
        "common/policy.toml",
        r#"
        [defaults.limits]
        max_xdr_depth = 32
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["common/policy.toml"]

        [defaults]
        base_dir = "wasm"
        strict   = true

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--explain-manifest"],
    );
    assert_eq!(
        run.code, 0,
        "resolution alone must exit 0\nstderr:\n{}",
        run.stderr
    );

    let out = run.stdout;
    assert!(out.contains("Manifest resolution"));
    assert!(
        out.contains("root.toml") && out.contains("policy.toml"),
        "sources missing: {out}"
    );
    assert!(out.contains("[1] token"), "pair missing: {out}");
    assert!(out.contains("strict"), "settings missing: {out}");
    assert!(out.contains("built-in"), "origins missing: {out}");
    assert!(out.contains("32"), "included limit missing: {out}");

    // Nothing was compared: no verdict, no findings.
    assert!(
        !out.contains("SOROBAN BATCH SAFETY REPORT"),
        "must not run: {out}"
    );
    assert!(!out.contains("Critical"), "must not report findings: {out}");
}

#[test]
fn explain_manifest_requires_a_manifest() {
    let run = run_in(None, &["--explain-manifest"]);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("--manifest"),
        "must point at the missing flag: {}",
        run.stderr
    );
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn the_same_manifest_yields_byte_identical_json() {
    let dir = temp_dir("mc-determinism");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "frag.toml",
        r#"
        [defaults.policy]
        gate_event_indexer = true
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["frag.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "b"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "a"
        "#,
    );

    let first = run_manifest(&root, &[]);
    let second = run_manifest(&root, &[]);
    assert_eq!(first.code, second.code);

    // Byte-identity is asserted on the `manifest` block specifically, not on the
    // whole document. The finding stream is ordered by iteration over the
    // `HashMap`s in `spec.rs`, so `findings_by_category` reorders between runs —
    // a pre-existing defect reproducible on a plain single-pair run with
    // `--no-timestamp` and unrelated to manifest composition. Asserting the whole
    // document here would make this test a flaky proxy for that bug; when it is
    // fixed, widen this to `first.stdout == second.stdout`.
    let manifest_of = |run: &Run| serde_json::to_string_pretty(&run.json()["manifest"]).unwrap();
    assert_eq!(
        manifest_of(&first),
        manifest_of(&second),
        "resolved manifest provenance must be byte-identical across runs"
    );
    assert_eq!(first.json()["is_safe"], second.json()["is_safe"]);
    assert_eq!(first.json()["total_pairs"], second.json()["total_pairs"]);

    // Report order follows manifest composition order.
    let json = first.json();
    let names: Vec<&str> = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["b", "a"]);

    // Provenance keeps composition order, which is the useful order there.
    let pair_names: Vec<&str> = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(pair_names, vec!["b", "a"]);
}

// ── Verdict summary ──────────────────────────────────────────────────────────

/// A manifest with one pair in each of the four verdict categories:
///
/// - `safe-pair`: v1 -> v1, schema-backed, no breaking changes.
/// - `unsafe-pair`: v1 -> v2, breaking changes (3 criticals).
/// - `incomplete-pair`: v1 -> v1, no storage schema (interface-only), no
///   breaking changes.
/// - `errored-pair`: only one of `old_storage_schema`/`new_storage_schema`
///   set, a partial declaration that fails per-pair without a compatibility
///   verdict ever being reached.
fn write_mixed_verdict_manifest(dir: &Path) -> PathBuf {
    stage_wasm(&dir.join("wasm"));
    write(dir, "schemas/empty.json", r#"{"declarations": []}"#);

    write(
        dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "safe-pair"
        old_storage_schema = "schemas/empty.json"
        new_storage_schema = "schemas/empty.json"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "unsafe-pair"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "incomplete-pair"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "errored-pair"
        old_storage_schema = "schemas/empty.json"
        "#,
    )
}

#[test]
fn batch_summary_counts_every_verdict_category_in_json() {
    let dir = temp_dir("mc-verdict-json");
    let root = write_mixed_verdict_manifest(&dir);

    let run = run_manifest(&root, &[]);
    assert_eq!(
        run.code, 1,
        "an unsafe/errored pair in the batch must fail the run"
    );
    let json = run.json();

    assert_eq!(json["summary"]["safe"], 1, "summary: {}", json["summary"]);
    assert_eq!(json["summary"]["unsafe"], 1, "summary: {}", json["summary"]);
    assert_eq!(
        json["summary"]["errored"], 1,
        "summary: {}",
        json["summary"]
    );
    assert_eq!(
        json["summary"]["incomplete"], 1,
        "summary: {}",
        json["summary"]
    );
    assert_eq!(json["summary"]["total"], 4, "summary: {}", json["summary"]);

    // The summary is a tally, not a replacement: every per-pair result and
    // its findings must still be present and untouched.
    assert_eq!(json["results"].as_array().unwrap().len(), 4);
    assert_eq!(
        result(&json, "unsafe-pair")["counts"]["critical"],
        3,
        "per-pair findings must survive alongside the summary"
    );
    assert_eq!(result(&json, "safe-pair")["is_safe"], true);
    assert_eq!(result(&json, "incomplete-pair")["is_safe"], true);

    let errored_entry = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "errored-pair")
        .expect("errored-pair result must be present");
    assert!(
        errored_entry.get("error").is_some(),
        "errored-pair must carry a pair error: {errored_entry}"
    );
}

#[test]
fn batch_summary_appears_before_detailed_results_in_text_output() {
    let dir = temp_dir("mc-verdict-text");
    let root = write_mixed_verdict_manifest(&dir);

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);

    let summary_pos = run
        .stdout
        .find("Verdict Summary:")
        .expect("text output must include a Verdict Summary line");
    assert!(
        run.stdout
            .contains("1 safe, 1 unsafe, 1 errored, 1 incomplete (4 total)"),
        "counts must match the mixed batch, got:\n{}",
        run.stdout
    );

    let details_pos = run
        .stdout
        .find("=== Contract:")
        .expect("detailed per-contract sections must still be present");
    assert!(
        summary_pos < details_pos,
        "the verdict summary must appear before detailed results"
    );
}

#[test]
fn batch_summary_appears_before_detailed_results_in_markdown_output() {
    let dir = temp_dir("mc-verdict-markdown");
    let root = write_mixed_verdict_manifest(&dir);

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--format", "markdown"],
    );
    assert_eq!(run.code, 1);

    let summary_pos = run
        .stdout
        .find("### Verdict Summary")
        .expect("markdown output must include a Verdict Summary section");
    assert!(
        run.stdout.contains("| 1 | 1 | 1 | 1 | 4 |"),
        "the verdict table row must match the mixed batch, got:\n{}",
        run.stdout
    );

    let details_pos = run
        .stdout
        .find("## Details:")
        .expect("detailed per-contract sections must still be present");
    assert!(
        summary_pos < details_pos,
        "the verdict summary must appear before detailed results"
    );
}

#[test]
fn batch_summary_is_all_safe_when_every_pair_is_schema_backed_and_clean() {
    let dir = temp_dir("mc-verdict-all-safe");
    stage_wasm(&dir.join("wasm"));
    write(&dir, "schemas/empty.json", r#"{"declarations": []}"#);
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "a"
        old_storage_schema = "schemas/empty.json"
        new_storage_schema = "schemas/empty.json"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "b"
        old_storage_schema = "schemas/empty.json"
        new_storage_schema = "schemas/empty.json"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();
    assert_eq!(json["summary"]["safe"], 2);
    assert_eq!(json["summary"]["unsafe"], 0);
    assert_eq!(json["summary"]["errored"], 0);
    assert_eq!(json["summary"]["incomplete"], 0);
    assert_eq!(json["summary"]["total"], 2);
}

// ── --max-pairs ──────────────────────────────────────────────────────────────

/// A manifest with `n` pairs, all comparing the checked-in `v1.wasm` fixture
/// against itself, none needing a storage schema. Cheap and fast to run even
/// at boundary sizes, since a safe v1 -> v1 comparison does no real work.
fn write_n_pair_manifest(dir: &Path, n: usize) -> PathBuf {
    stage_wasm(&dir.join("wasm"));
    let mut body = String::from("[defaults]\nbase_dir = \"wasm\"\n\n");
    for i in 0..n {
        body.push_str(&format!(
            "[[pairs]]\nold = \"v1.wasm\"\nnew = \"v1.wasm\"\nname = \"pair-{i}\"\n\n"
        ));
    }
    write(dir, "root.toml", &body)
}

#[test]
fn default_max_pairs_does_not_affect_an_ordinary_sized_manifest() {
    let dir = temp_dir("max-pairs-default-ok");
    let root = write_n_pair_manifest(&dir, 3);

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["total_pairs"], 3);
}

#[test]
fn custom_max_pairs_rejects_an_oversized_manifest_before_loading_any_wasm() {
    let dir = temp_dir("max-pairs-custom-reject");
    let root = write_n_pair_manifest(&dir, 3);
    let reports = dir.join("reports");

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--max-pairs",
            "2",
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(combined.contains("3 pairs"), "got: {combined}");
    assert!(combined.contains("maximum of 2"), "got: {combined}");
    assert!(combined.contains("--max-pairs"), "got: {combined}");

    // Rejected ahead of any WASM loading: no per-contract report exists.
    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

#[test]
fn max_pairs_exactly_at_the_custom_limit_runs_normally() {
    let dir = temp_dir("max-pairs-boundary-ok");
    let root = write_n_pair_manifest(&dir, 2);

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--max-pairs", "2"],
    );
    assert_eq!(
        run.code, 0,
        "a manifest exactly at the limit must run: {}{}",
        run.stdout, run.stderr
    );
}

#[test]
fn max_pairs_one_over_the_custom_limit_is_rejected() {
    let dir = temp_dir("max-pairs-boundary-reject");
    let root = write_n_pair_manifest(&dir, 3);

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--max-pairs", "2"],
    );
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(combined.contains("3 pairs"), "got: {combined}");
    assert!(combined.contains("maximum of 2"), "got: {combined}");
}

#[test]
fn max_pairs_zero_rejects_any_manifest_with_pairs() {
    let dir = temp_dir("max-pairs-zero");
    let root = write_n_pair_manifest(&dir, 1);

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--max-pairs", "0"],
    );
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(combined.contains("1 pairs"), "got: {combined}");
    assert!(combined.contains("maximum of 0"), "got: {combined}");
}

// ── Labels ───────────────────────────────────────────────────────────────────

#[test]
fn labels_appear_in_batch_json_results_and_manifest_provenance() {
    let dir = temp_dir("labels-json");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "labeled"
        labels = ["stage:prod", "service:payments"]

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "unlabeled"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();

    let labeled_result = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "labeled")
        .expect("labeled result must be present");
    assert_eq!(
        labeled_result["labels"],
        serde_json::json!(["stage:prod", "service:payments"])
    );

    let unlabeled_result = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "unlabeled")
        .expect("unlabeled result must be present");
    assert_eq!(unlabeled_result["labels"], serde_json::json!([]));

    // Per-contract provenance (the manifest.pairs[] block) carries labels too.
    let labeled_pair = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "labeled")
        .expect("labeled pair provenance must be present");
    assert_eq!(
        labeled_pair["labels"],
        serde_json::json!(["stage:prod", "service:payments"])
    );
}

#[test]
fn labels_appear_in_text_output() {
    let dir = temp_dir("labels-text");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "labeled"
        labels = ["prod", "payments"]
        "#,
    );

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("prod") && run.stdout.contains("payments"),
        "text output must surface labels: {}",
        run.stdout
    );
}

#[test]
fn labels_appear_in_markdown_output() {
    let dir = temp_dir("labels-markdown");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "labeled"
        labels = ["prod", "payments"]
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--format", "markdown"],
    );
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Labels"), "got:\n{}", run.stdout);
    assert!(
        run.stdout.contains("prod") && run.stdout.contains("payments"),
        "markdown output must surface labels: {}",
        run.stdout
    );
}

#[test]
fn repeated_labels_across_many_pairs_are_accepted() {
    let dir = temp_dir("labels-repeated");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "a"
        labels = ["prod"]

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "b"
        labels = ["prod"]

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "c"
        labels = ["prod"]
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(
        run.code, 0,
        "the same label repeating across pairs must not be rejected: {}",
        run.stderr
    );
    let json = run.json();
    for name in ["a", "b", "c"] {
        let entry = json["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("no result named '{name}'"));
        assert_eq!(entry["labels"], serde_json::json!(["prod"]));
    }
}

#[test]
fn invalid_label_is_rejected_before_anything_runs() {
    let dir = temp_dir("labels-invalid");
    stage_wasm(&dir.join("wasm"));
    let reports = dir.join("reports");
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "token"
        labels = ["not a valid label!"]
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Invalid label 'not a valid label!'"),
        "error must name the offending label: {combined}"
    );

    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

#[test]
fn unlabeled_pairs_are_unaffected_in_a_mixed_batch() {
    let dir = temp_dir("labels-mixed");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v1.wasm"
        name   = "labeled"
        labels = ["prod"]

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "unlabeled"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0);
    let json = run.json();
    assert_eq!(result(&json, "unlabeled")["is_safe"], true);
    let unlabeled_entry = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "unlabeled")
        .unwrap();
    assert_eq!(unlabeled_entry["labels"], serde_json::json!([]));
}

// ── Manifest Format Versioning ───────────────────────────────────────────────

#[test]
fn manifest_version_defaults_to_one_integration() {
    let dir = temp_dir("mc-version-default");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "default-version"
        "#,
    );
    let run = run_manifest(&root, &[]);
    assert_eq!(
        run.code, 0,
        "legacy default version 1 must resolve successfully"
    );
}

#[test]
fn manifest_version_one_toml_integration() {
    let dir = temp_dir("mc-version-one-toml");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        version = 1

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "version-one"
        "#,
    );
    let run = run_manifest(&root, &[]);
    assert_eq!(
        run.code, 0,
        "explicit version 1 TOML must resolve successfully"
    );
}

#[test]
fn manifest_version_one_json_integration() {
    let dir = temp_dir("mc-version-one-json");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.json",
        r#"{
            "version": 1,
            "defaults": { "base_dir": "wasm" },
            "pairs": [
                { "old": "v1.wasm", "new": "v1.wasm", "name": "version-one" }
            ]
        }"#,
    );
    let run = run_manifest(&root, &[]);
    assert_eq!(
        run.code, 0,
        "explicit version 1 JSON must resolve successfully"
    );
}

#[test]
fn manifest_version_mismatch_toml_integration() {
    let dir = temp_dir("mc-version-mismatch-toml");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.toml",
        r#"
        version = 2

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "version-two"
        "#,
    );
    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Unsupported manifest version"),
        "got: {combined}"
    );
    assert!(combined.contains("Supported version: 1"), "got: {combined}");
    assert!(combined.contains("encountered: 2"), "got: {combined}");
}

#[test]
fn manifest_version_mismatch_json_integration() {
    let dir = temp_dir("mc-version-mismatch-json");
    stage_wasm(&dir.join("wasm"));
    let root = write(
        &dir,
        "root.json",
        r#"{
            "version": 2,
            "defaults": { "base_dir": "wasm" },
            "pairs": [
                { "old": "v1.wasm", "new": "v1.wasm", "name": "version-two" }
            ]
        }"#,
    );
    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Unsupported manifest version"),
        "got: {combined}"
    );
    assert!(combined.contains("Supported version: 1"), "got: {combined}");
    assert!(combined.contains("encountered: 2"), "got: {combined}");
}

// ── Empty/Invalid Manifest Validation ────────────────────────────────────────

#[test]
fn manifest_whitespace_only_rejected_integration() {
    let dir = temp_dir("mc-whitespace-only");
    let root = write(&dir, "root.toml", "   \n\t  ");
    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(combined.contains("is empty"), "got: {combined}");
    assert!(combined.contains("[[pairs]]"), "got: {combined}");
    assert!(combined.contains("\"pairs\":"), "got: {combined}");
}

#[test]
fn manifest_empty_pairs_toml_rejected_integration() {
    let dir = temp_dir("mc-empty-pairs-toml");
    let root = write(
        &dir,
        "root.toml",
        r#"
        version = 1
        "#,
    );
    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("contains no comparison pairs"),
        "got: {combined}"
    );
    assert!(combined.contains("[[pairs]]"), "got: {combined}");
    assert!(combined.contains("\"pairs\":"), "got: {combined}");
}

#[test]
fn manifest_empty_pairs_json_rejected_integration() {
    let dir = temp_dir("mc-empty-pairs-json");
    let root = write(&dir, "root.json", r#"{"version": 1}"#);
    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("contains no comparison pairs"),
        "got: {combined}"
    );
    assert!(combined.contains("[[pairs]]"), "got: {combined}");
    assert!(combined.contains("\"pairs\":"), "got: {combined}");
}
