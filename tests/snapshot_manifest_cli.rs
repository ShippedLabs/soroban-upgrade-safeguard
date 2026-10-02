//! CLI-level tests for integrity manifests on empirical storage snapshots.
//!
//! These confirm the end-to-end behavior that matters for
//! `--empirical-file`: a snapshot with a valid manifest is accepted and its
//! integrity status shows up in the JSON report, a snapshot whose manifest
//! fails verification is rejected *before* the comparison completes (no
//! empirical type-replay output at all), a legacy snapshot with no manifest
//! still loads (unverified) for backward compatibility, and a
//! gzip-compressed snapshot is accepted transparently.

use std::path::{Path, PathBuf};
use std::process::Command;

use soroban_upgrade_safeguard::snapshot_manifest::{build_manifest, ManifestInputs};
use stellar_xdr::curr::{
    ContractDataDurability, ContractDataEntry, ExtensionPoint, Hash, Limits, ScAddress, ScVal,
    WriteXdr,
};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout, stderr)
}

fn sample_entries() -> Vec<ContractDataEntry> {
    vec![ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(Hash([7; 32])),
        key: ScVal::Symbol("balance".try_into().unwrap()),
        val: ScVal::U64(500),
        durability: ContractDataDurability::Persistent,
    }]
}

fn entries_to_base64(entries: &[ContractDataEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| e.to_xdr_base64(Limits::none()).unwrap())
        .collect()
}

fn write_snapshot(path: &Path, manifest_json: Option<serde_json::Value>, entries_b64: &[String]) {
    let mut obj = serde_json::Map::new();
    if let Some(m) = manifest_json {
        obj.insert("manifest".to_string(), m);
    }
    obj.insert(
        "entries".to_string(),
        serde_json::Value::Array(
            entries_b64
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    let content = serde_json::to_string(&serde_json::Value::Object(obj)).unwrap();
    std::fs::write(path, content).expect("failed to write snapshot file");
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "safeguard-snapshot-manifest-cli-{}-{}",
        std::process::id(),
        name
    ))
}

#[test]
fn valid_manifest_is_accepted_and_reported_as_verified() {
    let entries = sample_entries();
    // The manifest's `contract_id` must match what the entries actually
    // decode to, since that binding is exactly what verification checks.
    let real_contract_id = match &entries[0].contract {
        ScAddress::Contract(h) => stellar_strkey::Contract(h.0).to_string(),
        _ => unreachable!(),
    };
    let manifest = build_manifest(
        &ManifestInputs {
            contract_id: real_contract_id,
            code_hash: "a".repeat(64),
            network: "Test SDF Network ; September 2015".to_string(),
            ledger_sequence: 100,
            source: "manual".to_string(),
            captured_at: None,
            generator: None,
            schema_assumptions: Default::default(),
        },
        &entries,
    )
    .unwrap_or_else(|e| panic!("failed to build manifest: {e}"));

    let path = temp_path("valid.json");
    let manifest_json = serde_json::to_value(&manifest).unwrap();
    write_snapshot(&path, Some(manifest_json), &entries_to_base64(&entries));

    let old = wasm("v1.wasm").display().to_string();
    let path_str = path.display().to_string();
    let (code, stdout, stderr) = run(&[
        &old,
        &old,
        "--empirical-file",
        &path_str,
        "--format",
        "json",
        "--no-color",
    ]);

    std::fs::remove_file(&path).ok();

    assert_eq!(code, 0, "valid manifest run should succeed, stderr: {stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let integrity = &report["snapshot_integrity"];
    assert_eq!(integrity["integrity"], "verified", "report: {report}");
    assert_eq!(integrity["entries_verified"], 1);
    assert_eq!(integrity["entries_total"], 1);
}

#[test]
fn tampered_manifest_is_rejected_before_any_comparison_output() {
    let entries = sample_entries();
    let real_contract_id = match &entries[0].contract {
        ScAddress::Contract(h) => stellar_strkey::Contract(h.0).to_string(),
        _ => unreachable!(),
    };
    let manifest = build_manifest(
        &ManifestInputs {
            contract_id: real_contract_id,
            code_hash: "a".repeat(64),
            network: "Test SDF Network ; September 2015".to_string(),
            ledger_sequence: 100,
            source: "manual".to_string(),
            captured_at: None,
            generator: None,
            schema_assumptions: Default::default(),
        },
        &entries,
    )
    .unwrap();

    // Tamper with the stored value after the manifest's digests were
    // computed, so the manifest no longer matches the entry it describes.
    let mut tampered_entries = entries.clone();
    tampered_entries[0].val = ScVal::U64(999_999);

    let path = temp_path("tampered.json");
    let manifest_json = serde_json::to_value(&manifest).unwrap();
    write_snapshot(
        &path,
        Some(manifest_json),
        &entries_to_base64(&tampered_entries),
    );

    let old = wasm("v1.wasm").display().to_string();
    let path_str = path.display().to_string();
    let (code, stdout, stderr) = run(&[
        &old,
        &old,
        "--empirical-file",
        &path_str,
        "--format",
        "json",
        "--no-color",
    ]);

    std::fs::remove_file(&path).ok();

    assert_ne!(code, 0, "tampered manifest must be rejected");
    assert!(
        stderr.to_lowercase().contains("integrity"),
        "stderr should explain the integrity rejection, got: {stderr}"
    );
    // No report (and so no empirical type-replay verdict) was ever
    // produced: rejection happened before the comparison completed.
    assert!(
        stdout.trim().is_empty() || serde_json::from_str::<serde_json::Value>(&stdout).is_err(),
        "no comparison report should be emitted on rejection, got stdout: {stdout}"
    );
}

#[test]
fn legacy_snapshot_without_a_manifest_still_loads_as_unverified() {
    let entries = sample_entries();
    let path = temp_path("legacy.json");
    write_snapshot(&path, None, &entries_to_base64(&entries));

    let old = wasm("v1.wasm").display().to_string();
    let path_str = path.display().to_string();
    let (code, stdout, stderr) = run(&[
        &old,
        &old,
        "--empirical-file",
        &path_str,
        "--format",
        "json",
        "--no-color",
    ]);

    std::fs::remove_file(&path).ok();

    assert_eq!(code, 0, "legacy snapshot without a manifest should still succeed, stderr: {stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    assert_eq!(report["snapshot_integrity"]["integrity"], "unverified");
}

#[test]
fn gzip_compressed_snapshot_is_accepted() {
    use std::io::Write;

    let entries = sample_entries();
    let path = temp_path("compressed.json.gz");

    let mut obj = serde_json::Map::new();
    obj.insert(
        "entries".to_string(),
        serde_json::Value::Array(
            entries_to_base64(&entries)
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    let content = serde_json::to_string(&serde_json::Value::Object(obj)).unwrap();

    let file = std::fs::File::create(&path).expect("failed to create gz file");
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    encoder
        .write_all(content.as_bytes())
        .expect("failed to write gzip payload");
    encoder.finish().expect("failed to finish gzip stream");

    let old = wasm("v1.wasm").display().to_string();
    let path_str = path.display().to_string();
    let (code, stdout, stderr) = run(&[
        &old,
        &old,
        "--empirical-file",
        &path_str,
        "--format",
        "json",
        "--no-color",
    ]);

    std::fs::remove_file(&path).ok();

    assert_eq!(code, 0, "gzip-compressed snapshot should load, stderr: {stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    assert_eq!(report["snapshot_integrity"]["integrity"], "unverified");
}
