use serde::Deserialize;
use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Manifest {
    version: String,
    description: String,
    pairs: Vec<CorpusPair>,
}

#[derive(Debug, Deserialize)]
struct CorpusPair {
    id: String,
    contract_name: String,
    protocol: String,
    provenance: String,
    license: String,
    old_version: String,
    new_version: String,
    old_wasm: String,
    new_wasm: String,
    expected_verdict: ExpectedVerdict,
    description: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedVerdict {
    is_safe: bool,
    recommended_bump: String,
    expected_critical_count: Option<usize>,
    expected_warning_count: Option<usize>,
    expected_info_count: Option<usize>,
    categories: Vec<String>,
}

#[test]
#[ignore = "real-world corpus validation - opt in via cargo test --test real_world_corpus -- --ignored or REAL_WORLD_CORPUS=1"]
fn test_real_world_corpus_validation() {
    let manifest_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/real_world_corpus/manifest.json");

    assert!(
        manifest_path.exists(),
        "Manifest file should exist at {:?}",
        manifest_path
    );

    let manifest_content =
        fs::read_to_string(&manifest_path).expect("Failed to read real-world corpus manifest.json");
    let manifest: Manifest =
        serde_json::from_str(&manifest_content).expect("Failed to deserialize manifest.json");

    println!("\n========================================================");
    println!("  Soroban Real-World Contract Upgrade Validation Corpus");
    println!("========================================================");
    println!("Corpus Version: {}", manifest.version);
    println!("Description: {}", manifest.description);
    println!("Loaded {} upgrade pairs.\n", manifest.pairs.len());

    let mut passed_count = 0;
    let base_dir = manifest_path.parent().unwrap();

    for pair in &manifest.pairs {
        println!("--------------------------------------------------------");
        println!("Pair: {} ({})", pair.contract_name, pair.id);
        println!("Protocol: {} | License: {}", pair.protocol, pair.license);
        println!("Provenance: {}", pair.provenance);
        println!("Upgrade: {} -> {}", pair.old_version, pair.new_version);
        println!("Description: {}", pair.description);

        let old_wasm_path = base_dir.join(&pair.old_wasm);
        let new_wasm_path = base_dir.join(&pair.new_wasm);

        assert!(
            old_wasm_path.exists(),
            "Old WASM binary not found at {:?}",
            old_wasm_path
        );
        assert!(
            new_wasm_path.exists(),
            "New WASM binary not found at {:?}",
            new_wasm_path
        );

        let old_bytes = fs::read(&old_wasm_path).expect("Failed to read old WASM");
        let new_bytes = fs::read(&new_wasm_path).expect("Failed to read new WASM");

        let options = CompareOptions::default();
        let report = compare_wasm_bytes_with_options(&old_bytes, &new_bytes, &options)
            .expect("Analysis should succeed on corpus WASMs");

        println!(
            "Verdict: Safe={} | Bump={} | Critical={} | Warning={} | Info={}",
            report.is_safe,
            report.recommended_bump(),
            report.critical_count,
            report.warning_count,
            report.info_count
        );
        for (cat, list) in &report.findings_by_category {
            for f in list {
                println!(
                    "  Finding [{:?}] {}: {}",
                    f.finding.severity, cat, f.finding.message
                );
            }
        }

        // Assertion 1: Safety status
        assert_eq!(
            report.is_safe, pair.expected_verdict.is_safe,
            "Safety verdict mismatch for pair {}",
            pair.id
        );

        // Assertion 2: Recommended SemVer bump
        assert_eq!(
            report.recommended_bump(),
            pair.expected_verdict.recommended_bump,
            "Recommended bump mismatch for pair {}",
            pair.id
        );

        // Assertion 3: Critical/Warning/Info count match if expected
        if let Some(expected_critical) = pair.expected_verdict.expected_critical_count {
            assert_eq!(
                report.critical_count, expected_critical,
                "Critical count mismatch for pair {}",
                pair.id
            );
        }
        if let Some(expected_warning) = pair.expected_verdict.expected_warning_count {
            assert_eq!(
                report.warning_count, expected_warning,
                "Warning count mismatch for pair {}",
                pair.id
            );
        }
        if let Some(expected_info) = pair.expected_verdict.expected_info_count {
            assert_eq!(
                report.info_count, expected_info,
                "Info count mismatch for pair {}",
                pair.id
            );
        }

        // Assertion 4: Verify expected finding categories are present
        let found_categories: HashMap<String, usize> = report
            .findings_by_category
            .iter()
            .map(|(cat, list)| (cat.clone(), list.len()))
            .collect();

        for expected_category in &pair.expected_verdict.categories {
            assert!(
                found_categories.contains_key(expected_category),
                "Pair {} expected category '{}', but found categories: {:?}",
                pair.id,
                expected_category,
                found_categories.keys().collect::<Vec<_>>()
            );
        }

        println!("Status: PASSED ✓\n");
        passed_count += 1;
    }

    println!("========================================================");
    println!(
        "Corpus Validation Complete: {}/{} pairs passed.",
        passed_count,
        manifest.pairs.len()
    );
    println!("========================================================\n");
}
