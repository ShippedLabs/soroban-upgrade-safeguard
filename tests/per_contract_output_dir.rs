use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn per_contract_output_dir_requires_batch_input_and_works_with_manifest() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("per-contract-output-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let wasm_dir = root.join("wasm");
    std::fs::create_dir_all(&wasm_dir).expect("failed to create fixture directory");
    std::fs::copy(wasm("v1.wasm"), wasm_dir.join("v1.wasm")).expect("failed to stage old fixture");
    std::fs::copy(wasm("v3.wasm"), wasm_dir.join("v3.wasm")).expect("failed to stage new fixture");

    let single_output_dir = root.join("single-reports");
    let single = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v3.wasm"))
        .arg("--per-contract-output-dir")
        .arg(&single_output_dir)
        .output()
        .expect("failed to run single comparison");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&single.stdout),
        String::from_utf8_lossy(&single.stderr)
    );
    assert_eq!(single.status.code(), Some(2), "{combined}");
    assert!(
        combined.contains("--manifest") && combined.contains("--old-dir/--new-dir"),
        "{combined}"
    );

    let manifest = root.join("manifest.toml");
    std::fs::write(
        &manifest,
        r#"
        [[pairs]]
        old = "wasm/v1.wasm"
        new = "wasm/v3.wasm"
        name = "contract"
        "#,
    )
    .expect("failed to write manifest");
    let batch_output_dir = root.join("batch-reports");
    let batch = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest)
        .arg("--per-contract-output-dir")
        .arg(&batch_output_dir)
        .output()
        .expect("failed to run batch comparison");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&batch.stdout),
        String::from_utf8_lossy(&batch.stderr)
    );
    assert_eq!(batch.status.code(), Some(0), "{combined}");
    assert!(
        batch_output_dir.join("contract.txt").is_file(),
        "batch report was not written"
    );
}
