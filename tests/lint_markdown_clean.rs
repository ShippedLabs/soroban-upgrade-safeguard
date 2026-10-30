use std::path::PathBuf;
use std::process::Command;

#[test]
fn lint_markdown_clean_spec_reports_no_findings() {
    let wasm = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .arg(wasm)
        .args(["--format", "markdown"])
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "lint should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.contains("No lint findings."),
        "stdout should report no lint findings, got:\n{stdout}"
    );
}
