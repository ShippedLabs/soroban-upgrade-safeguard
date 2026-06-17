//! Integration tests for filtering human-readable findings by severity.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn min_severity_critical_filters_display_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--min-severity", "critical"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "critical findings must still drive the exit code");
    assert!(
        stdout.contains("Critical: 3"),
        "critical count should still include all findings"
    );
    assert!(
        stdout.contains("Info:     1"),
        "info count should still reflect filtered findings"
    );
    assert!(
        stdout.contains("Function 'initialize': parameter count changed from 1 to 2."),
        "critical findings should remain visible"
    );
    assert!(
        !stdout.contains("EVENT ENUM CASE ADDED"),
        "info-only category should be hidden"
    );
    assert!(
        !stdout.contains("new case 'Archived'"),
        "info findings should be hidden"
    );
}
