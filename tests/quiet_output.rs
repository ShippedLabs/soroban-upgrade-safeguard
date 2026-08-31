use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_text(extra_args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(extra_args)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    (code, stdout, stderr)
}

/// The report body, starting at the `Status:` line. Everything before it is the
/// report's own decorative banner and, without `--quiet`, the progress chatter.
fn report_slice(output: &str) -> &str {
    output
        .find("Status:")
        .map(|index| &output[index..])
        .expect("text output should contain the report status")
}

#[test]
fn quiet_text_suppresses_progress_but_keeps_report_and_exit_code() {
    let (normal_code, normal_stdout, _) = run_text(&[]);
    let (quiet_code, quiet_stdout, quiet_stderr) = run_text(&["--quiet"]);

    assert_eq!(quiet_code, normal_code, "--quiet must preserve exit code");
    assert_eq!(quiet_code, 0, "identical upgrade should still pass");

    assert!(
        normal_stdout.contains("Soroban Upgrade Safeguard"),
        "normal text output should include decorative progress"
    );
    assert!(
        !quiet_stdout.contains("Soroban Upgrade Safeguard"),
        "--quiet must suppress the banner"
    );
    assert!(
        !quiet_stdout.contains("Loading and Parsing contracts"),
        "--quiet must suppress progress lines"
    );
    assert!(
        quiet_stdout
            .trim_start()
            .starts_with("========================================"),
        "--quiet output must open with the report itself, not progress"
    );
    assert!(
        quiet_stdout.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "--quiet must still print the report"
    );
    assert!(
        quiet_stdout.contains("Recommended Bump:"),
        "--quiet must keep report details"
    );
    assert_eq!(
        report_slice(&quiet_stdout),
        report_slice(&normal_stdout),
        "--quiet must leave the report body unchanged"
    );
    assert!(
        quiet_stderr.is_empty(),
        "--quiet should not move progress chatter to stderr"
    );
}
