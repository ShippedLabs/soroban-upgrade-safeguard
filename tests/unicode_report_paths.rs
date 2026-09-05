//! Regression coverage for Unicode report file paths.
//!
//! Report output may be written beneath directories or filenames containing
//! Unicode characters. This test verifies that output handling does not assume
//! ASCII filesystem names.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_with_output(old: &str, new: &str, format: &str, output: &PathBuf) -> Run {
    let output_res = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", format])
        .args(["--output", output.to_str().unwrap()])
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output_res.stdout).expect("stdout not utf8"),
        stderr: String::from_utf8(output_res.stderr).expect("stderr not utf8"),
        code: output_res.status.code().expect("process killed by signal"),
    }
}

#[test]
fn json_report_writes_to_unicode_directory() {
    // Use Unicode directory name: Japanese characters for "report"
    let dir = temp_dir("unicode-dir").join("レポート");
    std::fs::create_dir_all(&dir).expect("failed to create unicode dir");
    let output = dir.join("report.json");

    let run = run_with_output("v1.wasm", "v2.wasm", "json", &output);

    assert_eq!(
        run.code, 1,
        "v1->v2 is breaking, must exit 1, stderr:\n{}",
        run.stderr
    );

    assert!(
        output.exists(),
        "report file must exist at unicode path: {}",
        output.display()
    );

    let contents =
        std::fs::read_to_string(&output).expect("failed to read report from unicode directory");

    let json: Value = serde_json::from_str(&contents).expect("report must be valid JSON");

    assert!(json.get("is_safe").is_some(), "JSON must have 'is_safe'");
    assert_eq!(json["is_safe"], false);
    assert!(json.get("counts").is_some(), "JSON must have 'counts'");

    // stdout must be empty when --output is used
    assert!(
        run.stdout.trim().is_empty(),
        "stdout must be empty, got: {}",
        run.stdout
    );
}

#[test]
fn markdown_report_writes_to_unicode_filename() {
    // Use Unicode filename: Chinese characters for "safety report"
    let dir = temp_dir("unicode-filename");
    let output = dir.join("安全报告.md");

    let run = run_with_output("v1.wasm", "v1.wasm", "markdown", &output);

    assert_eq!(
        run.code, 0,
        "v1->v1 is safe, must exit 0, stderr:\n{}",
        run.stderr
    );

    assert!(
        output.exists(),
        "report file must exist with unicode filename: {}",
        output.display()
    );

    let contents =
        std::fs::read_to_string(&output).expect("failed to read report with unicode filename");

    assert!(
        contents.contains("# Soroban Upgrade Safety Report"),
        "markdown must contain report heading"
    );

    assert!(
        run.stdout.trim().is_empty(),
        "stdout must be empty, got: {}",
        run.stdout
    );
}

#[test]
fn text_report_writes_to_mixed_unicode_path() {
    // Use mixed Unicode: directory with Arabic, file with Cyrillic
    let dir = temp_dir("unicode-mixed").join("تقرير");
    std::fs::create_dir_all(&dir).expect("failed to create arabic dir");
    let output = dir.join("отчёт.txt");

    let run = run_with_output("v1.wasm", "v3.wasm", "text", &output);

    assert_eq!(
        run.code, 0,
        "v1->v3 has warnings only, must exit 0, stderr:\n{}",
        run.stderr
    );

    assert!(
        output.exists(),
        "report file must exist at mixed unicode path: {}",
        output.display()
    );

    let contents =
        std::fs::read_to_string(&output).expect("failed to read report from mixed unicode path");

    assert!(
        contents.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "text report must contain header"
    );

    assert!(
        run.stdout.trim().is_empty(),
        "stdout must be empty, got: {}",
        run.stdout
    );
}

#[test]
fn report_readback_validates_after_unicode_write() {
    // Use Unicode with emoji: directory with emoji, JSON file
    let dir = temp_dir("unicode-emoji").join("📊 reports");
    std::fs::create_dir_all(&dir).expect("failed to create emoji dir");
    let output = dir.join("analysis_🔍.json");

    let run = run_with_output("v1.wasm", "v2.wasm", "json", &output);

    assert_eq!(run.code, 1, "v1->v2 must exit 1, stderr:\n{}", run.stderr);

    // Read back and validate the JSON structure
    let contents = std::fs::read_to_string(&output).unwrap_or_else(|e| {
        panic!(
            "failed to read back report from {}: {}",
            output.display(),
            e
        )
    });

    let json: Value = serde_json::from_str(&contents).unwrap_or_else(|e| {
        panic!(
            "report written to unicode path must be valid JSON: {}\ncontents:\n{}",
            e, contents
        )
    });

    // Validate report structure
    assert!(json.get("is_safe").is_some());
    assert!(json.get("counts").is_some());
    assert!(json.get("findings_by_category").is_some());
    assert!(json.get("findings_by_axis").is_some());
    assert!(
        json["findings_by_category"]
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false),
        "v1->v2 breaking comparison must have findings"
    );
}

#[test]
fn unicode_path_cleanup_succeeds() {
    // Verify temporary artifacts can be cleaned up without locale issues
    let dir = temp_dir("unicode-cleanup").join("清理测试");
    std::fs::create_dir_all(&dir).expect("failed to create dir");

    let outputs = vec![
        dir.join("report1_日本語.json"),
        dir.join("report2_한국어.txt"),
        dir.join("report3_עברית.md"),
    ];

    // Write multiple reports
    for output in &outputs {
        let run = run_with_output("v1.wasm", "v1.wasm", "json", output);
        assert_eq!(run.code, 0, "writes must succeed");
        assert!(
            output.exists(),
            "file must be created: {}",
            output.display()
        );
    }

    // Clean up all files
    for output in &outputs {
        std::fs::remove_file(output)
            .unwrap_or_else(|e| panic!("cleanup must succeed for {}: {}", output.display(), e));
        assert!(
            !output.exists(),
            "file must be removed: {}",
            output.display()
        );
    }

    // Remove unicode directory
    std::fs::remove_dir(&dir).unwrap_or_else(|e| panic!("directory cleanup must succeed: {}", e));
}
