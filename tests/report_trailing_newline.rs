//! Integration tests for preserving trailing newlines in report file outputs.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_file(ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sus-trailing-newline-test-{}-{}.{}",
        ext,
        std::process::id(),
        ext
    ))
}

#[test]
fn report_files_preserve_trailing_newline_for_all_formats() {
    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    for (format, ext) in [("text", "txt"), ("markdown", "md"), ("json", "json")] {
        let file_path = temp_file(ext);
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
        }

        // Run safeguard with file output via --output FORMAT:PATH
        let spec_arg = format!("{}:{}", format, file_path.display());
        let _output = bin()
            .arg(&v1)
            .arg(&v2)
            .args(["--output", &spec_arg])
            .output()
            .expect("failed to run binary");

        let file_contents = fs::read_to_string(&file_path)
            .unwrap_or_else(|e| panic!("failed to read output file {}: {e}", file_path.display()));

        // Acceptance Criterion 1: Output ends with exactly one newline
        assert!(
            file_contents.ends_with('\n'),
            "file output for format '{format}' must end with a newline"
        );
        assert!(
            !file_contents.ends_with("\n\n"),
            "file output for format '{format}' must end with exactly one newline"
        );

        // Acceptance Criterion 2: Content before final newline is unchanged / JSON remains valid
        if format == "json" {
            let trimmed = file_contents.trim_end_matches('\n');
            let json_val: serde_json::Value = serde_json::from_str(trimmed)
                .expect("JSON file output must remain valid JSON when trailing newline is removed");
            assert!(json_val.get("report_schema_version").is_some());
        }

        let _ = fs::remove_file(&file_path);
    }
}
