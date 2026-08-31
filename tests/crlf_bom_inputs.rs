//! Regression coverage for CRLF line endings and a leading UTF-8 BOM in
//! text config inputs (suppression config, `--config`, manifest TOML) —
//! both common artifacts of Windows tooling. TOML/JSON already tolerate
//! CRLF by spec; the BOM is the part that previously had no handling and
//! would surface as a confusing "unexpected character" parse error.

use std::path::{Path, PathBuf};
use std::process::Command;

const BOM: &str = "\u{feff}";

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

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Run {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code(),
    }
}

#[test]
fn bom_prefixed_suppression_config_validates() {
    let dir = temp_dir("bom-suppression-config");
    let config = write(&dir, "config.toml", &format!("{BOM}max_suppressions = 5\n"));

    let run = run(&["--validate-config", config.to_str().unwrap()]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
    assert!(
        run.combined().contains("valid"),
        "expected a validity confirmation, got: {}",
        run.combined()
    );
}

#[test]
fn crlf_suppression_config_validates() {
    let dir = temp_dir("crlf-suppression-config");
    let config = write(&dir, "config.toml", "max_suppressions = 5\r\n");

    let run = run(&["--validate-config", config.to_str().unwrap()]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
}

#[test]
fn bom_prefixed_config_flag_loads_for_a_full_run() {
    let dir = temp_dir("bom-config-flag");
    let config = write(&dir, "config.toml", BOM);

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
}

#[test]
fn bom_prefixed_manifest_resolves() {
    let dir = temp_dir("bom-manifest");
    let manifest = write(
        &dir,
        "manifest.toml",
        &format!(
            "{BOM}[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"token\"\n",
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
        ),
    );

    let run = run(&[
        "--manifest",
        manifest.to_str().unwrap(),
        "--explain-manifest",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
}

#[test]
fn crlf_manifest_resolves() {
    let dir = temp_dir("crlf-manifest");
    let manifest = write(
        &dir,
        "manifest.toml",
        &format!(
            "[[pairs]]\r\nold = {:?}\r\nnew = {:?}\r\nname = \"token\"\r\n",
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
        ),
    );

    let run = run(&[
        "--manifest",
        manifest.to_str().unwrap(),
        "--explain-manifest",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
}
