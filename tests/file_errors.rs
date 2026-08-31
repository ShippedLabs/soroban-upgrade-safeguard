//! Regression coverage for unreadable inputs and unwritable output
//! destinations.
//!
//! Permission enforcement is platform-specific (Unix mode bits vs. Windows
//! ACLs), so the true permission-denied cases are gated `#[cfg(unix)]`,
//! mirroring `tests/symlink_input.rs`. The blocked-output-path case below
//! needs no OS-specific permission bits (a file component instead of a
//! directory fails identically everywhere) and so runs unconditionally.

use std::path::{Path, PathBuf};
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
    code: Option<i32>,
}

impl Run {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn run(args: &[&Path]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    command.args(args);
    let output = command.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code(),
    }
}

#[test]
fn output_path_blocked_by_a_file_component_is_a_clear_error() {
    // A parent directory in the `--output` path that already exists as a
    // plain file can't be created on any OS; the failure must name the
    // path, not surface as a bare unlabeled OS error code.
    let dir = temp_dir("output-blocked-by-file");
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"not a directory").expect("failed to write blocker file");
    let output = blocker.join("report.json");

    let run = run(&[
        wasm("v1.wasm").as_path(),
        wasm("v1.wasm").as_path(),
        Path::new("--output"),
        &output,
    ]);

    assert_ne!(
        run.code,
        Some(0),
        "a blocked output path must fail, not silently succeed: {}",
        run.combined()
    );
    let combined = run.combined();
    assert!(
        combined.contains(&blocker.display().to_string()),
        "error should name the blocking path, not a bare OS error code: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_input_file_names_the_path() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("input-permission-denied");
    let unreadable = dir.join("new.wasm");
    std::fs::copy(wasm("v1.wasm"), &unreadable).expect("failed to copy fixture");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
        .expect("failed to strip permissions");

    let run = run(&[wasm("v1.wasm").as_path(), unreadable.as_path()]);

    // Restore permissions so the temp dir can be cleaned up by later runs.
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).ok();

    assert_ne!(run.code, Some(0), "an unreadable input must fail the run");
    let combined = run.combined();
    assert!(
        combined.contains(&unreadable.display().to_string()),
        "error should name the unreadable path, got: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn an_unwritable_output_directory_names_the_path() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("output-permission-denied");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555))
        .expect("failed to make directory read-only");
    let output = dir.join("report.json");

    let run = run(&[
        wasm("v1.wasm").as_path(),
        wasm("v1.wasm").as_path(),
        Path::new("--output"),
        &output,
    ]);

    // Restore permissions so the temp dir can be cleaned up by later runs.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).ok();

    assert_ne!(
        run.code,
        Some(0),
        "an unwritable output directory must fail the run"
    );
    let combined = run.combined();
    assert!(
        combined.contains(&output.display().to_string())
            || combined.contains(&dir.display().to_string()),
        "error should name the failing output path, got: {combined}"
    );
}
