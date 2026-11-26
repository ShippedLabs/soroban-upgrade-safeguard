use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn interface_lockfile_directory_is_reported() {
    let lockfile_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "interface-lockfile-directory-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&lockfile_dir).expect("failed to create temporary lockfile directory");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg("--interface-lockfile")
        .arg(&lockfile_dir)
        .output()
        .expect("failed to run binary");

    let _ = fs::remove_dir_all(&lockfile_dir);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "passing a directory as --interface-lockfile must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("Failed to read interface lockfile"),
        "stderr must explain the lockfile read failure, got: {stderr}"
    );
    assert!(
        stderr.contains(&lockfile_dir.display().to_string()),
        "stderr must name the offending directory path, got: {stderr}"
    );
}
