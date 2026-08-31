//! Process-level test for clean SIGTERM shutdown in `--watch` mode.
//!
//! Watch mode is a long-running loop; the only way to verify it actually
//! shuts down cleanly on SIGTERM (rather than being killed mid-write by the
//! OS's default disposition for the signal) is to spawn the real binary,
//! signal it, and inspect what it left behind. That makes this Unix-only and
//! gated on the `watch` feature.
//!
//! On non-Unix platforms, or builds without the `watch` feature, there is no
//! SIGTERM-specific shutdown path: watch mode is stopped via Ctrl+C or by
//! the OS/service manager's default kill behavior for the process. That is
//! the documented fallback for this test's absence there.
#![cfg(all(unix, feature = "watch"))]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn status_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-sigterm-{label}-{}.json",
        std::process::id()
    ))
}

#[test]
fn sigterm_shuts_down_cleanly_with_a_complete_status_file() {
    let status = status_path("clean");
    let _ = std::fs::remove_file(&status);

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--watch")
        .arg("--watch-status-file")
        .arg(&status)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn watch process");

    // Wait for the first cycle to finish so we know the process reached its
    // watch loop (and wrote a real cycle) rather than racing startup.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut saw_completed_cycle = false;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(&status) {
            if contents.contains("\"completed\"") {
                saw_completed_cycle = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw_completed_cycle,
        "watch process never wrote a completed cycle to its status file"
    );

    let pid = child.id() as libc::pid_t;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(rc, 0, "failed to send SIGTERM to the watch process");

    let exit_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().expect("failed to poll child").is_some() {
            break;
        }
        if Instant::now() > exit_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("watch process did not exit within the deadline after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The status file must still be a single, well-formed JSON document —
    // never a truncated or half-written one — and reflect a clean shutdown
    // rather than an in-progress or errored cycle.
    let final_contents =
        std::fs::read_to_string(&status).expect("status file must survive shutdown");
    let parsed: serde_json::Value = serde_json::from_str(&final_contents).unwrap_or_else(|e| {
        panic!(
            "status file was not a complete, well-formed JSON document after SIGTERM \
             shutdown (would indicate a partial write): {e}\ncontents: {final_contents:?}"
        )
    });
    assert_eq!(parsed["state"], "shutting_down");

    let _ = std::fs::remove_file(&status);
}
