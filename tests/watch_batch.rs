//! Process-level tests for incremental batch `--watch` mode.
//!
//! Watch mode is a long-running loop, so the only way to verify its behavior
//! (coalescing a burst, re-analyzing only the affected pair, surviving a
//! removal, re-resolving a manifest edit, and emitting a deterministic
//! aggregate) is to run the real binary and observe its outputs. These tests
//! are gated on the `watch` feature and are Unix-oriented (they use `kill` to
//! terminate the watcher).
#![cfg(all(unix, feature = "watch"))]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn temp_workspace(label: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("watch-batch-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create workspace");
    dir
}

/// Guard that terminates the child process on drop so a failing assertion does
/// not leak a long-running watch process.
struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_watch(args: &[&str], status_file: &Path, report_file: &Path) -> ChildGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .arg("--watch")
        .arg("--watch-debounce-ms")
        .arg("100")
        .arg("--watch-status-file")
        .arg(status_file)
        .arg("--output")
        .arg(format!("json:{}", report_file.display()))
        .arg("--no-timestamp")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn watch process");
    ChildGuard(Some(child))
}

/// Wait until the status file reports a completed cycle at or above `min_cycle`.
fn wait_for_completed_cycle(status_file: &Path, min_cycle: u64) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(status_file) {
            if let Ok(value) = serde_json::from_str::<Value>(&contents) {
                if value["state"] == "completed"
                    && value["cycle"].as_u64().unwrap_or(0) >= min_cycle
                {
                    return;
                }
            }
        }
        sleep(Duration::from_millis(50));
    }
    panic!(
        "watch process never reached completed cycle >= {min_cycle} (status at {} '{}')",
        status_file.display(),
        std::fs::read_to_string(status_file).unwrap_or_default()
    );
}

fn read_report(report_file: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(report_file).expect("read report"))
        .expect("report file must be valid JSON")
}

fn result_safe(report: &Value, name: &str) -> Option<bool> {
    report["results"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["name"] == name))
        .map(|r| r["report"]["is_safe"].as_bool().unwrap_or(false))
}

fn result_coverage<'a>(report: &'a Value, name: &str) -> Option<&'a str> {
    report["results"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["name"] == name))
        .and_then(|r| r["coverage"].as_str())
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, contents).expect("write file");
}

#[test]
fn batch_watch_recomputes_only_the_changed_pair() {
    let ws = temp_workspace("incremental");
    let old = ws.join("old");
    let new = ws.join("new");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out dir");

    write_file(
        &old.join("a.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );
    write_file(
        &new.join("a.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );
    write_file(
        &old.join("b.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );
    write_file(
        &new.join("b.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );

    let manifest = ws.join("m.toml");
    write_file(
        &manifest,
        format!(
            "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"a\"\n\n[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"b\"\n",
            old.join("a.wasm"), new.join("a.wasm"),
            old.join("b.wasm"), new.join("b.wasm"),
        )
        .as_bytes(),
    );

    let status = out.join("status.json");
    let report = out.join("report.json");
    let _guard = spawn_watch(
        &["--manifest", manifest.to_str().unwrap()],
        &status,
        &report,
    );

    wait_for_completed_cycle(&status, 1);
    let initial = read_report(&report);
    assert_eq!(initial["is_safe"], true, "initial manifest must be safe");
    assert_eq!(initial["results"].as_array().unwrap().len(), 2);

    // Make only pair "a" breaking; pair "b" must retain its last known result.
    write_file(
        &new.join("a.wasm"),
        &std::fs::read(wasm("v2.wasm")).unwrap(),
    );

    wait_for_completed_cycle(&status, 2);
    // Give any trailing events a moment to settle before asserting the count.
    sleep(Duration::from_millis(300));
    let after = read_report(&report);
    assert_eq!(after["is_safe"], false);
    assert_eq!(result_safe(&after, "a"), Some(false));
    assert_eq!(result_safe(&after, "b"), Some(true));
    // A single content edit coalesces into exactly one incremental cycle.
    let cycle = read_value(&status, "cycle");
    assert!(
        cycle <= 2,
        "edit should produce a single cycle, got {cycle}"
    );
}

#[test]
fn batch_watch_coalesces_an_atomic_replacement_burst() {
    let ws = temp_workspace("coalesce");
    let old = ws.join("old");
    let new = ws.join("new");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out dir");

    write_file(
        &old.join("a.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );
    write_file(
        &new.join("a.wasm"),
        &std::fs::read(wasm("v1.wasm")).unwrap(),
    );

    let status = out.join("status.json");
    let report = out.join("report.json");
    let _guard = spawn_watch(
        &[
            "--old-dir",
            old.to_str().unwrap(),
            "--new-dir",
            new.to_str().unwrap(),
        ],
        &status,
        &report,
    );

    wait_for_completed_cycle(&status, 1);

    // A build tool's write-temp-then-rename pattern, repeated quickly: six
    // logical replacements should be debounced into a single watch cycle.
    let v2 = std::fs::read(wasm("v2.wasm")).unwrap();
    for i in 0..6 {
        let temp = ws.join(format!(".tmp-{i}"));
        write_file(&temp, &v2);
        let _ = std::fs::rename(&temp, new.join("a.wasm"));
    }

    wait_for_completed_cycle(&status, 2);
    sleep(Duration::from_millis(300));
    let after = read_report(&report);
    assert_eq!(after["is_safe"], false);
    assert_eq!(result_safe(&after, "a"), Some(false));
    let cycle = read_value(&status, "cycle");
    assert!(
        cycle <= 2,
        "burst of replacements must coalesce, got {cycle} cycles"
    );
}

#[test]
fn batch_watch_manifest_edit_re_resolves_the_composition() {
    let ws = temp_workspace("manifest-edit");
    let old = ws.join("old");
    let new = ws.join("new");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out dir");

    let v1 = std::fs::read(wasm("v1.wasm")).unwrap();
    write_file(&old.join("a.wasm"), &v1);
    write_file(&new.join("a.wasm"), &v1);
    write_file(&old.join("c.wasm"), &v1);

    let manifest = ws.join("m.toml");
    write_file(
        &manifest,
        format!(
            "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"a\"\n",
            old.join("a.wasm"),
            new.join("a.wasm")
        )
        .as_bytes(),
    );

    let status = out.join("status.json");
    let report = out.join("report.json");
    let _guard = spawn_watch(
        &["--manifest", manifest.to_str().unwrap()],
        &status,
        &report,
    );

    wait_for_completed_cycle(&status, 1);
    assert_eq!(read_report(&report)["results"].as_array().unwrap().len(), 1);

    // Add a pair by editing the manifest; the composition must re-resolve.
    write_file(
        &manifest,
        format!(
            "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"a\"\n\n[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"c\"\n",
            old.join("a.wasm"), new.join("a.wasm"), old.join("c.wasm"), new.join("c.wasm"),
        )
        .as_bytes(),
    );

    wait_for_completed_cycle(&status, 2);
    sleep(Duration::from_millis(300));
    let after = read_report(&report);
    let names: Vec<&str> = after["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"c"),
        "edited manifest must add pair 'c', got {names:?}"
    );
}

#[test]
fn batch_watch_removal_becomes_a_gap_then_restore_heals() {
    let ws = temp_workspace("removal");
    let old = ws.join("old");
    let new = ws.join("new");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out dir");

    let v1 = std::fs::read(wasm("v1.wasm")).unwrap();
    write_file(&old.join("a.wasm"), &v1);
    write_file(&new.join("a.wasm"), &v1);
    write_file(&old.join("b.wasm"), &v1);
    write_file(&new.join("b.wasm"), &v1);

    let status = out.join("status.json");
    let report = out.join("report.json");
    let _guard = spawn_watch(
        &[
            "--old-dir",
            old.to_str().unwrap(),
            "--new-dir",
            new.to_str().unwrap(),
        ],
        &status,
        &report,
    );

    wait_for_completed_cycle(&status, 1);
    assert_eq!(read_report(&report)["is_safe"], true);

    // Removing the new side of "a" demotes it to a gap (Critical). The pair "b"
    // must retain its unchanged result.
    std::fs::remove_file(new.join("a.wasm")).unwrap();

    wait_for_completed_cycle(&status, 2);
    sleep(Duration::from_millis(300));
    let after = read_report(&report);
    assert_eq!(after["is_safe"], false);
    assert_eq!(result_coverage(&after, "a"), Some("error"));
    assert_eq!(result_safe(&after, "b"), Some(true));

    // Restoring the file heals the pair back to safe.
    write_file(&new.join("a.wasm"), &v1);
    wait_for_completed_cycle(&status, 3);
    sleep(Duration::from_millis(300));
    let healed = read_report(&report);
    assert_eq!(healed["is_safe"], true);
    assert_eq!(result_safe(&healed, "a"), Some(true));
}

#[test]
fn batch_watch_newly_added_pair_appears() {
    let ws = temp_workspace("newly-added");
    let old = ws.join("old");
    let new = ws.join("new");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out dir");

    let v1 = std::fs::read(wasm("v1.wasm")).unwrap();
    write_file(&old.join("a.wasm"), &v1);
    write_file(&new.join("a.wasm"), &v1);

    let status = out.join("status.json");
    let report = out.join("report.json");
    let _guard = spawn_watch(
        &[
            "--old-dir",
            old.to_str().unwrap(),
            "--new-dir",
            new.to_str().unwrap(),
        ],
        &status,
        &report,
    );

    wait_for_completed_cycle(&status, 1);
    assert_eq!(read_report(&report)["results"].as_array().unwrap().len(), 1);

    // A new shared-name artifact appears on both sides → becomes a pair.
    write_file(&old.join("zz.wasm"), &v1);
    write_file(&new.join("zz.wasm"), &v1);

    wait_for_completed_cycle(&status, 2);
    sleep(Duration::from_millis(300));
    let after = read_report(&report);
    let names: Vec<&str> = after["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"zz"),
        "newly added artifact must appear, got {names:?}"
    );
    assert_eq!(after["results"].as_array().unwrap().len(), 2);
}

#[test]
fn batch_watch_output_is_deterministic_across_runs() {
    let ws = temp_workspace("deterministic");

    let run = || -> Value {
        let old = ws.join("old");
        let new = ws.join("new");
        let out = ws.join("out");
        std::fs::create_dir_all(&out).expect("out dir");

        write_file(
            &old.join("a.wasm"),
            &std::fs::read(wasm("v1.wasm")).unwrap(),
        );
        write_file(
            &new.join("a.wasm"),
            &std::fs::read(wasm("v1.wasm")).unwrap(),
        );
        write_file(
            &old.join("b.wasm"),
            &std::fs::read(wasm("v1.wasm")).unwrap(),
        );
        write_file(
            &new.join("b.wasm"),
            &std::fs::read(wasm("v2.wasm")).unwrap(),
        );

        let status = out.join("status.json");
        let report = out.join("report.json");
        let _guard = spawn_watch(
            &[
                "--old-dir",
                old.to_str().unwrap(),
                "--new-dir",
                new.to_str().unwrap(),
            ],
            &status,
            &report,
        );
        wait_for_completed_cycle(&status, 1);
        sleep(Duration::from_millis(200));
        read_report(&report)
    };

    // Two independent watch runs over identical inputs must render identical
    // aggregate output (timestamps are already suppressed with --no-timestamp).
    let first = run();
    let second = run();
    assert_eq!(first, second, "aggregate output must be deterministic");
    assert_eq!(first["is_safe"], false);
    assert_eq!(result_safe(&first, "a"), Some(true));
    assert_eq!(result_safe(&first, "b"), Some(false));
}

fn read_value(path: &Path, key: &str) -> u64 {
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).expect("read status"))
        .unwrap_or_else(|_| Value::Null)[key]
        .as_u64()
        .unwrap_or(0)
}
