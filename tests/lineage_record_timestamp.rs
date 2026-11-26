// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn recording_versions_stores_current_non_decreasing_rfc3339_timestamps() {
    let store_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "lineage-record-timestamp-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos()
    ));

    for version_id in ["v1", "v2"] {
        let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
            .arg(wasm("v1.wasm"))
            .arg(wasm("v1.wasm"))
            .arg("--lineage-store")
            .arg(&store_path)
            .args(["--record-version", version_id])
            .arg("--quiet")
            .output()
            .expect("failed to run binary");
        assert!(
            output.status.success(),
            "recording {version_id} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let store: Value = serde_json::from_slice(
        &std::fs::read(&store_path).expect("lineage store should be written"),
    )
    .expect("lineage store should contain JSON");
    let records = store["records"]
        .as_array()
        .expect("lineage store should contain records");
    assert_eq!(records.len(), 2);

    let timestamps: Vec<&str> = records
        .iter()
        .map(|record| {
            record["created_at"]
                .as_str()
                .expect("record should have a timestamp")
        })
        .collect();
    for timestamp in &timestamps {
        assert_ne!(*timestamp, "2026-08-25T00:00:00Z");
        assert_eq!(timestamp.len(), 20);
        assert!(timestamp.ends_with('Z'));
        assert_eq!(&timestamp[4..5], "-");
        assert_eq!(&timestamp[7..8], "-");
        assert_eq!(&timestamp[10..11], "T");
        assert_eq!(&timestamp[13..14], ":");
        assert_eq!(&timestamp[16..17], ":");
    }
    assert!(
        timestamps[0] <= timestamps[1],
        "timestamps went backwards: {timestamps:?}"
    );

    std::fs::remove_file(store_path).expect("should remove temporary lineage store");
}
