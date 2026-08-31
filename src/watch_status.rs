//! Structured, atomically-written status file for `--watch` mode.
//!
//! External build systems and service managers need a cheap way to check
//! whether a watch process is alive and when it last completed a cycle,
//! without parsing (or waiting for) the full text/JSON comparison report.
//! [`WatchStatus`] is a small, stable JSON document — operational state only,
//! never findings — that is replaced atomically after every cycle
//! transition so a reader never observes a partially written file.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Lifecycle state of a watch cycle, written to the status file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchState {
    /// A comparison cycle has started and is still in progress.
    Running,
    /// The most recent cycle completed and produced a verdict.
    Completed,
    /// The most recent cycle failed with an error.
    Error,
    /// The watch process is shutting down.
    ShuttingDown,
}

/// Structured operational state for one watch process, written after every
/// cycle transition (start, completion, error, shutdown). Contains no
/// findings or report content — only enough for an external process to
/// answer "is it alive" and "when did it last finish".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchStatus {
    pub state: WatchState,
    /// 1-based count of the comparison cycle this status describes.
    pub cycle: u64,
    /// Unix seconds (UTC) when this cycle started.
    pub started_at: u64,
    /// Unix seconds (UTC) when this cycle finished. `None` while `state` is
    /// `Running`.
    pub finished_at: Option<u64>,
    /// Whether the cycle produced a safe verdict. `None` until the cycle
    /// reaches `Completed`.
    pub is_safe: Option<bool>,
    /// A short, top-level failure reason when `state` is `Error`. Never
    /// contains individual findings.
    pub error: Option<String>,
}

impl WatchStatus {
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A freshly started cycle. Any error/result from a previous cycle is
    /// intentionally absent here — each write replaces the entire document,
    /// so starting a new cycle can never leak a stale verdict or error from
    /// an earlier one.
    pub fn starting(cycle: u64) -> Self {
        Self {
            state: WatchState::Running,
            cycle,
            started_at: Self::now_unix(),
            finished_at: None,
            is_safe: None,
            error: None,
        }
    }

    /// Mark this cycle as completed with the given verdict.
    pub fn completed(mut self, is_safe: bool) -> Self {
        self.state = WatchState::Completed;
        self.finished_at = Some(Self::now_unix());
        self.is_safe = Some(is_safe);
        self.error = None;
        self
    }

    /// Mark this cycle as failed with a short, top-level reason.
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.state = WatchState::Error;
        self.finished_at = Some(Self::now_unix());
        self.is_safe = None;
        self.error = Some(error.into());
        self
    }

    /// Mark the watch process as shutting down.
    pub fn shutdown(mut self) -> Self {
        self.state = WatchState::ShuttingDown;
        self.finished_at = Some(Self::now_unix());
        self
    }

    /// Atomically write this status to `path`.
    ///
    /// The document is serialized to a sibling temp file, flushed and
    /// `fsync`ed, then moved into place with `rename`. A rename onto an
    /// existing path is atomic on the same filesystem, so a concurrent
    /// reader always observes either the previous complete document or the
    /// new one, never a partial write; and if writing the temp file fails
    /// (disk full, permissions, interrupted process), `path` itself is left
    /// untouched rather than truncated or corrupted.
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let temp_path = sibling_temp_path(path);
        let result = (|| -> io::Result<()> {
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            std::fs::rename(&temp_path, path)?;
            Ok(())
        })();
        if result.is_err() {
            // Best-effort cleanup: don't let a failed write leave a
            // half-written temp file lying around next to the status file.
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }
}

/// A process-unique sibling path for the atomic-write temp file, so
/// concurrent writers (unlikely, but cheap to guard against) never collide.
fn sibling_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("watch-status.json");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "safeguard_watch_status_{label}_{}_{}.json",
            std::process::id(),
            label.len()
        ))
    }

    #[test]
    fn successful_cycle_round_trips_through_disk() {
        let path = unique_path("success");
        let _cleanup = CleanupOnDrop(path.clone());

        let status = WatchStatus::starting(1);
        status.write_to(&path).unwrap();
        let loaded: WatchStatus =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.state, WatchState::Running);
        assert!(loaded.finished_at.is_none());

        let status = status.completed(true);
        status.write_to(&path).unwrap();
        let loaded: WatchStatus =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.state, WatchState::Completed);
        assert_eq!(loaded.is_safe, Some(true));
        assert!(loaded.finished_at.is_some());
        assert!(loaded.error.is_none());
    }

    #[test]
    fn error_cycle_records_reason_and_clears_is_safe() {
        let path = unique_path("error");
        let _cleanup = CleanupOnDrop(path.clone());

        let status = WatchStatus::starting(2).failed("comparison panicked");
        status.write_to(&path).unwrap();

        let loaded: WatchStatus =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.state, WatchState::Error);
        assert_eq!(loaded.error.as_deref(), Some("comparison panicked"));
        assert!(loaded.is_safe.is_none());
    }

    #[test]
    fn shutdown_marks_state_without_a_verdict() {
        let path = unique_path("shutdown");
        let _cleanup = CleanupOnDrop(path.clone());

        let status = WatchStatus::starting(3).shutdown();
        status.write_to(&path).unwrap();

        let loaded: WatchStatus =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.state, WatchState::ShuttingDown);
        assert!(loaded.finished_at.is_some());
    }

    #[test]
    fn starting_a_new_cycle_never_carries_over_previous_error() {
        let failed = WatchStatus::starting(1).failed("boom");
        assert!(failed.error.is_some());

        let next = WatchStatus::starting(2);
        assert!(next.error.is_none());
        assert!(next.is_safe.is_none());
        assert!(next.finished_at.is_none());
    }

    #[test]
    fn interrupted_write_does_not_corrupt_existing_status_file() {
        let path = unique_path("interrupted");
        let _cleanup = CleanupOnDrop(path.clone());

        // Seed the destination with a valid prior status.
        let original = WatchStatus::starting(1).completed(true);
        original.write_to(&path).unwrap();
        let original_contents = std::fs::read_to_string(&path).unwrap();

        // Force the write to fail by occupying the exact temp path the
        // implementation will try to create a file at.
        let next = WatchStatus::starting(2);
        let temp_path = sibling_temp_path(&path);
        std::fs::create_dir(&temp_path).unwrap();
        let _cleanup_dir = CleanupOnDrop(temp_path.clone());

        assert!(next.write_to(&path).is_err());

        // The destination must be untouched: still the last good document,
        // never truncated or partially overwritten by the failed attempt.
        let contents_after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents_after, original_contents);
        let loaded: WatchStatus = serde_json::from_str(&contents_after).unwrap();
        assert_eq!(loaded.cycle, 1);
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_dir(&self.0);
        }
    }
}
