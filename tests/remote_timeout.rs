//! Verifies that `--remote-timeout-secs 0` is a defined, fast failure
//! rather than an unbounded wait.
//!
//! ureq (the HTTP client `src/remote.rs` uses) computes a request's
//! deadline once, as `Instant::now() + timeout`, when the request
//! starts. With a zero-second timeout that deadline is already in the
//! past by the time it's first checked — resolving the host and opening
//! the socket both take some nonzero time — so the very first check
//! fails the request with a timeout error instead of ever blocking on
//! I/O. See the "Size and timeout limits" note under the HTTPS section
//! of docs/choosing-an-input-source.md, and the `--remote-timeout-secs`
//! flag's own `--help` text, for how this is documented for users.
//!
//! The host below, `203.0.113.1`, is RFC 5737's "TEST-NET-3"
//! documentation-only address block: guaranteed non-routable, and
//! because it's an IP literal rather than a hostname, resolving it needs
//! no DNS lookup (`std`'s address resolution parses an IP literal
//! directly). The test therefore touches no real network and can't be
//! flaky in a sandboxed CI environment — consistent with
//! `tests/remote_cli.rs`'s own doc comment, which notes the same "no
//! network access" constraint for this project's other `https://` tests.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn remote_timeout_secs_zero_fails_fast_with_a_clear_message_instead_of_hanging() {
    let old = wasm("v1.wasm").display().to_string();

    let cache_dir = std::env::temp_dir().join(format!(
        "safeguard-remote-timeout-zero-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&cache_dir);
    let cache_dir_str = cache_dir.display().to_string();

    // A syntactically valid reference (real digest shape) so the CLI
    // gets past input validation and actually attempts the fetch --
    // that's the only way to exercise the timeout path itself, as
    // opposed to tests/remote_cli.rs's validation-rejection tests.
    let reference = format!("https://203.0.113.1/contract.wasm#sha256={}", "a".repeat(64));

    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            &old,
            &reference,
            "--remote-timeout-secs",
            "0",
            "--remote-cache-dir",
            &cache_dir_str,
            "--quiet",
        ])
        .output()
        .expect("failed to run binary");
    let elapsed = start.elapsed();

    let _ = std::fs::remove_dir_all(&cache_dir);

    // The real assertion the ticket is about: this must not hang. Being
    // an unroutable IP literal with zero budget, the process should
    // return in well under a second in practice; 10s leaves enormous
    // headroom for a loaded CI box while still catching an accidental
    // regression to an unbounded (or OS-default, e.g. ~30-120s TCP SYN)
    // wait.
    assert!(
        elapsed < Duration::from_secs(10),
        "a zero-second remote timeout must fail fast, not hang; took {elapsed:?}"
    );

    let code = output.status.code().expect("process terminated by signal");
    assert_ne!(
        code, 0,
        "an unreachable host with a zero-second timeout must be a defined failure, not a silent success"
    );

    let stderr = String::from_utf8(output.stderr)
        .expect("stderr was not valid UTF-8")
        .to_lowercase();
    assert!(
        stderr.contains("time"), // matches "timed out" / "timeout"
        "stderr should explain the failure as a timeout, got: {stderr}"
    );
}
