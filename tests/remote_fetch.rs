//! Local-server integration tests for the `https://` input resolver
//! (`src/remote.rs`).
//!
//! These spin up a tiny raw-socket HTTP server (mirroring the style already
//! used in `tests/rpc_fetch.rs`) and drive `remote::fetch_verified` and
//! `loader::load_wasm_from_url` against it directly. Production traffic is
//! HTTPS-only ([`RemoteFetchConfig::https_only`] defaults to `true`, and the
//! CLI never overrides it), so every test here explicitly opts into plain
//! HTTP against localhost via `https_only: false` — the one documented
//! escape hatch that exists solely for this kind of test harness. The
//! `https_only` enforcement itself is covered separately, without needing a
//! live server, since it is rejected before any connection is attempted.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use soroban_upgrade_safeguard::error::Error;
use soroban_upgrade_safeguard::loader::{load_wasm_from_url, sha256_hex};
use soroban_upgrade_safeguard::remote::{
    fetch_verified, CacheStatus, RemoteFetchConfig, RemoteRef,
};

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
        if request.len() > 64 * 1024 {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

/// Spawns a server that replies to successive connections with each of
/// `responses`, in order, then stops accepting. Returns the bound
/// `host:port` address; the listener is kept alive via the returned `Arc`.
fn spawn_server(responses: Vec<Vec<u8>>) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let accept_on = Arc::clone(&listener);

    thread::spawn(move || {
        for response in responses {
            if let Ok((mut stream, _)) = accept_on.accept() {
                let _ = read_http_request(&mut stream);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                // Give the client time to finish reading before the
                // connection (and, on the last response, the listener) drops.
                thread::sleep(Duration::from_millis(30));
            }
        }
    });

    (addr, listener)
}

fn ok_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.0 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// A response that declares a `Content-Length` larger than the body it
/// actually sends before closing the connection.
fn truncated_response(declared_len: usize, actual_body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/wasm\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    response.extend_from_slice(actual_body);
    response
}

static CACHE_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, uniquely-named cache directory for one test, so parallel tests
/// (and the process-wide `SOROBAN_SAFEGUARD_REMOTE_CACHE` default) never
/// collide.
fn fresh_cache_dir(label: &str) -> PathBuf {
    let n = CACHE_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "safeguard-remote-fetch-test-{}-{label}-{n}",
        std::process::id()
    ))
}

fn config(cache_dir: PathBuf) -> RemoteFetchConfig {
    RemoteFetchConfig {
        https_only: false, // localhost-only test harness escape hatch; see module docs.
        max_redirects: 3,
        max_bytes: 1024,
        timeout: Duration::from_secs(5),
        cache_dir: Some(cache_dir),
        no_cache: false,
    }
}

#[test]
fn fetch_verified_downloads_and_verifies_success() {
    let body = b"a small pretend wasm artifact".to_vec();
    let digest = sha256_hex(&body);
    let (addr, _server) = spawn_server(vec![ok_response("application/wasm", &body)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/contract.wasm"),
        expected_sha256: digest.clone(),
    };
    let cfg = config(fresh_cache_dir("success"));

    let artifact = fetch_verified(&remote, &cfg).expect("fetch should succeed");
    assert_eq!(artifact.bytes, body);
    assert_eq!(artifact.sha256, digest);
    assert_eq!(artifact.cache_status, CacheStatus::Miss);
    assert_eq!(artifact.media_type.as_deref(), Some("application/wasm"));
    assert!(artifact.final_url.contains(&addr));
}

#[test]
fn fetch_verified_serves_second_call_from_cache_without_hitting_the_network_again() {
    let body = b"cache me if you can".to_vec();
    let digest = sha256_hex(&body);
    // Exactly one canned response: a second network hit would starve on
    // `accept()` and the test would hang/timeout rather than silently pass.
    let (addr, _server) = spawn_server(vec![ok_response("application/wasm", &body)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/contract.wasm"),
        expected_sha256: digest.clone(),
    };
    let cfg = config(fresh_cache_dir("cache-hit"));

    let first = fetch_verified(&remote, &cfg).expect("first fetch should succeed");
    assert_eq!(first.cache_status, CacheStatus::Miss);

    let second = fetch_verified(&remote, &cfg).expect("second fetch should be served from cache");
    assert_eq!(second.cache_status, CacheStatus::Hit);
    assert_eq!(second.bytes, body);
    assert_eq!(second.sha256, digest);
}

#[test]
fn fetch_verified_bypasses_cache_when_no_cache_is_set() {
    let body = b"never cached".to_vec();
    let digest = sha256_hex(&body);
    let (addr, _server) = spawn_server(vec![
        ok_response("application/wasm", &body),
        ok_response("application/wasm", &body),
    ]);

    let remote = RemoteRef {
        url: format!("http://{addr}/contract.wasm"),
        expected_sha256: digest,
    };
    let mut cfg = config(fresh_cache_dir("no-cache"));
    cfg.no_cache = true;

    let first = fetch_verified(&remote, &cfg).expect("first fetch should succeed");
    assert_eq!(first.cache_status, CacheStatus::Bypassed);

    // Because caching was disabled, this must hit the network a second time
    // (the mock server only has two canned responses, matching exactly).
    let second = fetch_verified(&remote, &cfg).expect("second fetch should succeed");
    assert_eq!(second.cache_status, CacheStatus::Bypassed);
}

#[test]
fn fetch_verified_follows_a_redirect_and_records_the_final_url() {
    let body = b"redirected artifact bytes".to_vec();
    let digest = sha256_hex(&body);

    // Two independent listeners (different ports = different origins) so the
    // redirect genuinely crosses an origin boundary.
    let (final_addr, _final_server) = spawn_server(vec![ok_response("application/wasm", &body)]);
    let final_url = format!("http://{final_addr}/final.wasm");
    let (entry_addr, _entry_server) = spawn_server(vec![redirect_response(&final_url)]);

    let remote = RemoteRef {
        url: format!("http://{entry_addr}/start.wasm"),
        expected_sha256: digest.clone(),
    };
    let cfg = config(fresh_cache_dir("redirect"));

    let artifact = fetch_verified(&remote, &cfg).expect("fetch should follow the redirect");
    assert_eq!(artifact.bytes, body);
    assert_eq!(artifact.sha256, digest);
    assert!(
        artifact.final_url.contains(&final_addr),
        "final_url '{}' should reflect the redirect target",
        artifact.final_url
    );
    assert!(artifact.original_url.contains(&entry_addr));
}

#[test]
fn fetch_verified_rejects_a_redirect_chain_longer_than_the_configured_limit() {
    // Every hop redirects back to the same URL: an infinite loop capped only
    // by `max_redirects`.
    let (addr, _server) = spawn_server(vec![
        redirect_response("/loop"),
        redirect_response("/loop"),
        redirect_response("/loop"),
        redirect_response("/loop"),
        redirect_response("/loop"),
    ]);

    let remote = RemoteRef {
        url: format!("http://{addr}/loop"),
        expected_sha256: "a".repeat(64),
    };
    let mut cfg = config(fresh_cache_dir("too-many-redirects"));
    cfg.max_redirects = 2;

    let err = fetch_verified(&remote, &cfg).expect_err("redirect loop should be rejected");
    assert!(matches!(err, Error::RemoteFetch { .. }));
    assert!(
        err.to_string().to_lowercase().contains("redirect"),
        "unexpected error message: {err}"
    );
}

#[test]
fn fetch_verified_rejects_a_response_larger_than_the_configured_limit() {
    let body = vec![b'x'; 200];
    let (addr, _server) = spawn_server(vec![ok_response("application/wasm", &body)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/big.wasm"),
        expected_sha256: sha256_hex(&body),
    };
    let mut cfg = config(fresh_cache_dir("oversized"));
    cfg.max_bytes = 16; // far smaller than the 200-byte body above.

    let err = fetch_verified(&remote, &cfg).expect_err("oversized response should be rejected");
    assert!(matches!(err, Error::RemoteFetch { .. }));
    assert!(
        err.to_string().to_lowercase().contains("size"),
        "unexpected error message: {err}"
    );

    // Nothing should have been cached from a rejected download.
    assert!(!cfg.resolved_cache_dir().exists());
}

#[test]
fn fetch_verified_rejects_a_truncated_response() {
    let actual = b"only part of the body arrives";
    // Declares a body twice as long as what is actually sent, then closes.
    let (addr, _server) = spawn_server(vec![truncated_response(actual.len() * 2, actual)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/truncated.wasm"),
        // A digest that would only match the *full* (never-delivered) body.
        expected_sha256: sha256_hex(&[actual.as_slice(), actual.as_slice()].concat()),
    };
    let cfg = config(fresh_cache_dir("truncated"));

    let err = fetch_verified(&remote, &cfg).expect_err("truncated response must not verify");
    // Either a transport-level read failure or a digest mismatch is an
    // acceptable rejection — what matters is that truncated bytes are never
    // silently accepted as the verified artifact.
    assert!(matches!(
        err,
        Error::RemoteFetch { .. } | Error::Integrity { .. }
    ));
}

#[test]
fn fetch_verified_rejects_digest_mismatch() {
    let body = b"the real content".to_vec();
    let (addr, _server) = spawn_server(vec![ok_response("application/wasm", &body)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/mismatch.wasm"),
        expected_sha256: sha256_hex(b"a completely different expected payload"),
    };
    let cfg = config(fresh_cache_dir("digest-mismatch"));

    let err = fetch_verified(&remote, &cfg).expect_err("digest mismatch should be rejected");
    assert!(matches!(err, Error::Integrity { .. }));
    assert!(err.to_string().contains("digest mismatch"));

    // A failed verification must not poison the cache.
    assert!(!cfg.resolved_cache_dir().exists());
}

#[test]
fn fetch_verified_rejects_non_https_scheme_when_https_only_is_left_at_its_default() {
    // `https_only` defaults to `true` in production; the check happens
    // before any connection attempt, so an unreachable address is fine here.
    let remote = RemoteRef {
        url: "http://127.0.0.1:1/never-reached.wasm".to_string(),
        expected_sha256: "a".repeat(64),
    };
    let cfg = RemoteFetchConfig {
        cache_dir: Some(fresh_cache_dir("https-only-default")),
        ..RemoteFetchConfig::default()
    };
    assert!(cfg.https_only, "production default must require https");

    let err = fetch_verified(&remote, &cfg).expect_err("non-https URL must be rejected");
    assert!(matches!(err, Error::RemoteFetch { .. }));
}

#[test]
fn load_wasm_from_url_produces_a_validated_wasm_module() {
    let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let bytes = std::fs::read(&wasm_path).expect("fixture WASM should exist");
    let digest = sha256_hex(&bytes);
    let (addr, _server) = spawn_server(vec![ok_response("application/wasm", &bytes)]);

    let remote = RemoteRef {
        url: format!("http://{addr}/contract.wasm"),
        expected_sha256: digest.clone(),
    };
    let cfg = config(fresh_cache_dir("wasm-module"));

    let (module, artifact) =
        load_wasm_from_url(&remote, &cfg).expect("a valid fixture WASM should load");
    assert_eq!(module.bytes, bytes);
    assert_eq!(module.sha256, digest);
    assert_eq!(module.path, artifact.final_url);
    assert_eq!(artifact.cache_status, CacheStatus::Miss);
}
