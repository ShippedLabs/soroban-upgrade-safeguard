//! Hermetic local-registry integration tests for the `oci://` input resolver
//! (`src/oci.rs`).
//!
//! These spin up a tiny raw-socket HTTP server (mirroring the style already
//! used in `tests/remote_fetch.rs` / `tests/rpc_fetch.rs`) that plays the
//! role of an OCI distribution-spec registry: it serves canned manifest and
//! blob responses in a fixed order, and can simulate the `401`
//! `WWW-Authenticate` challenge/retry dance a real registry uses for token
//! auth. Production traffic is HTTPS-only ([`OciFetchConfig::https_only`]
//! defaults to `true`, and the CLI never overrides it), so every test here
//! explicitly opts into plain HTTP against localhost via `https_only: false`
//! — the one documented escape hatch that exists solely for this kind of
//! test harness.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use soroban_upgrade_safeguard::error::Error;
use soroban_upgrade_safeguard::loader::{load_wasm_from_oci, sha256_hex};
use soroban_upgrade_safeguard::oci::{
    resolve_oci_artifact, CacheStatus, OciArtifactKind, OciFetchConfig, OciReference, OciSelector,
    MEDIA_TYPE_EXTRACTED_SPEC, MEDIA_TYPE_WASM_GENERIC,
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
/// `host:port` address and the raw request text seen for each connection (in
/// the same order), so a test can assert exactly what was sent (headers
/// included) without a second live round trip.
fn spawn_server(responses: Vec<Vec<u8>>) -> (String, Arc<TcpListener>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock registry");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let accept_on = Arc::clone(&listener);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_writer = Arc::clone(&requests);

    thread::spawn(move || {
        for response in responses {
            if let Ok((mut stream, _)) = accept_on.accept() {
                let request = read_http_request(&mut stream);
                requests_writer.lock().unwrap().push(request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                thread::sleep(Duration::from_millis(30));
            }
        }
    });

    (addr, listener, requests)
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

fn unauthorized_response(www_authenticate: &str) -> Vec<u8> {
    format!(
        "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: {www_authenticate}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

static CACHE_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_cache_dir(label: &str) -> PathBuf {
    let n = CACHE_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "safeguard-oci-fetch-test-{}-{label}-{n}",
        std::process::id()
    ))
}

fn config(cache_dir: PathBuf) -> OciFetchConfig {
    OciFetchConfig {
        https_only: false, // localhost-only test harness escape hatch; see module docs.
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(5),
        cache_dir: Some(cache_dir),
        no_cache: false,
        allow_tags: false,
    }
}

/// Builds a minimal single-layer OCI manifest naming one layer with
/// `media_type` and `layer_digest` (`sha256:<hex>`), and returns its bytes
/// alongside its own content digest (`sha256:<hex>`).
fn build_manifest(media_type: &str, layer_digest: &str) -> (Vec<u8>, String) {
    let json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:00", "size": 2 },
        "layers": [
            { "mediaType": media_type, "digest": layer_digest, "size": 0 }
        ]
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    let digest = format!("sha256:{}", sha256_hex(&bytes));
    (bytes, digest)
}

fn digest_reference(registry: &str, repository: &str, digest: &str) -> OciReference {
    OciReference {
        registry: registry.to_string(),
        repository: repository.to_string(),
        selector: OciSelector::Digest(digest.to_string()),
    }
}

#[test]
fn resolve_downloads_and_verifies_a_digest_pinned_wasm_layer() {
    let wasm_bytes = b"a small pretend wasm artifact".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    let (addr, _server, _reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("success"));

    let artifact = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect("resolve should succeed");
    assert_eq!(artifact.bytes, wasm_bytes);
    assert_eq!(artifact.layer_digest, layer_digest);
    assert_eq!(artifact.manifest_digest, manifest_digest);
    assert_eq!(artifact.cache_status, CacheStatus::Miss);
    assert_eq!(artifact.media_type, MEDIA_TYPE_WASM_GENERIC);
    assert!(artifact.resolved_tag.is_none());
}

#[test]
fn second_resolve_serves_the_layer_from_cache_without_refetching_the_blob() {
    let wasm_bytes = b"cache me if you can".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    // Exactly 3 canned responses: manifest+blob for the first resolve, then
    // only a manifest for the second — a fourth connection attempt (a
    // re-fetched blob) would starve on `accept()` and the test would hang.
    let (addr, _server, _reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("cache-hit"));

    let first = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect("first resolve should succeed");
    assert_eq!(first.cache_status, CacheStatus::Miss);

    let second = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect("second resolve should be served from cache");
    assert_eq!(second.cache_status, CacheStatus::Hit);
    assert_eq!(second.bytes, wasm_bytes);
}

#[test]
fn resolve_rejects_a_manifest_digest_mismatch() {
    let wasm_bytes = b"irrelevant".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, _real_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    let (addr, _server, _reqs) = spawn_server(vec![ok_response(
        "application/vnd.oci.image.manifest.v1+json",
        &manifest_bytes,
    )]);

    // Pin a digest that does NOT match the manifest bytes the server sends.
    let bogus_digest = format!("sha256:{}", "a".repeat(64));
    let reference = digest_reference(&addr, "myrepo", &bogus_digest);
    let cfg = config(fresh_cache_dir("manifest-mismatch"));

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("digest mismatch must be rejected");
    assert!(matches!(err, Error::Integrity { .. }));
    assert!(err.to_string().contains("manifest digest mismatch"));
}

#[test]
fn resolve_rejects_a_layer_digest_mismatch_and_does_not_poison_the_cache() {
    let claimed_digest = format!("sha256:{}", "b".repeat(64));
    let (manifest_bytes, manifest_digest) =
        build_manifest(MEDIA_TYPE_WASM_GENERIC, &claimed_digest);

    let (addr, _server, _reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        // The blob served does not hash to `claimed_digest`.
        ok_response("application/wasm", b"not the promised bytes"),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cache_dir = fresh_cache_dir("layer-mismatch");
    let cfg = config(cache_dir.clone());

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("layer digest mismatch must be rejected");
    assert!(matches!(err, Error::Integrity { .. }));
    assert!(err.to_string().contains("layer digest mismatch"));
    assert!(
        !cache_dir.exists(),
        "a failed verification must not populate the cache"
    );
}

#[test]
fn resolve_rejects_a_malformed_manifest() {
    let malformed = b"not valid json at all".to_vec();
    let digest = format!("sha256:{}", sha256_hex(&malformed));

    let (addr, _server, _reqs) = spawn_server(vec![ok_response(
        "application/vnd.oci.image.manifest.v1+json",
        &malformed,
    )]);

    let reference = digest_reference(&addr, "myrepo", &digest);
    let cfg = config(fresh_cache_dir("malformed-manifest"));

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("malformed manifest JSON must be rejected");
    assert!(matches!(err, Error::OciFetch { .. }));
    assert!(err.to_string().to_lowercase().contains("json"));
}

#[test]
fn resolve_rejects_a_manifest_with_no_matching_layer() {
    let (manifest_bytes, digest) = build_manifest(
        "application/vnd.some-other-artifact.v1",
        &format!("sha256:{}", "c".repeat(64)),
    );

    let (addr, _server, _reqs) = spawn_server(vec![ok_response(
        "application/vnd.oci.image.manifest.v1+json",
        &manifest_bytes,
    )]);

    let reference = digest_reference(&addr, "myrepo", &digest);
    let cfg = config(fresh_cache_dir("no-matching-layer"));

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("a manifest with no wasm-typed layer must be rejected");
    assert!(matches!(err, Error::OciFetch { .. }));
    assert!(err.to_string().contains("no layer"));
}

#[test]
fn resolve_rejects_a_multi_manifest_image_index() {
    let index_json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:aa", "size": 1 }
        ]
    });
    let bytes = serde_json::to_vec(&index_json).unwrap();
    let digest = format!("sha256:{}", sha256_hex(&bytes));

    let (addr, _server, _reqs) = spawn_server(vec![ok_response(
        "application/vnd.oci.image.index.v1+json",
        &bytes,
    )]);

    let reference = digest_reference(&addr, "myrepo", &digest);
    let cfg = config(fresh_cache_dir("image-index"));

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("a multi-manifest image index must be rejected");
    assert!(matches!(err, Error::OciFetch { .. }));
    assert!(err.to_string().to_lowercase().contains("index"));
}

#[test]
fn resolve_rejects_a_response_larger_than_the_configured_limit() {
    let big_body = vec![b'x'; 4096];
    let digest = format!("sha256:{}", sha256_hex(&big_body));

    let (addr, _server, _reqs) = spawn_server(vec![ok_response(
        "application/vnd.oci.image.manifest.v1+json",
        &big_body,
    )]);

    let reference = digest_reference(&addr, "myrepo", &digest);
    let mut cfg = config(fresh_cache_dir("oversized"));
    cfg.max_bytes = 16; // far smaller than the manifest body above.

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("an oversized response should be rejected");
    assert!(matches!(err, Error::OciFetch { .. }));
    assert!(err.to_string().to_lowercase().contains("size"));
}

#[test]
fn a_401_bearer_challenge_is_exchanged_for_a_token_and_the_request_is_retried_with_it() {
    let wasm_bytes = b"gated behind a bearer token".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    // Two independent listeners (different ports = different origins), so
    // the token exchange genuinely crosses a boundary from the registry to
    // its auth realm, exactly as it would against a real registry.
    let (token_addr, _token_server, token_reqs) = spawn_server(vec![ok_response(
        "application/json",
        br#"{"token":"granted-token-123"}"#,
    )]);
    let www_authenticate = format!(
        r#"Bearer realm="http://{token_addr}/token",service="registry.example",scope="repository:myrepo:pull""#
    );
    let (addr, _registry_server, registry_reqs) = spawn_server(vec![
        unauthorized_response(&www_authenticate),
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("bearer-auth"));

    let artifact = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect("bearer challenge/retry flow should succeed");
    assert_eq!(artifact.bytes, wasm_bytes);

    let token_seen = token_reqs.lock().unwrap();
    assert_eq!(
        token_seen.len(),
        1,
        "the token realm should be hit exactly once"
    );
    assert!(
        token_seen[0].starts_with("GET /token"),
        "token exchange should hit the realm path, got: {}",
        token_seen[0]
    );

    let registry_seen = registry_reqs.lock().unwrap();
    assert_eq!(
        registry_seen.len(),
        3,
        "expected the initial challenge, the retried manifest request, and the blob request"
    );
    assert!(
        registry_seen[1].contains("Authorization: Bearer granted-token-123"),
        "retried manifest request must carry the issued bearer token, got headers:\n{}",
        registry_seen[1]
    );
}

#[test]
fn a_401_basic_challenge_uses_docker_config_credentials() {
    let wasm_bytes = b"gated behind basic auth".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    let (addr, _server, reqs) = spawn_server(vec![
        unauthorized_response(r#"Basic realm="registry""#),
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
    ]);

    // Point DOCKER_CONFIG at a fresh directory containing a plaintext
    // `auths` entry for this mock registry's host:port.
    let docker_config_dir = fresh_cache_dir("docker-config");
    std::fs::create_dir_all(&docker_config_dir).unwrap();
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let auth = BASE64.encode("alice:hunter2");
    let config_json = serde_json::json!({ "auths": { addr.clone(): { "auth": auth } } });
    std::fs::write(
        docker_config_dir.join("config.json"),
        serde_json::to_vec(&config_json).unwrap(),
    )
    .unwrap();

    let original_docker_config = std::env::var("DOCKER_CONFIG").ok();
    std::env::set_var("DOCKER_CONFIG", &docker_config_dir);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("basic-auth"));
    let result = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg);

    match original_docker_config {
        Some(v) => std::env::set_var("DOCKER_CONFIG", v),
        None => std::env::remove_var("DOCKER_CONFIG"),
    }
    std::fs::remove_dir_all(&docker_config_dir).ok();

    let artifact = result.expect("basic auth flow with docker config credentials should succeed");
    assert_eq!(artifact.bytes, wasm_bytes);

    let seen = reqs.lock().unwrap();
    let expected_basic = format!("Basic {}", BASE64.encode("alice:hunter2"));
    assert!(
        seen[1].contains(&format!("Authorization: {expected_basic}")),
        "retried manifest request must carry the resolved Basic credentials, got headers:\n{}",
        seen[1]
    );
}

#[test]
fn a_tag_reference_resolves_to_a_digest_only_when_tags_are_explicitly_allowed() {
    let wasm_bytes = b"tag-resolved artifact".to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    let (addr, _server, reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
    ]);

    let reference = OciReference {
        registry: addr.clone(),
        repository: "myrepo".to_string(),
        selector: OciSelector::Tag("latest".to_string()),
    };

    let mut cfg = config(fresh_cache_dir("tag-allowed"));
    cfg.allow_tags = true;

    let artifact = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect("an allowed tag reference should resolve");
    assert_eq!(artifact.resolved_tag.as_deref(), Some("latest"));
    // The resolved digest is computed locally from the manifest bytes, not
    // trusted from any header, and must match what a digest-pinned
    // reference would have required.
    assert_eq!(artifact.manifest_digest, manifest_digest);

    let seen = reqs.lock().unwrap();
    assert!(
        seen[0].starts_with("GET /v2/myrepo/manifests/latest"),
        "manifest request should use the tag, got: {}",
        seen[0]
    );
}

#[test]
fn resolve_rejects_a_tag_reference_without_the_opt_in_before_any_network_access() {
    // No server is spawned at all: rejection must happen before any
    // connection is attempted, so an unreachable address is fine here.
    let reference = OciReference {
        registry: "127.0.0.1:1".to_string(),
        repository: "myrepo".to_string(),
        selector: OciSelector::Tag("latest".to_string()),
    };
    let cfg = config(fresh_cache_dir("tag-disallowed"));
    assert!(!cfg.allow_tags);

    let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &cfg)
        .expect_err("a tag reference must be rejected without --allow-oci-tags");
    assert!(matches!(err, Error::InvalidInput { .. }));
}

#[test]
fn resolve_selects_the_extracted_spec_layer_for_that_artifact_kind() {
    let spec_bytes = br#"{"functions":[]}"#.to_vec();
    let layer_digest = format!("sha256:{}", sha256_hex(&spec_bytes));
    let (manifest_bytes, manifest_digest) =
        build_manifest(MEDIA_TYPE_EXTRACTED_SPEC, &layer_digest);

    let (addr, _server, _reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/json", &spec_bytes),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("extracted-spec"));

    let artifact = resolve_oci_artifact(&reference, OciArtifactKind::ExtractedSpec, &cfg)
        .expect("extracted-spec resolve should succeed");
    assert_eq!(artifact.bytes, spec_bytes);
    assert_eq!(artifact.media_type, MEDIA_TYPE_EXTRACTED_SPEC);
}

#[test]
fn load_wasm_from_oci_produces_a_validated_wasm_module() {
    let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join("v1.wasm");
    let wasm_bytes = std::fs::read(&wasm_path).expect("fixture WASM should exist");
    let layer_digest = format!("sha256:{}", sha256_hex(&wasm_bytes));
    let (manifest_bytes, manifest_digest) = build_manifest(MEDIA_TYPE_WASM_GENERIC, &layer_digest);

    let (addr, _server, _reqs) = spawn_server(vec![
        ok_response(
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_bytes,
        ),
        ok_response("application/wasm", &wasm_bytes),
    ]);

    let reference = digest_reference(&addr, "myrepo", &manifest_digest);
    let cfg = config(fresh_cache_dir("wasm-module"));

    let (module, artifact) =
        load_wasm_from_oci(&reference, &cfg).expect("a valid fixture WASM should load");
    assert_eq!(module.bytes, wasm_bytes);
    assert_eq!(module.sha256, sha256_hex(&wasm_bytes));
    assert_eq!(
        module.path,
        format!("oci://{addr}/myrepo@{}", artifact.layer_digest)
    );
}
