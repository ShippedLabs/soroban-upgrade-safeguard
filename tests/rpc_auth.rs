use std::env;
use std::sync::Mutex;

use soroban_upgrade_safeguard::error::ErrorKind;
use soroban_upgrade_safeguard::rpc::{redact_url, RpcClientConfig};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn resolves_named_secret_environment_variables_without_exposing_values() {
    let _guard = ENV_LOCK.lock().unwrap();
    env::set_var("SAFEGUARD_TEST_RPC_SECRET", "super-secret-token");

    let config = RpcClientConfig::new("https://user:pass@example.test/rpc?token=secret")
        .unwrap()
        .with_env_header("Authorization", "SAFEGUARD_TEST_RPC_SECRET")
        .unwrap();
    let resolved = config.resolve_headers().unwrap();

    let debug = format!("{config:?} {resolved:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("user:pass"));
    assert!(!debug.contains("token=secret"));
    assert!(debug.contains("[REDACTED]"));

    env::remove_var("SAFEGUARD_TEST_RPC_SECRET");
}

#[test]
fn missing_secret_is_a_typed_configuration_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    env::remove_var("SAFEGUARD_MISSING_RPC_SECRET");

    let config = RpcClientConfig::new("https://example.test/rpc")
        .unwrap()
        .with_env_header("X-Api-Key", "SAFEGUARD_MISSING_RPC_SECRET")
        .unwrap();
    let error = config.resolve_headers().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RpcAuthConfig);
    assert!(error.to_string().contains("SAFEGUARD_MISSING_RPC_SECRET"));
}

#[test]
fn duplicate_and_malformed_headers_are_rejected() {
    let duplicate = RpcClientConfig::new("https://example.test/rpc")
        .unwrap()
        .with_env_header("X-Api-Key", "ONE")
        .unwrap()
        .with_env_header("x-api-key", "TWO")
        .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::RpcAuthConfig);

    let malformed = RpcClientConfig::new("https://example.test/rpc")
        .unwrap()
        .with_env_header("X Bad", "SECRET")
        .unwrap_err();
    assert_eq!(malformed.kind(), ErrorKind::InvalidHeaderName);
}

#[test]
fn url_redaction_removes_credentials_and_query_fragments() {
    assert_eq!(
        redact_url("https://alice:password@example.test/rpc?api_key=secret#frag"),
        "https://[REDACTED]example.test/rpc"
    );
}
