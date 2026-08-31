//! Coverage for error retryability and transience classification.
//!
//! Consumers use `is_retryable()` and `is_transient()` to decide whether an
//! operation should be attempted again. This test suite verifies that:
//! - RPC transport errors are classified as retryable and transient.
//! - Input, parsing, integrity, and configuration errors are non-retryable.
//! - Both classification methods remain consistent.

use soroban_upgrade_safeguard::error::{Error, ErrorKind};
use std::path::PathBuf;

#[test]
fn rpc_transport_errors_are_retryable_and_transient() {
    let error = Error::RpcTransport {
        rpc_url: "https://rpc.example.com".to_string(),
        details: "Connection timeout".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::RpcTransport);
    assert!(
        error.is_retryable(),
        "RPC transport errors should be retryable"
    );
    assert!(
        error.is_transient(),
        "RPC transport errors should be transient"
    );
}

#[test]
fn remote_fetch_errors_are_retryable_and_transient() {
    let error = Error::RemoteFetch {
        url: "https://example.com/contract.wasm".to_string(),
        details: "Network timeout".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::RemoteFetch);
    assert!(
        error.is_retryable(),
        "Remote fetch errors should be retryable"
    );
    assert!(
        error.is_transient(),
        "Remote fetch errors should be transient"
    );
}

#[test]
fn oci_fetch_errors_are_retryable_and_transient() {
    let error = Error::OciFetch {
        reference: "oci://registry.example.com/contract@sha256:abc123".to_string(),
        details: "Temporary network issue".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::OciFetch);
    assert!(error.is_retryable(), "OCI fetch errors should be retryable");
    assert!(error.is_transient(), "OCI fetch errors should be transient");
}

#[test]
fn file_access_errors_are_not_retryable() {
    let error = Error::FileAccess {
        path: PathBuf::from("/nonexistent/file.wasm"),
        details: "File not found".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::FileAccess);
    assert!(
        !error.is_retryable(),
        "File access errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "File access errors should not be transient"
    );
}

#[test]
fn wasm_validation_errors_are_not_retryable() {
    let error = Error::WasmValidation {
        path: Some(PathBuf::from("contract.wasm")),
        details: "Bad magic bytes".to_string(),
        byte_offset: Some(0),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::WasmValidation);
    assert!(
        !error.is_retryable(),
        "WASM validation errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "WASM validation errors should not be transient"
    );
}

#[test]
fn xdr_decoding_errors_are_not_retryable() {
    let error = Error::XdrDecoding {
        entry_index: Some(0),
        byte_offset: Some(42),
        details: "Invalid XDR structure".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::XdrDecoding);
    assert!(
        !error.is_retryable(),
        "XDR decoding errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "XDR decoding errors should not be transient"
    );
}

#[test]
fn integrity_errors_are_not_retryable() {
    let error = Error::Integrity {
        details: "Hash mismatch".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert!(
        !error.is_retryable(),
        "Integrity errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "Integrity errors should not be transient"
    );
}

#[test]
fn invalid_input_errors_are_not_retryable() {
    let error = Error::InvalidInput {
        details: "Invalid contract ID".to_string(),
    };

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        !error.is_retryable(),
        "Invalid input errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "Invalid input errors should not be transient"
    );
}

#[test]
fn suppression_config_errors_are_not_retryable() {
    let error = Error::SuppressionConfig {
        path: Some(PathBuf::from(".safeguard.toml")),
        details: "Invalid TOML syntax".to_string(),
        source: None,
    };

    assert_eq!(error.kind(), ErrorKind::SuppressionConfig);
    assert!(
        !error.is_retryable(),
        "Suppression config errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "Suppression config errors should not be transient"
    );
}

#[test]
fn rpc_protocol_errors_are_not_retryable() {
    let error = Error::RpcProtocol {
        rpc_url: "https://rpc.example.com".to_string(),
        code: -32601,
        message: "Method not found".to_string(),
    };

    assert_eq!(error.kind(), ErrorKind::RpcProtocol);
    assert!(
        !error.is_retryable(),
        "RPC protocol errors should not be retryable"
    );
    assert!(
        !error.is_transient(),
        "RPC protocol errors should not be transient"
    );
}

#[test]
fn retryable_and_transient_methods_are_consistent() {
    // For all error variants, is_retryable() and is_transient() should
    // always return the same value (they are currently aliases).
    let errors = vec![
        Error::RpcTransport {
            rpc_url: "https://rpc.example.com".to_string(),
            details: "timeout".to_string(),
            source: None,
        },
        Error::RemoteFetch {
            url: "https://example.com/file.wasm".to_string(),
            details: "timeout".to_string(),
            source: None,
        },
        Error::OciFetch {
            reference: "oci://registry.example.com/image".to_string(),
            details: "timeout".to_string(),
            source: None,
        },
        Error::FileAccess {
            path: PathBuf::from("file.wasm"),
            details: "not found".to_string(),
            source: None,
        },
        Error::WasmValidation {
            path: None,
            details: "bad magic".to_string(),
            byte_offset: None,
            source: None,
        },
        Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: "invalid".to_string(),
            source: None,
        },
        Error::Integrity {
            details: "mismatch".to_string(),
            source: None,
        },
        Error::InvalidInput {
            details: "invalid".to_string(),
        },
        Error::SuppressionConfig {
            path: None,
            details: "parse error".to_string(),
            source: None,
        },
        Error::RpcProtocol {
            rpc_url: "https://rpc.example.com".to_string(),
            code: -1,
            message: "error".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(
            error.is_retryable(),
            error.is_transient(),
            "is_retryable() and is_transient() must be consistent for {:?}",
            error.kind()
        );
    }
}
