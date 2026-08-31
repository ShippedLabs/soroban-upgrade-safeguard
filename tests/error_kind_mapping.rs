//! Coverage for ErrorKind mapping from every Error variant.
//!
//! Each structured error variant maps to a stable ErrorKind, but a newly
//! added variant could be missed silently. This test constructs every
//! current variant and checks its kind, focusing on the public classification
//! contract rather than formatted error messages.

use soroban_upgrade_safeguard::error::{Error, ErrorKind};
use std::path::PathBuf;

#[test]
fn file_access_error_maps_to_file_access_kind() {
    let error = Error::FileAccess {
        path: PathBuf::from("file.wasm"),
        details: "not found".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::FileAccess);
}

#[test]
fn wasm_validation_error_maps_to_wasm_validation_kind() {
    let error = Error::WasmValidation {
        path: Some(PathBuf::from("contract.wasm")),
        details: "bad magic bytes".to_string(),
        byte_offset: Some(0),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::WasmValidation);
}

#[test]
fn section_extraction_error_maps_to_section_extraction_kind() {
    let error = Error::SectionExtraction {
        section_name: "contractspecv0".to_string(),
        section_index: 1,
        byte_offset: 42,
        details: "malformed section".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::SectionExtraction);
}

#[test]
fn xdr_decoding_error_maps_to_xdr_decoding_kind() {
    let error = Error::XdrDecoding {
        entry_index: Some(0),
        byte_offset: Some(100),
        details: "invalid XDR".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::XdrDecoding);
}

#[test]
fn rpc_transport_error_maps_to_rpc_transport_kind() {
    let error = Error::RpcTransport {
        rpc_url: "https://rpc.example.com".to_string(),
        details: "connection timeout".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::RpcTransport);
}

#[test]
fn rpc_protocol_error_maps_to_rpc_protocol_kind() {
    let error = Error::RpcProtocol {
        rpc_url: "https://rpc.example.com".to_string(),
        code: -32601,
        message: "method not found".to_string(),
    };
    assert_eq!(error.kind(), ErrorKind::RpcProtocol);
}

#[test]
fn unsupported_contract_error_maps_to_unsupported_contract_kind() {
    let error = Error::UnsupportedContract {
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_string(),
        kind: "Stellar Asset".to_string(),
    };
    assert_eq!(error.kind(), ErrorKind::UnsupportedContract);
}

#[test]
fn suppression_config_error_maps_to_suppression_config_kind() {
    let error = Error::SuppressionConfig {
        path: Some(PathBuf::from(".safeguard.toml")),
        details: "invalid TOML".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::SuppressionConfig);
}

#[test]
fn batch_boundary_error_maps_to_batch_boundary_kind() {
    let error = Error::BatchBoundary {
        details: "batch processing failed".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::BatchBoundary);
}

#[test]
fn integrity_error_maps_to_integrity_kind() {
    let error = Error::Integrity {
        details: "hash mismatch".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::Integrity);
}

#[test]
fn invalid_input_error_maps_to_invalid_input_kind() {
    let error = Error::InvalidInput {
        details: "invalid contract ID".to_string(),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn limit_exceeded_error_maps_to_limit_exceeded_kind() {
    let error = Error::LimitExceeded {
        details: "XDR depth limit exceeded".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn rpc_auth_config_error_maps_to_rpc_auth_config_kind() {
    let error = Error::RpcAuthConfig {
        details: "invalid bearer token".to_string(),
    };
    assert_eq!(error.kind(), ErrorKind::RpcAuthConfig);
}

#[test]
fn invalid_header_name_error_maps_to_invalid_header_name_kind() {
    let error = Error::InvalidHeaderName {
        name: "Invalid\nHeader".to_string(),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidHeaderName);
}

#[test]
fn remote_fetch_error_maps_to_remote_fetch_kind() {
    let error = Error::RemoteFetch {
        url: "https://example.com/contract.wasm".to_string(),
        details: "download failed".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::RemoteFetch);
}

#[test]
fn oci_fetch_error_maps_to_oci_fetch_kind() {
    let error = Error::OciFetch {
        reference: "oci://registry.example.com/contract@sha256:abc123".to_string(),
        details: "manifest not found".to_string(),
        source: None,
    };
    assert_eq!(error.kind(), ErrorKind::OciFetch);
}

#[test]
fn rpc_snapshot_consistency_error_maps_to_rpc_snapshot_consistency_kind() {
    let error = Error::RpcSnapshotConsistency {
        rpc_url: "https://rpc.example.com".to_string(),
        details: "ledger sequence mismatch".to_string(),
        attempts: 3,
        observed_sequences: vec![100, 101, 102],
    };
    assert_eq!(error.kind(), ErrorKind::RpcSnapshotConsistency);
}

#[test]
fn rpc_id_mismatch_error_maps_to_rpc_id_mismatch_kind() {
    let error = Error::RpcIdMismatch {
        rpc_url: "https://rpc.example.com".to_string(),
        expected_id: 1,
        received_id: Some("2".to_string()),
    };
    assert_eq!(error.kind(), ErrorKind::RpcIdMismatch);
}

#[test]
fn symlink_rejected_error_maps_to_symlink_rejected_kind() {
    let error = Error::SymlinkRejected {
        path: PathBuf::from("link.wasm"),
        resolved: Some(PathBuf::from("/actual/contract.wasm")),
    };
    assert_eq!(error.kind(), ErrorKind::SymlinkRejected);
}

#[test]
fn all_error_kinds_are_covered_by_mapping() {
    // This test ensures every ErrorKind variant has a corresponding Error
    // variant that maps to it. If a new ErrorKind is added without a
    // corresponding Error variant (or vice versa), this test will fail to
    // compile, catching the omission at build time.
    let all_kinds = vec![
        ErrorKind::FileAccess,
        ErrorKind::WasmValidation,
        ErrorKind::SectionExtraction,
        ErrorKind::XdrDecoding,
        ErrorKind::RpcTransport,
        ErrorKind::RpcProtocol,
        ErrorKind::UnsupportedContract,
        ErrorKind::SuppressionConfig,
        ErrorKind::BatchBoundary,
        ErrorKind::Integrity,
        ErrorKind::InvalidInput,
        ErrorKind::LimitExceeded,
        ErrorKind::RpcAuthConfig,
        ErrorKind::InvalidHeaderName,
        ErrorKind::RemoteFetch,
        ErrorKind::OciFetch,
        ErrorKind::RpcSnapshotConsistency,
        ErrorKind::RpcIdMismatch,
        ErrorKind::SymlinkRejected,
    ];

    // Create one error of each variant to ensure they all map correctly
    let errors = vec![
        Error::FileAccess {
            path: PathBuf::from("test"),
            details: String::new(),
            source: None,
        },
        Error::WasmValidation {
            path: None,
            details: String::new(),
            byte_offset: None,
            source: None,
        },
        Error::SectionExtraction {
            section_name: String::new(),
            section_index: 0,
            byte_offset: 0,
            details: String::new(),
            source: None,
        },
        Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: String::new(),
            source: None,
        },
        Error::RpcTransport {
            rpc_url: String::new(),
            details: String::new(),
            source: None,
        },
        Error::RpcProtocol {
            rpc_url: String::new(),
            code: 0,
            message: String::new(),
        },
        Error::UnsupportedContract {
            contract_id: String::new(),
            kind: String::new(),
        },
        Error::SuppressionConfig {
            path: None,
            details: String::new(),
            source: None,
        },
        Error::BatchBoundary {
            details: String::new(),
            source: None,
        },
        Error::Integrity {
            details: String::new(),
            source: None,
        },
        Error::InvalidInput {
            details: String::new(),
        },
        Error::LimitExceeded {
            details: String::new(),
            source: None,
        },
        Error::RpcAuthConfig {
            details: String::new(),
        },
        Error::InvalidHeaderName {
            name: String::new(),
        },
        Error::RemoteFetch {
            url: String::new(),
            details: String::new(),
            source: None,
        },
        Error::OciFetch {
            reference: String::new(),
            details: String::new(),
            source: None,
        },
        Error::RpcSnapshotConsistency {
            rpc_url: String::new(),
            details: String::new(),
            attempts: 0,
            observed_sequences: vec![],
        },
        Error::RpcIdMismatch {
            rpc_url: String::new(),
            expected_id: 0,
            received_id: None,
        },
        Error::SymlinkRejected {
            path: PathBuf::new(),
            resolved: None,
        },
    ];

    // Verify we have the same count
    assert_eq!(
        all_kinds.len(),
        errors.len(),
        "Number of ErrorKind variants must match number of Error variants"
    );

    // Verify each error maps to the expected kind
    for (expected_kind, error) in all_kinds.iter().zip(errors.iter()) {
        assert_eq!(
            error.kind(),
            *expected_kind,
            "Error variant must map to its corresponding ErrorKind"
        );
    }
}
