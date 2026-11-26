// SPDX-License-Identifier: MIT

//! Integration and unit tests for structured logging, correlation IDs, pair IDs,
//! redaction rules, concurrency safety, and verbosity control.

use soroban_upgrade_safeguard::logging::*;

#[test]
fn test_structured_event_model_stages() {
    set_json_logging(true);
    set_disable_timestamps(true);
    set_log_level(LogLevel::Debug);

    let stages = vec![
        "loading",
        "parsing",
        "comparison",
        "rpc",
        "cache",
        "policy",
        "rendering",
    ];

    for stage in stages {
        let mut fields = serde_json::Map::new();
        fields.insert("stage_name".to_string(), serde_json::json!(stage));
        log_event(
            LogLevel::Info,
            &format!("{}_event", stage),
            Some("corr-run-1"),
            Some("pair-alpha"),
            Some(fields),
            &format!("Completed stage {}", stage),
        );
    }
}

#[test]
fn test_correlation_ids_and_pair_ids() {
    set_json_logging(true);
    set_disable_timestamps(true);

    log_event(
        LogLevel::Info,
        "run_start",
        Some("run-corr-1"),
        None,
        None,
        "Run started",
    );

    log_event(
        LogLevel::Info,
        "batch_pair_analysis",
        Some("run-corr-1"),
        Some("pair-xyz"),
        None,
        "Analyzing pair",
    );

    log_event(
        LogLevel::Info,
        "rpc_sequence",
        Some("run-corr-1"),
        Some("pair-xyz"),
        None,
        "RPC request attempt",
    );

    log_event(
        LogLevel::Info,
        "watch_cycle",
        Some("watch-corr-1"),
        None,
        None,
        "Watch cycle iteration",
    );
}

#[test]
fn test_redaction_rules() {
    set_configured_private_fields(vec!["custom_private_token".to_string()]);

    assert_eq!(redact_value("api_key", "secret-key-123"), "[REDACTED]");
    assert_eq!(
        redact_value(
            "rpc_url",
            "https://admin:secret@rpc.stellar.org:8000/api?token=abc"
        ),
        "https://[REDACTED]rpc.stellar.org:8000/api"
    );
    assert_eq!(
        redact_value("wasm_file", "/Users/alice/projects/contract.wasm"),
        "<redacted>/contract.wasm"
    );
    assert_eq!(
        redact_value("custom_private_token", "my-private-value"),
        "[REDACTED]"
    );
}

#[test]
fn test_concurrency_logging() {
    set_json_logging(true);
    set_disable_timestamps(true);
    set_log_level(LogLevel::Info);

    let mut handles = vec![];
    for i in 0..10 {
        let handle = std::thread::spawn(move || {
            let corr = format!("corr-thread-{i}");
            let pair = format!("pair-{i}");
            for j in 0..5 {
                log_event(
                    LogLevel::Info,
                    "concurrent_event",
                    Some(&corr),
                    Some(&pair),
                    None,
                    &format!("Message {} from thread {}", j, i),
                );
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
}
