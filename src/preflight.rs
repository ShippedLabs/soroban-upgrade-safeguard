//! Lightweight RPC connectivity preflight checks.
//!
//! Unlike the full analysis pipeline, a preflight check never fetches
//! contract code or ledger entries. It only confirms that the configured RPC
//! endpoint is reachable, speaks the minimum JSON-RPC 2.0 envelope shape, and
//! answers a cheap read-only method. Passing a preflight check is not a claim
//! that a contract or network is fully compatible with this tool — only that
//! the endpoint itself is usable.

use std::time::Duration;

use serde::Serialize;

use crate::rpc::RpcClientConfig;

/// Default request timeout for a preflight check. Deliberately shorter than
/// the 30s used for full RPC reads, since a preflight exists to fail fast.
pub const DEFAULT_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);

/// The JSON-RPC method used to probe endpoint capability. Read-only and cheap
/// on every known Stellar RPC implementation.
const PREFLIGHT_METHOD: &str = "getHealth";

/// Deterministic id sent with the preflight request; checked against the id
/// echoed back in the response.
const PREFLIGHT_REQUEST_ID: i64 = 1;

/// Result of the transport-level check: could the endpoint be reached at all.
#[derive(Debug, Clone, Serialize)]
pub struct TransportCheck {
    pub success: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

/// Result of the protocol-shape check: does the response look like a
/// well-formed JSON-RPC 2.0 envelope for the request that was sent.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCheck {
    pub success: bool,
    pub jsonrpc_version: Option<String>,
    pub id_matches: Option<bool>,
    pub error: Option<String>,
}

/// Result of the endpoint-capability check: did the probed method actually
/// succeed (a JSON-RPC `result`, not an `error`).
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityCheck {
    pub method: String,
    pub success: bool,
    pub latest_ledger: Option<u64>,
    pub error: Option<String>,
}

/// Full preflight report. Transport, protocol, and capability are reported
/// separately since each can fail for an independent reason (an endpoint can
/// be reachable but speak a broken protocol, or speak valid JSON-RPC while
/// still rejecting the specific probed method).
#[derive(Debug, Clone, Serialize)]
pub struct PreflightReport {
    pub rpc_endpoint: String,
    pub transport: TransportCheck,
    pub protocol: ProtocolCheck,
    pub capability: CapabilityCheck,
}

impl PreflightReport {
    pub fn all_passed(&self) -> bool {
        self.transport.success && self.protocol.success && self.capability.success
    }
}

/// Run a preflight check against `config`'s endpoint using the default timeout.
pub fn run_preflight(config: &RpcClientConfig) -> PreflightReport {
    run_preflight_with_timeout(config, DEFAULT_PREFLIGHT_TIMEOUT)
}

/// Run a preflight check with an explicit request timeout. Exposed
/// separately so tests can use a short timeout instead of waiting out the
/// production default.
pub fn run_preflight_with_timeout(config: &RpcClientConfig, timeout: Duration) -> PreflightReport {
    let rpc_endpoint = config.redacted_url();
    let mut transport = TransportCheck {
        success: false,
        status_code: None,
        error: None,
    };
    let mut protocol = ProtocolCheck {
        success: false,
        jsonrpc_version: None,
        id_matches: None,
        error: None,
    };
    let mut capability = CapabilityCheck {
        method: PREFLIGHT_METHOD.to_string(),
        success: false,
        latest_ledger: None,
        error: None,
    };

    let headers = match config.resolve_headers() {
        Ok(headers) => headers,
        Err(e) => {
            transport.error = Some(e.to_string());
            return PreflightReport {
                rpc_endpoint,
                transport,
                protocol,
                capability,
            };
        }
    };

    let agent = crate::rpc::agent_with_timeout(timeout);
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": PREFLIGHT_REQUEST_ID,
        "method": PREFLIGHT_METHOD,
        "params": {}
    });

    let mut request = agent.post(&config.url);
    for (name, value) in &headers.values {
        request = request.set(name, value);
    }

    let response = match request.send_json(payload) {
        Ok(resp) => {
            transport.success = true;
            transport.status_code = Some(resp.status());
            resp
        }
        Err(ureq::Error::Status(code, resp)) => {
            transport.success = true;
            transport.status_code = Some(code);
            let message = if code == 401 || code == 403 {
                format!("endpoint rejected the request: authentication failed (HTTP {code})")
            } else {
                format!("endpoint returned HTTP {code}")
            };
            protocol.error = Some(message.clone());
            capability.error = Some(message);
            resp
        }
        Err(ureq::Error::Transport(t)) => {
            transport.error = Some(format!("{t}"));
            let unreachable = "endpoint was not reachable; transport check failed".to_string();
            protocol.error = Some(unreachable.clone());
            capability.error = Some(unreachable);
            return PreflightReport {
                rpc_endpoint,
                transport,
                protocol,
                capability,
            };
        }
    };

    let body: serde_json::Value = match response.into_json() {
        Ok(body) => body,
        Err(_) => {
            if protocol.error.is_none() {
                protocol.error = Some("response body is not valid JSON".to_string());
            }
            if capability.error.is_none() {
                capability.error =
                    Some("could not evaluate endpoint capability: invalid JSON body".to_string());
            }
            return PreflightReport {
                rpc_endpoint,
                transport,
                protocol,
                capability,
            };
        }
    };

    let jsonrpc_version = body
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let id_matches = body
        .get("id")
        .map(|id| id.as_i64() == Some(PREFLIGHT_REQUEST_ID));
    protocol.jsonrpc_version = jsonrpc_version.clone();
    protocol.id_matches = id_matches;

    if protocol.error.is_none() {
        if jsonrpc_version.as_deref() != Some("2.0") {
            protocol.error =
                Some("response missing or invalid 'jsonrpc' version field".to_string());
        } else if id_matches != Some(true) {
            protocol.error = Some("response 'id' does not match the request id".to_string());
        } else if body.get("result").is_none() && body.get("error").is_none() {
            protocol.error = Some("response has neither 'result' nor 'error'".to_string());
        } else {
            protocol.success = true;
        }
    }

    if capability.error.is_none() {
        if let Some(err) = body.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown RPC error");
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            capability.error = Some(format!("RPC error (code {code}): {msg}"));
        } else if let Some(result) = body.get("result") {
            capability.latest_ledger = result.get("latestLedger").and_then(|v| v.as_u64());
            capability.success = protocol.success;
        } else {
            capability.error = Some("response has neither 'result' nor 'error'".to_string());
        }
    }

    PreflightReport {
        rpc_endpoint,
        transport,
        protocol,
        capability,
    }
}
