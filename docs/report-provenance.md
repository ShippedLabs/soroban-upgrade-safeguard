# Report Provenance Fields

Every report produced by `soroban-upgrade-safeguard` includes a `provenance` block at the top level of the JSON document. Its purpose is to tie each verdict to the exact inputs and environment that produced it, so that a stored report can be audited, reproduced, or compared against a later run.

## Fields

| Field | Type | Always present | Description |
|-------|------|---------------|-------------|
| `tool_version` | string | Yes | The version of `soroban-upgrade-safeguard` that produced the report, taken from the crate's `Cargo.toml` at build time (e.g. `"0.9.1"`). |
| `timestamp` | string | Yes¹ | ISO 8601 / RFC 3339 timestamp of when the run completed (e.g. `"2024-06-11T14:03:27Z"`). |
| `inputs` | array of strings | Yes | Identifiers for the inputs the tool compared. For local paths these are the file paths; for RPC baselines the contract ID; for HTTPS inputs the URL including its `#sha256=…` pin. The old build appears first, followed by the new build. |
| `git_commit` | string or null | No | The full SHA of the Git commit the tool was invoked from, when the working directory is inside a Git repository and the `git` binary is available. `null` (field absent) when Git metadata could not be captured — this is always best-effort and is never required for a report to be valid. |
| `symlinks` | array of objects | No | One entry for each positional input that was, or passed through, a symbolic link. Each entry has `requested` (the path as supplied on the command line) and `resolved` (the absolute target after all symlink hops). Absent when neither input traversed a symlink. |
| `ledger_sequence` | integer or null | No | The ledger sequence number at which the on-chain baseline was fetched, when `--contract-id` / `--rpc-url` was used. Absent for local-file comparisons. |
| `network` | string or null | No | The Stellar network passphrase or short identifier returned by the RPC endpoint (e.g. `"Test SDF Network ; September 2015"`). Absent for local-file comparisons. |
| `rpc_endpoint` | string or null | No | The sanitized RPC endpoint URL — any `Authorization` or `Cookie` query parameters are stripped before recording. Absent for local-file comparisons. |
| `code_hash` | string or null | No | The hex-encoded SHA-256 of the on-chain WASM bytecode fetched via RPC, as verified against the contract instance hash. Absent for local-file comparisons. |
| `live_until_ledger_seq` | integer or null | No | The ledger sequence until which the sampled ledger entry remains live (`liveUntilLedgerSeq`), when the RPC endpoint reported one. Absent when the entry has no TTL or the endpoint did not report it. |

¹ See [Fields omitted by flags](#fields-omitted-by-flags) below.

## Fields omitted by flags

### `--no-timestamp`

Omits the `timestamp` value from provenance. The field remains in the JSON document but its value is an empty string (`""`). All other provenance fields are unaffected. Use this flag when you need deterministic, byte-for-byte reproducible reports — for snapshot tests or content-addressed artifact stores where an ever-changing timestamp would produce a different hash on every run.

### `--redact-paths`

Replaces the `resolved` target in each `symlinks` entry with a stable, non-identifying label (e.g. `<redacted>`). The `requested` path (what was passed on the command line) is kept so the report still identifies which input was a symlink. Use this flag before publishing a report anywhere that the local filesystem layout — usernames, workspace directories, build server paths — should not be visible.

`--redact-paths` does not affect `inputs`, `rpc_endpoint`, `code_hash`, or interface hashes, all of which are already sanitized or are content-derived identifiers that carry no path information.

## Example provenance block (JSON)

```json
"provenance": {
  "tool_version": "0.9.1",
  "timestamp": "2024-06-11T14:03:27Z",
  "inputs": [
    "./wasm/v1.wasm",
    "./wasm/v2.wasm"
  ],
  "git_commit": "a3f9c1e4b2d87650cd31f9e82b4c7a015d6e8f02",
  "symlinks": [
    {
      "requested": "./wasm/current.wasm",
      "resolved": "/builds/2024-06-11/token.wasm"
    }
  ]
}
```

An RPC-backed run includes the additional fields:

```json
"provenance": {
  "tool_version": "0.9.1",
  "timestamp": "2024-06-11T14:05:11Z",
  "inputs": [
    "CABCD1234...",
    "./wasm/v2.wasm"
  ],
  "ledger_sequence": 4921038,
  "network": "Test SDF Network ; September 2015",
  "rpc_endpoint": "https://soroban-testnet.stellar.org",
  "code_hash": "31fc0a23f04c6fc647ac44ba791228d8f0f12308685f0ac3798d37c79518906b",
  "live_until_ledger_seq": 5200000
}
```
