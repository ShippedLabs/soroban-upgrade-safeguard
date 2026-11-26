# Metrics Reference

`soroban-upgrade-safeguard` can emit an [OpenMetrics](https://openmetrics.io/)
(Prometheus-compatible) text snapshot at the end of any run. Pass
`--metrics-file <PATH>` to write it:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --metrics-file ./metrics.txt
```

The file is written atomically (written to a temp file in the same directory
first, then renamed) so an interrupted run never leaves a partial file.

## Privacy / data-leakage guarantees

**No user-supplied string ever appears as a metric label value.** Every label is
drawn from a closed enumeration defined in the metrics module. Contract IDs, RPC
URLs, file paths, finding messages, and suppression targets are all excluded from
label values. The complete set of distinct time series this module can produce is
fixed and documented below; it will never grow due to user input.

## Metric catalogue

All metric names are prefixed with `soroban_safeguard_`.

### Analysis pairs

| Metric | Type | Description |
|--------|------|-------------|
| `soroban_safeguard_pairs_total` | counter | Total contract-pair analysis attempts in this run |
| `soroban_safeguard_pairs_success_total` | counter | Pairs that completed without an internal error |
| `soroban_safeguard_pairs_error_total` | counter | Pairs that failed with an internal error |

### Findings

```
soroban_safeguard_findings_total{severity="<s>",axis="<a>",outcome="<o>"} <n>
```

Labels are drawn from closed enumerations:

**`severity`**

| Value | Meaning |
|-------|---------|
| `critical` | Critical severity |
| `warning` | Warning severity |
| `info` | Informational |

**`axis`**

| Value | Meaning |
|-------|---------|
| `storage_layout` | Storage-layout compatibility axis |
| `call_abi` | Call-ABI compatibility axis |
| `event_indexer` | Event-indexer compatibility axis |
| `source_level` | Source-level compatibility axis |
| `runtime_surface` | Runtime-surface compatibility axis |

**`outcome`**

| Value | Meaning |
|-------|---------|
| `active` | Finding was not suppressed |
| `suppressed` | Finding was suppressed by a suppression config |
| `migrated` | Finding is covered by a verified migration |

Maximum cardinality: 3 × 5 × 3 = **45 time series**.

### Pipeline stage durations

```
soroban_safeguard_stage_duration_seconds_total{stage="<s>"} <seconds>
```

Only emitted for stages that were actually timed (count > 0).

| `stage` value | Pipeline stage |
|---------------|----------------|
| `loading` | WASM file/bytes loading |
| `parsing` | Spec and metadata extraction |
| `diffing` | Structural comparison |
| `rendering` | Report rendering |
| `rpc` | RPC baseline fetch |

### Total run duration

```
soroban_safeguard_run_duration_seconds_total <seconds>
```

Wall-clock time of the entire analysis run. Only emitted when a run duration
was recorded (i.e. the run reached the metrics-write point).

### Metadata cache

```
soroban_safeguard_cache_lookups_total{result="<r>"} <n>
```

| `result` value | Meaning |
|----------------|---------|
| `hit` | Cache entry was found and used |
| `miss` | Cache entry was not found |
| `invalidated` | Cache entry was present but invalidated |

### RPC attempts

```
soroban_safeguard_rpc_attempts_total{result="<r>"} <n>
```

| `result` value | Meaning |
|----------------|---------|
| `success` | RPC call succeeded |
| `transport_error` | HTTP/network error |
| `protocol_error` | Invalid JSON-RPC response |
| `timeout` | Request timed out |
| `hash_mismatch` | Fetched WASM did not match `--expected-wasm-hash` |

### Watch mode

```
soroban_safeguard_watch_cycles_total <n>
```

Number of watch-mode re-analysis cycles triggered by filesystem events. Only
emitted in watch mode runs.

### Resource limits

```
soroban_safeguard_resource_limit_hits_total <n>
```

Number of times a configured resource limit (WASM size, complexity budget) was
exceeded. Only emitted when at least one limit was hit.

### WASM sizes (gauges)

```
soroban_safeguard_wasm_bytes{build="old"} <bytes>
soroban_safeguard_wasm_bytes{build="new"} <bytes>
```

WASM input sizes in bytes. Only emitted when the gauge was set (i.e. at least
one WASM was measured).

### Analysis mode

```
soroban_safeguard_mode{mode="<m>"} <0_or_1>
```

One time series per mode value; exactly one will be `1` for the current run.
Only emitted when the mode was recorded.

| `mode` value | Meaning |
|--------------|---------|
| `single` | Single-pair comparison |
| `batch` | Manifest batch mode |
| `watch` | Watch mode |
| `directory` | Directory-scan mode |
| `stream` | JSON Lines streaming mode |

## OpenMetrics EOF

The output always ends with the mandatory `# EOF` line as required by the
OpenMetrics text format specification.

## Compatibility policy

Metric names, units, label names, and the closed set of label values are part
of the documented compatibility policy. Once a metric is stabilised it will not
be renamed or have its labels changed in a backwards-incompatible way without a
major version bump. New metrics may be added in minor versions.

## Example output

```
# HELP soroban_safeguard_pairs Total number of contract-pair analysis attempts in this run.
# TYPE soroban_safeguard_pairs counter
soroban_safeguard_pairs_total 1
# HELP soroban_safeguard_pairs_success Contract-pair analyses that completed without an error.
# TYPE soroban_safeguard_pairs_success counter
soroban_safeguard_pairs_success_total 1
# HELP soroban_safeguard_pairs_error Contract-pair analyses that failed with an internal error.
# TYPE soroban_safeguard_pairs_error counter
soroban_safeguard_pairs_error_total 0
# HELP soroban_safeguard_findings Finding counts by severity, axis, and outcome. Labels are drawn from closed enumerations; no user data appears as a label value.
# TYPE soroban_safeguard_findings counter
soroban_safeguard_findings_total{severity="critical",axis="storage_layout",outcome="active"} 2
soroban_safeguard_findings_total{severity="warning",axis="call_abi",outcome="suppressed"} 1
# HELP soroban_safeguard_cache_lookups Metadata-cache lookups by result.
# TYPE soroban_safeguard_cache_lookups counter
soroban_safeguard_cache_lookups_total{result="hit"} 0
soroban_safeguard_cache_lookups_total{result="miss"} 0
soroban_safeguard_cache_lookups_total{result="invalidated"} 0
# HELP soroban_safeguard_rpc_attempts RPC baseline-fetch attempts by result.
# TYPE soroban_safeguard_rpc_attempts counter
soroban_safeguard_rpc_attempts_total{result="success"} 0
soroban_safeguard_rpc_attempts_total{result="transport_error"} 0
soroban_safeguard_rpc_attempts_total{result="protocol_error"} 0
soroban_safeguard_rpc_attempts_total{result="timeout"} 0
soroban_safeguard_rpc_attempts_total{result="hash_mismatch"} 0
# HELP soroban_safeguard_run_duration_seconds Total wall-clock time of the analysis run.
# TYPE soroban_safeguard_run_duration_seconds counter
soroban_safeguard_run_duration_seconds_total 0.123456789
# EOF
```
