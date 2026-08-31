# Multi-Axis Compatibility Classification

This document details the multi-dimensional compatibility classification framework used by `soroban-upgrade-safeguard`.

Unlike simple severity scales that collapse all findings onto a single pass/fail scale, the tool evaluates compatibility across four distinct named compatibility axes. This allows teams to gate deployments precisely on the safety criteria they care about, while ignoring or warning on issues that only affect unrelated departments (such as off-chain indexers or client codebases).

---

## 1. The Compatibility Axes

### 1.1 Storage Layout (`storage_layout`)
- **Impact**: On-Chain State / Ledger Persistence.
- **Description**: Verifies that any state written to contract storage (instance, persistent, or temporary storage) by the old code can be successfully parsed and decoded by the upgraded contract code.
- **Breaking Changes**:
  - Reordering fields in a struct.
  - Deleting fields in a struct.
  - Adding non-optional fields to a struct (without default initializers).
  - Changing type definitions of embedded UDTs.
- **Consequences**: If violated, upgrading will cause state corruption, deserialization failures during execution, and runtime panics.

### 1.2 Call ABI (`call_abi`)
- **Impact**: On-Chain & Cross-Contract Calls / SDKs.
- **Description**: Verifies that external function signatures, parameter orders, and return types remain backward-compatible for callers.
- **Breaking Changes**:
  - Removing an exported contract function.
  - Reordering function parameters.
  - Changing a function parameter type or return type.
  - Modifying error enum codes returned by contract functions.
- **Consequences**: If violated, other smart contracts calling this contract on-chain will panic, and external frontend/backend SDK integrations calling these functions will encounter transaction submission failures.

### 1.3 Event & Indexer (`event_indexer`)
- **Impact**: Off-Chain Analytics / Event Listeners.
- **Description**: Verifies that the topics and payloads emitted by contract events match expected types.
- **Breaking Changes**:
  - Removing a field from an event structure.
  - Reordering fields in an event structure.
  - Modifying event structure types.
- **Consequences**: If violated, event consumers, dApp notifications, and database indexers (e.g. Mercury, Subgraphs) will fail to parse emitted events, leading to database indexing gaps.

### 1.4 Source Level (`source_level`)
- **Impact**: Client Compilation / Developer Experience.
- **Description**: Verifies that developers who compile their project against the upgraded contract interface do not experience compiler/type errors, even if the change is wire-compatible.
- **Breaking Changes**:
  - Renaming a function parameter (positional arguments are wire-compatible but break source-level references in some language bindings).
  - Modifying documentation comments.
- **Consequences**: If violated, callers might need to update parameter labels or client bindings, but their existing deployed binary will continue to execute safely.

---

## 2. Policy Configuration (`.safeguard.toml`)

By default, the tool enforces gating on `storage_layout` and `call_abi`, while treating `event_indexer` and `source_level` as warnings. This behavior can be customized by adding a `[policy]` section to your suppression config file:

```toml
[policy]
# If true, any unsuppressed finding on this axis will fail the run (non-zero exit code).
# If false, findings are reported as warnings but do not fail the run.
gate_storage_layout = true
gate_call_abi        = true
gate_event_indexer  = false
gate_source_level    = false
```

### 2.1 Gating Rules
- **Passed**: No unsuppressed findings on this axis.
- **Warning**: There are unsuppressed findings on this axis, but the axis is not gated (`gate_* = false`).
- **Failed**: There are unsuppressed findings on this axis, and the axis is gated (`gate_* = true`).

The overall safety check only fails if at least one gated axis returns a status of **Failed**.

### 2.2 Gating Override via `--strict`
The `--strict` CLI flag overrides the gating policy, forcing **all** axes to be gated. When strict mode is enabled, any unsuppressed compatibility finding on any axis will fail the run.
