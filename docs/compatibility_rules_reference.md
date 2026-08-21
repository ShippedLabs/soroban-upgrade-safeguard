# Compatibility Rules Reference

This reference catalog details every compatibility check performed by `soroban-upgrade-safeguard` during contract upgrade analysis. It explains why each change triggers a finding, which compatibility axis it affects, and how to remediate the warning.

---

## 1. Storage Layout Changes (`storage_layout`)

These findings affect the layout of serialized persistent and instance storage. If deployed, they lead to deserialization errors when reading existing ledger entries.

### 1.1 Struct Field Removed
- **Description**: A field was deleted from a struct definition.
- **Why it breaks**: Soroban structures are serialized sequentially. Removing a field shifts the offsets of subsequent fields, causing the decoder to parse incorrect bytes into the wrong fields.
- **Remediation**: Avoid removing fields. If the field is no longer needed, deprecate it in documentation but leave it in the struct structure, or migrate the data under a new struct name.

### 1.2 Struct Field Reordered
- **Description**: The ordering of fields in a struct definition was changed.
- **Why it breaks**: Positional serialization expects fields in a strict order. Reordering fields swaps their deserialized values.
- **Remediation**: Revert the reordering to restore the original field sequence.

### 1.3 Struct Field Type Changed
- **Description**: The type of a field in a struct was modified.
- **Why it breaks**: The decoder will attempt to decode the stored bytes using the new type definition. If they are incompatible (e.g. `u32` to `u128`), decoding will fail or produce corrupt data.
- **Remediation**: Do not change field types. If a type change is necessary, define a new struct (e.g., `MyStructV2`) and handle migration in contract code.

---

## 2. Call ABI Changes (`call_abi`)

These findings affect the public interface of the contract. If deployed, calling contracts and client applications using existing SDKs will fail to compile or execute transactions.

### 2.0 Directional verdicts and Soroban value flow

Every comparison now reports two independent call conclusions:

- `old_client_to_new_contract`: an existing client encodes old values and the
  upgraded contract decodes them.
- `new_client_to_old_contract`: a newly generated client encodes new values and
  the old contract decodes them.

Arguments flow from client to provider; return values flow from provider to
client. The analyzer follows Soroban's encoded representation recursively:
positional function arguments and tuple elements retain arity and order;
`Option`, `Vec`, `Map`, and `Result` descend into their contained values;
struct fields are matched by encoded symbol keys; enum and union cases must
remain decodable for every value the producer may emit. A break includes the
exact value path, such as `function.transfer.argument[0].some.value` or
`function.quote.return[0].err`.

The existing aggregate `call_abi` axis remains available for policies and older
consumers. It fails when either directional verdict is incompatible.

### 2.1 Function Removed
- **Description**: An exported public function was deleted.
- **Why it breaks**: Deployed contracts or client SDKs that invoke this function will receive an unrecognized function identifier error.
- **Remediation**: Retain the function and return a deprecation error, or perform a coordinated release of all calling parties before removing it.

### 2.2 Function Signature Changed
- **Description**: The inputs or output type of a function changed.
- **Why it breaks**: Callers sending arguments in the old format will cause invocation parsing to fail at the host environment level.
- **Remediation**: Define a new function (e.g., `my_func_v2`) instead of modifying the existing signature.

### 2.3 Parameter Reordered
- **Description**: The sequence of arguments in a function was modified.
- **Why it breaks**: Arguments are sent positionally on the wire. Reordering them swaps the values received by the contract logic.
- **Remediation**: Revert the parameter order.

### 2.4 Host Import / Protocol Capability Changes

A WASM import that a contract did not previously need can raise the minimum
Stellar protocol version the target network must support to run it, even
when the exported spec is byte-identical. `diff::compare_host_imports`
classifies these changes against the versioned registry in
`src/capability.rs` — see [Host Imports and Protocol
Capabilities](documentation.md#host-imports-and-protocol-capabilities) for
the full explanation and [capability-registry.md](capability-registry.md)
for how the registry itself is maintained.

- **Host Import Added**: A new import resolves to a recognized capability. Warning.
- **Host Import Removed**: A previously imported recognized capability is gone. Informational.
- **Host Import Signature Changed**: The same `(module, name)` import resolves to a different parameter/result signature on each side. Critical for a recognized capability, Warning for an unrecognized one.
- **Unknown Host Import**: The import is not in the registry, so no protocol requirement is assigned. Warning — this is a visibility signal, not a guess.
- **Protocol Requirement Raised**: The highest protocol implied by the new build's recognized imports exceeds the old build's. Warning.
- **Protocol Environment Mismatch**: A build's own declared protocol version (`contractenvmetav0`) is lower than what its own recognized imports require. Critical.

---

## 3. Event & Indexer Changes (`event_indexer`)

These findings affect the topics and payload shape of events emitted by the contract. If deployed, downstream indexers and dashboard applications will fail to index transactions.

### 3.1 Event Field Removed
- **Description**: A field was removed from an event payload structure.
- **Why it breaks**: Off-chain indexers decoding transaction logs will find missing keys, causing parsing loops to fail.
- **Remediation**: Deprecate the event field but leave it in the schema, or version the event name.

### 3.2 Event Field Reordered
- **Description**: The order of fields in an event structure changed.
- **Why it breaks**: Payload fields are serialized sequentially. Reordering them scrambles the indexed properties.
- **Remediation**: Restore original order.

---

## 4. Source Level Changes (`source_level`)

These findings do not affect binary/wire execution on-chain but require developer action when compiling source code against the upgraded interface.

### 4.1 Parameter Renamed
- **Description**: A parameter of a public function was renamed.
- **Why it breaks**: Client bindings (such as TypeScript or Rust SDK generators) generate named arguments based on parameter names. Renaming a parameter breaks the client codebase compilation.
- **Remediation**: If client compilation breaks are acceptable, document the rename in release notes. Otherwise, keep the original name.

---

## 5. Best Practices for Compatibility Gating

When configuring gating policies, different environments should enforce different constraints:

### 5.1 Mainnet/Release Pipelines
In release pipelines leading directly to mainnet deployments, we recommend keeping both `storage_layout` and `call_abi` gated.
- **Storage Layout Gating**: Ensures that existing contract instances can decode their persisted storage safely without throwing runtime errors.
- **Call ABI Gating**: Prevents breaking existing client integrations and calling contracts.

### 5.2 Development Pipelines
In development or feature branch pipelines, teams might choose to disable gating on all axes:
- This allows checking in modifications to the interface freely without failing the CI pipeline.
- Suppression configurations (`.safeguard.toml`) can still be used to whitelist intentional storage breaks when performing testnet migrations.

---

## 6. Appendix: Complete Gating Templates

### 6.1 Gated Mainnet Deployment Policy
```toml
[policy]
gate_storage_layout = true
gate_call_abi        = true
gate_event_indexer  = true
gate_source_level    = false
```

### 6.2 Permissive Testing Policy
```toml
[policy]
gate_storage_layout = false
gate_call_abi        = false
gate_event_indexer  = false
gate_source_level    = false
```
