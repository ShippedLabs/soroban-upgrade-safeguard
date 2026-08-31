# Empirical Storage Validation Mode

The Empirical Storage Validation Mode complements the static structural analysis of `soroban-upgrade-safeguard` by checking actual smart contract storage data (either fetched from Stellar RPC or loaded from a local snapshot) against the new contract version's type definitions.

---

## Why Empirical Validation?

Static analysis is an over-approximation. For example, if a developer changes a struct field's type or removes a struct completely, static analysis will report a critical layout break. However, this is only a breaking change *if* there is serialized data of that struct type currently residing in the ledger's storage. If the contract has never stored any instances of that struct, the upgrade is technically safe to perform.

Empirical validation addresses this by checking actual contract data to confirm or refute structural warnings:
1. **Confirmed**: Actual stored values failed to decode under the new specification (definitely unsafe).
2. **Contradicted**: A structural change was flagged, but all sampled real data decoded successfully under the new spec (safe in practice for current data).
3. **Unconfirmed**: No matching stored data was found in the sample (status unknown).

---

## How it Works

When `--empirical` or `--empirical-file` is enabled:
1. The tool identifies all user-defined types (UDTs) that are structurally modified or removed.
2. It fetches/loads contract storage entries (`ContractDataEntry`).
3. It recursively scans the keys and values of the storage entries to find candidate sub-values that match the old specification of each modified UDT.
4. It attempts to decode and validate these candidate values against the new UDT specification.
5. If any validation fails, it generates a concrete decode error naming the entry, the type, and the exact path where serialization would fail.

---

## CLI Options

### 1. RPC/On-Chain Mode
To validate using the contract's instance storage on-chain:
```bash
soroban-upgrade-safeguard --contract-id <CONTRACT_ID> --rpc-url <RPC_URL> <NEW_WASM> --empirical
```

### 2. Offline/Snapshot Mode
For deterministic, offline validation using captured ledger entries:
```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> --empirical-file ./ledger_snapshot.json
```

---

## Input JSON Format

The `--empirical-file` JSON should be an array of base64-encoded XDR `LedgerEntry` or `ContractDataEntry` strings. For example:

```json
[
  "AAAAEAAAAAAAAAAAAAAAAAAAAHNhZmVLZXkAAAADAAAAAAAAAAAAAAAB...",
  "AAAAEAAAAAAAAAAAAAAAAAAAAHVuc2FmZUtleQAAAAMAAAAAAAAAAAAA..."
]
```

Or an object containing an `entries` array:

```json
{
  "entries": [
    { "xdr": "AAAAEAAAAAAAAAAAAAAAAAAAAHNhZmVLZXk..." },
    { "xdr": "AAAAEAAAAAAAAAAAAAAAAAAAAHVuc2FmZUtl..." }
  ]
}
```

---

## Guarantees and Limits

> [!IMPORTANT]
> ### What Empirical Validation Guarantees
> - **Sample Safety**: It guarantees that the concrete data sampled/provided *will decode successfully* after the upgrade.
> - **Zero-False-Positives for Failures**: Any reported decode failure is a concrete structural incompatibility that would cause the contract to panic on-chain during execution.

> [!WARNING]
> ### What Empirical Validation Does NOT Guarantee
> - **Stellar RPC Ledger Scan Limits**: The Stellar RPC `getLedgerEntries` protocol **does not support wildcard scanning or wildcard listing of keys**. Therefore, off-chain tooling cannot natively fetch all persistent storage entries for a contract over RPC. It can only fetch the contract's instance storage. Thus, when running in RPC mode, validation is bounded to the **instance storage** and does not cover persistent storage keys unless supplied via `--empirical-file`.
> - **Semantic/Invariant Safety**: Just because data decodes successfully does not mean the contract logic operates correctly under the new code (e.g., changes in formula bounds or function assertions).
> - **New Write Layouts**: It cannot guarantee that new data written under the new code would be compatible with old code if you ever need to rollback (downgrade).

---

## Verdict Composition Policy

- **Unsafe Verdict**: If any sampled storage entry fails validation under the new specification, the upgrade is flagged as **FAILED** and the tool exits with code `1`, regardless of whether strict mode is enabled.
- **Structural Warnings**: If structural layout changes are detected but all sampled data validates successfully, the tool still lists the structural changes in the report (marking them as `[CONTRADICTED]`), but does not fail the upgrade unless strict mode is enabled.
