# Persistent Compatibility Lineage Ledger

## Overview

In smart contract deployments (such as Stellar Soroban contracts), upgrading a contract does not automatically erase existing ledger storage state written by previous versions. A contract accumulates a historical lineage of deployed versions, and sparse or long-lived data entries created under early versions (e.g. `v1.0.0`) may remain unread across intermediate upgrades (`v2.0.0`, `v3.0.0`) until accessed much later by a new release candidate (`v4.0.0`).

Checking compatibility only against the immediate predecessor (`v3.0.0` vs `v4.0.0`) introduces a false sense of safety if `v3.0.0` never touched data structures introduced in `v1.0.0`. If `v4.0.0` alters or removes XDR types written by `v1.0.0`, reading that old state will result in runtime decoding failures on-chain.

The **Persistent Compatibility Lineage Ledger** records each analyzed and deployed version of a contract, maintains its full historical lineage, and validates upgrade candidates against **every historical version still considered live**, not just the immediate predecessor.

---

## Architecture & Data Flow

```
+-------------------------------------------------------------------+
|                        Lineage Store                              |
|                                                                   |
|   +-----------------+   +-----------------+   +---------------+   |
|   | Version 1 (Live)|   | Version 2 (Live)|   | Version 3 ... |   |
|   | - ExtractedSpec |   | - ExtractedSpec |   |               |   |
|   +--------+--------+   +--------+--------+   +-------+-------+   |
+------------|---------------------|--------------------|-----------+
             |                     |                    |
             v                     v                    v
      +--------------+      +--------------+     +--------------+
      | Convert to   |      | Convert to   |     | Convert to   |
      | ContractSpec |      | ContractSpec |     | ContractSpec |
      +------+-------+      +------+-------+     +------+-------+
             |                     |                    |
             +------------------+  |  +-----------------+
                                |  |  |
                                v  v  v
                    +-----------------------+
                    | Structural Diff Engine| <--- Candidate (v4.0.0)
                    +-----------+-----------+
                                |
                                v
                    +-----------------------+
                    | Historical Findings   |
                    | (Attributed to v1/v2) |
                    +-----------------------+
```

---

## Ledger File Format (JSON / TOML)

The lineage ledger file is portable, machine-readable, and human-editable. It can be saved as either JSON (`.json`) or TOML (`.toml`).

### JSON Example

```json
{
  "schema_version": 1,
  "contract_id": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMWAXA26TXOBGY",
  "contract_name": "token_vault",
  "policy": {
    "max_live_versions": 5,
    "allow_retired_data": false
  },
  "records": [
    {
      "version_id": "v1.0.0",
      "order": 1,
      "created_at": "2026-01-15T10:00:00Z",
      "status": "Live",
      "wasm_hash": "a1b2c3d4...",
      "interface_hash": "e5f6a7b8...",
      "spec_json": "{...}",
      "metadata": {
        "git_commit": "7a3f89b"
      }
    }
  ]
}
```

### Key Fields

- `schema_version`: Version of the lineage store schema (currently `1`).
- `contract_id`: Optional Soroban contract ID.
- `contract_name`: Optional human-readable contract identity.
- `policy`:
  - `max_live_versions`: Maximum historical live versions to validate against (most recent $N$).
  - `retire_before_version`: Optional version tag threshold where versions ordered before it are treated as retired.
  - `allow_retired_data`: Whether retired versions should still be included in validation.
- `records`: Ordered sequence of historical version entries.
  - `version_id`: Unique version tag/commit SHA.
  - `order`: Strictly increasing sequence index (1-indexed).
  - `created_at`: ISO-8601 timestamp string.
  - `status`: `"Live"` or `"Retired"`.
  - `wasm_hash`: SHA256 hex digest of the compiled WASM binary.
  - `interface_hash`: SHA256 hex digest of the extracted contract spec.
  - `spec_json`: Full JSON representation of the contract spec for offline structural comparison.

---

## CLI Flag Reference & Environment Variables

| CLI Flag | Environment Variable | Description |
| :--- | :--- | :--- |
| `--lineage-store <PATH>` | `SAFEGUARD_LINEAGE_STORE` | Path to lineage store file (`.json` or `.toml`). |
| `--record-version <TAG>` | `SAFEGUARD_RECORD_VERSION` | Record candidate build as a new live version tag upon safe comparison. |
| `--retire-version <TAG>` | `SAFEGUARD_RETIRE_VERSION` | Mark an existing historical version as `Retired`. |
| `--max-live-versions <N>`| `SAFEGUARD_MAX_LIVE_VERSIONS`| Limit validation to the $N$ most recent live versions. |

---

## Workflow Example

### 1. Record Initial Build (`v1.0.0`)
```bash
soroban-upgrade-safeguard compare \
  --new build/v1.wasm \
  --lineage-store lineage.json \
  --record-version v1.0.0
```

### 2. Validate & Record Subsequent Build (`v2.0.0`)
```bash
soroban-upgrade-safeguard compare \
  --old build/v1.wasm \
  --new build/v2.wasm \
  --lineage-store lineage.json \
  --record-version v2.0.0
```

### 3. Validate Candidate `v3.0.0` Against Full Lineage
When comparing `v3.0.0`, the safeguard automatically reconstructs the XDR spec for all live historical versions (`v1.0.0` and `v2.0.0`) stored in `lineage.json` and reports any breaking changes targeting data types introduced by any live version.

```bash
soroban-upgrade-safeguard compare \
  --old build/v2.wasm \
  --new build/v3.wasm \
  --lineage-store lineage.json
```
