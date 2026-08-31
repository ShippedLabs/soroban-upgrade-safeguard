# Protocol Version Policy & Directional Severity

## Overview

Stellar Soroban contracts encode environment metadata (including protocol interface version and pre-release numbers) into the `contractenvmetav0` custom WASM section.

Because deploying a smart contract compiled against an older protocol interface than the active live target poses severe compatibility risks on-chain (such as unhandled host functions or missing system capabilities), `soroban-upgrade-safeguard` distinguishes directional movement (downgrades vs. upgrades) when comparing environment metadata between contract builds.

---

## Severity & Directional Rules

| Condition | Severity | Target | Gate Impact | Finding Description |
| :--- | :--- | :--- | :--- | :--- |
| **Protocol Version Downgrade** (`old > new`) | `Critical` | `protocol_version` | **Fails default run** | `"Soroban protocol version downgraded from X to Y (pre-release A → B)."` |
| **Protocol Version Upgrade** (`old < new`) | `Warning` | `protocol_version` | Passes default (fails `--strict`) | `"Soroban protocol version upgraded from X to Y (pre-release A → B)."` |
| **Pre-release Downgrade** (`old == new`, `old_pre > new_pre`) | `Warning` | `pre_release_version` | Passes default (fails `--strict`) | `"Soroban protocol pre-release version downgraded from A to B (protocol version X unchanged)."` |
| **Pre-release Upgrade** (`old == new`, `old_pre < new_pre`) | `Info` | `pre_release_version` | Informational | `"Soroban protocol pre-release version upgraded from A to B (protocol version X unchanged)."` |
| **Metadata Disappeared** (`Some` → `None`) | `Warning` | `env_metadata` | Passes default (fails `--strict`) | `"Contract environment metadata was removed (was: ...)."` |
| **Metadata Appeared** (`None` → `Some`) | `Info` | `env_metadata` | Informational | `"Contract environment metadata appeared (...)."` |

---

## Precise Target Suppressions

Each environment finding is assigned a target name (`protocol_version`, `pre_release_version`, or `env_metadata`). This allows targeted suppression rules in `.safeguard.toml` without silencing the entire `Environment` category:

```toml
# Suppress a reviewed protocol version upgrade
[[suppress]]
category = "Environment"
target   = "protocol_version"
reason   = "Planned upgrade to Soroban Protocol 22."
```
