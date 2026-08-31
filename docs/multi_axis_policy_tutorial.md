# Transitioning to Multi-Axis Compatibility Gating

This tutorial walks you through transitioning your CI/CD pipelines from a simple, single-severity validation model to the more flexible, multi-axis compatibility classification framework.

---

## Step 1: Analyze Your Team Roles and Owners

The first step is identifying who cares about which compatibility breaks in your organization.

| Team | Primary Interest | Relevant Compatibility Axis |
| :--- | :--- | :--- |
| **Protocol / Core Team** | Ledger state deserialization, storage footprints, node panics. | `storage_layout` |
| **Integrations / Frontend**| API function signatures, client SDKs, frontend compilation. | `call_abi` |
| **Data / Analytics Team** | Transaction event logs, dashboards, data indexing pipelines. | `event_indexer` |
| **Developer Experience** | Source-code documentation, inline comments, parameter labels. | `source_level` |

---

## Step 2: Establish the Gating Policy

By default, the tool enforces a gating policy where `storage_layout` and `call_abi` changes cause the check to fail, while event changes and source-level renames are reported as warnings.

If your team wants to start gating event schemas to prevent analytics pipelines from breaking, add this to your `.safeguard.toml`:

```toml
[policy]
gate_storage_layout = true
gate_call_abi        = true
gate_event_indexer  = true
gate_source_level    = false
```

---

## Step 3: Run Gated Checks in CI/CD

Integrate the check in your GitHub Actions workflow or deployment scripts:

```bash
# Run compatibility safeguard analysis
soroban-upgrade-safeguard --old old_contract.wasm --new new_contract.wasm --suppress .safeguard.toml
```

If the run encounters any unsuppressed findings on gated axes (e.g. a struct layout change or a call ABI signature change), the command will exit with a non-zero exit code, stopping the deployment pipeline.

If there are warnings on ungated axes (e.g. documentation changes or parameter renames), the pipeline will print the warnings but exit with code `0` (success), allowing the deployment to continue.

---

## Step 4: Handle Intentional Breaks

When a breaking change is intended (e.g., a scheduled storage migration), you must explicitly acknowledge it in `.safeguard.toml` to prevent pipeline failures:

```toml
[[suppress]]
category = "Struct Field Type Changed"
target   = "ConfigData.threshold"
reason   = "Widening threshold storage type to support finer precision in v2."
```

Once added, the finding is marked as **Suppressed**, its gated failure is bypassed, and the overall pipeline returns to green.
