# Soroban Upgrade Safety Report

## Status: ❌ FAILED (Exported-interface breaking changes detected)

_Exported interface + environment metadata only — storage layout is NOT verified by this result._

**Scope:** Storage layout: NOT analyzed — no storage schema supplied.

### Summary Table

| Finding Severity | Count |
| :--- | :--- |
| **Critical** | 3 |
| **Warning** | 0 |
| **Info** | 1 |

**Recommended SemVer Bump**: `major`

**Baseline Source**: `Local File`

---

### Enum Case Added

- 🔵 Enum 'StatusEvent': new case 'Archived' (value 4) added.

### Enum Case Value Changed

- 🔴 Enum 'StatusEvent': case 'Paused' value changed from 2 to 3. This breaks data serialization.

### Function Signature Changed

- 🔴 Function 'initialize': parameter count changed from 1 to 2.

### Struct Field Removed

- 🔴 Struct 'ConfigData': field 'threshold' was removed. Backwards compatibility is broken.

### ⚠️ Action Required

- The new contract version modifies existing storage layouts or function interfaces.
- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.
## 📊 Build Metrics

| Metric | Old | New | Delta |
| :--- | ---: | ---: | ---: |
| **WASM size** | 876 B | 852 B | -24 B |
| **Functions** | 2 | 2 | +0 |
| **Structs** | 1 | 1 | +0 |
| **Enums** | 1 | 1 | +0 |
| **Unions** | 0 | 0 | +0 |
| **Error Enums** | 0 | 0 | +0 |


