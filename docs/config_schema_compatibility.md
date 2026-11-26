# Configuration & Manifest Schema Compatibility

Soroban Upgrade Safeguard publishes canonical, machine-readable [JSON Schema](http://json-schema.org/draft-07/schema#) documents (Draft-07) and editor completion catalogs covering the full configuration and batch manifest surface:
- **Safeguard Configuration**: `.safeguard.toml` and `.safeguard.json`
- **Batch Manifest**: `.manifest.toml` and `manifest.json`
- **Editor Completion & Hovers**: VS Code, Taplo (Neovim/Helix/Zed/IntelliJ), and Language Server Protocol tools.

---

## 1. Canonical Schema Artifacts & URIs

The canonical schemas are committed in the repository and hosted on GitHub:

| Schema Target | Canonical Path | Canonical Schema URI |
|---|---|---|
| **Safeguard Config** | `schemas/v1/safeguard-config.schema.json` | `https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/safeguard-config.schema.json` |
| **Batch Manifest** | `schemas/v1/batch-manifest.schema.json` | `https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/batch-manifest.schema.json` |
| **Editor Completion Catalog** | `schemas/v1/safeguard-completion.json` | `https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/safeguard-completion.json` |

---

## 2. Schema Versioning & Forward Compatibility Policy

1. **Semantic Versioning**:
   - The schemas are versioned at `v1` (`schemas/v1/`).
   - Minor backward-compatible field additions (optional fields with defaults) retain the `v1` path.
   - Breaking field modifications or structural removals increment the major schema directory (`schemas/v2/`).

2. **Unknown Field Policy (`deny_unknown_fields`)**:
   - Both configuration and batch manifests enforce strict unknown field validation at load time.
   - Any unknown, misspelled, or misplaced key triggers a schema-aware diagnostic specifying file, line, column, and field path before execution starts.
   - To support future non-breaking fields, configuration files should reference the canonical `$schema` matching their installed CLI release.

3. **Format Consistency Across TOML and JSON**:
   - Both TOML and JSON formats share identical validation rules, semantic checks, and enum definitions.
   - When using JSON, line and column diagnostics are derived directly from parser state.
   - When using TOML, span mappings pin errors to exact source locations.

---

## 3. Editor Setup & Autocompletion

### Option A: Direct `$schema` Header (Recommended)

You can associate the schema directly in your configuration file using the top-level `$schema` field:

#### TOML (`.safeguard.toml`):
```toml
"$schema" = "https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/safeguard-config.schema.json"

strict = false
explain = true
format = "text"

[limits]
max_xdr_depth = 32
```

#### JSON (`.safeguard.json`):
```json
{
  "$schema": "https://raw.githubusercontent.com/ShippedLabs/soroban-upgrade-safeguard/main/schemas/v1/safeguard-config.schema.json",
  "strict": false,
  "explain": true,
  "format": "text"
}
```

---

### Option B: VS Code Workspace Configuration

Add schema mappings to your workspace `.vscode/settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": ["*.safeguard.json", "safeguard.json"],
      "url": "./schemas/v1/safeguard-config.schema.json"
    },
    {
      "fileMatch": ["*manifest*.json"],
      "url": "./schemas/v1/batch-manifest.schema.json"
    }
  ],
  "evenBetterToml.schema.associations": {
    "(.*\\.)?safeguard\\.toml": "./schemas/v1/safeguard-config.schema.json",
    "(.*\\.)?manifest\\.toml": "./schemas/v1/batch-manifest.schema.json"
  }
}
```

---

### Option C: Taplo TOML Language Server (Neovim, Helix, Zed, IntelliJ)

Create `taplo.toml` in your repository root:

```toml
[[rule]]
include = ["**/.safeguard.toml", "**/safeguard*.toml"]
schema = "schemas/v1/safeguard-config.schema.json"

[[rule]]
include = ["**/*manifest*.toml"]
schema = "schemas/v1/batch-manifest.schema.json"
```

---

## 4. CLI Subcommand: `print-schema`

The `print-schema` subcommand emits machine-readable schemas, editor catalogs, and documentation directly from the running binary:

### 1. Print Safeguard Configuration Schema
```bash
soroban-upgrade-safeguard print-schema --config
```

### 2. Print Batch Manifest Schema
```bash
soroban-upgrade-safeguard print-schema --manifest
```

### 3. Print Report Schema (Default, for backward compatibility)
```bash
soroban-upgrade-safeguard print-schema
```

### 4. Print Editor Completion & Hover Catalog
```bash
soroban-upgrade-safeguard print-schema --config --completion
soroban-upgrade-safeguard print-schema --manifest --completion
```

### 5. Print Markdown Documentation
```bash
soroban-upgrade-safeguard print-schema --config --markdown
soroban-upgrade-safeguard print-schema --manifest --markdown
```

### 6. Single-line Output for Piping
```bash
soroban-upgrade-safeguard print-schema --config --compact | jq '.definitions'
```

---

## 5. Validating Configuration Offline

To validate any configuration file in isolation without WASM inputs:
```bash
soroban-upgrade-safeguard --validate-config .safeguard.toml
```

If validation fails, schema-aware diagnostics pinpoint the issue:
```text
Validating suppression config: .safeguard.toml
❌ .safeguard.toml:3:1: error at `strct_typo`: unknown field `strct_typo`, expected one of `format`, `strict`, `explain`, `no_color`, `max_suppressions`, ...
```
