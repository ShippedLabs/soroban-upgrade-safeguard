# Public API Surface Hardening & Migration Guide

Starting in version `0.2.0`, the public API surface of the `soroban-upgrade-safeguard` library has been hardened to separate internal pipeline modules from the stable, curated public API. This hardening allows the project internals to evolve without causing breaking changes for downstream consumers.

---

## Key Changes

1. **Module Visibility**: Modules like `loader`, `parser`, `mapper`, `diff`, `spec`, and `suppression` are now private by default. They can only be accessed by enabling the `unstable` Cargo feature flag.
2. **Accessors**: Direct field accesses on major public structs (`SafetyReport`, `ReportedFinding`, `Finding`, `ContractSpec`, `SuppressionConfig`, `SuppressionRule`) have been replaced with read-only getter methods.
3. **Non-Exhaustive Structs**: Major configuration and schema structs (`CompareOptions`, `ResourcePolicy`, `SuppressionConfig`, `SuppressionRule`, `StorageSchema`, `DeclaredType`) are marked `#[non_exhaustive]`, meaning they cannot be instantiated directly using struct literal syntax (`Struct { field: value }`). Instead, construct them via `Default::default()` and mutate public fields.

---

## Non-Exhaustive Structs Design Rationale

By decorating configuration structs with `#[non_exhaustive]`, we prevent external code from breaking when we add new fields in future minor releases (e.g. adding new validation options or limit boundaries). 

### How to construct non-exhaustive structures
Instead of:
```rust
// This will FAIL to compile in 0.2.0
let policy = ResourcePolicy {
    max_xdr_len: 1024,
    max_xdr_depth: 32,
    max_entries: 100,
    max_walk_depth: 128,
};
```

You must do:
```rust
// This will compile successfully and is future-proof
let mut policy = ResourcePolicy::default();
policy.max_xdr_len = 1024;
policy.max_xdr_depth = 32;
```

---

## Curated stable API Migration Examples

### 1. Running the Pipeline & Accessing Verdicts

**Before (0.1.0)**:
```rust
use std::path::Path;
use soroban_upgrade_safeguard::compare_wasm_files;

let report = compare_wasm_files(
    Path::new("old.wasm"),
    Path::new("new.wasm")
).unwrap();

// Direct field accesses (Now private)
if !report.is_safe {
    println!(
        "Safety check failed: {} critical, {} warnings",
        report.critical_count,
        report.warning_count
    );
}
```

**After (0.2.0)**:
```rust
use std::path::Path;
use soroban_upgrade_safeguard::compare_wasm_files;

let report = compare_wasm_files(
    Path::new("old.wasm"),
    Path::new("new.wasm")
).unwrap();

// Access fields using public getter methods
if !report.is_safe() {
    println!(
        "Safety check failed: {} critical, {} warnings",
        report.critical_count(),
        report.warning_count()
    );
}
```

---

### 2. Iterating Over Findings

**Before (0.1.0)**:
```rust
for (category, list) in &report.findings_by_category {
    println!("Category: {}", category);
    for reported in list {
        let finding = &reported.finding;
        println!(
            "  [{:?}] {}: {}",
            finding.severity,
            finding.target.as_deref().unwrap_or("general"),
            finding.message
        );
    }
}
```

**After (0.2.0)**:
```rust
// Iterate using categories() and findings_for_category() accessors
for category in report.categories() {
    println!("Category: {}", category);
    if let Some(list) = report.findings_for_category(category) {
        for reported in list {
            let finding = reported.finding();
            println!(
                "  [{:?}] {}: {}",
                finding.severity(),
                finding.target().unwrap_or("general"),
                finding.message()
            );
        }
    }
}
```

---

## Advanced Usage: Unstable Custom Pipeline Walking

For advanced consumers who need to run individual pipeline stages or parse metadata manually, enable the `unstable` feature gate in your `Cargo.toml`:

```toml
[dependencies]
soroban-upgrade-safeguard = { version = "0.2.0", default-features = false, features = ["unstable"] }
```

### Complete Code Tutorial for Unstable Custom Pipeline

```rust
use std::path::Path;
use soroban_upgrade_safeguard::loader::load_wasm;
use soroban_upgrade_safeguard::parser::extract_metadata;
use soroban_upgrade_safeguard::spec::ContractSpec;
use soroban_upgrade_safeguard::mapper::try_type_to_string;
use soroban_upgrade_safeguard::diff::compare;
use soroban_upgrade_safeguard::report::SafetyReport;

fn run_custom_analysis() -> Result<(), anyhow::Error> {
    // 1. Load WASM file binaries using unstable loader module
    let old_wasm = load_wasm(Path::new("old.wasm"))?;
    let new_wasm = load_wasm(Path::new("new.wasm"))?;
    
    // 2. Parse out spec and env metadata structures
    let old_meta = extract_metadata(&old_wasm.bytes)?;
    let new_meta = extract_metadata(&new_wasm.bytes)?;
    
    // 3. Assemble spec maps for functions and types
    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);
    
    // 4. Walk types using try_type_to_string
    if let Some(first_fn) = old_spec.functions.values().next() {
        for input in &first_fn.inputs {
            let signature = try_type_to_string(&input.type_, 0, 128)?;
            println!("Param '{}' has type: {}", input.name, signature);
        }
    }
    
    // 5. Compare specs structurally
    let raw_diff = compare(&old_spec, &new_spec);
    
    // 6. Wrap in safety report with custom criteria
    let report = SafetyReport::new(&raw_diff);
    println!("Upgrade safe? {}", report.is_safe());
    
    Ok(())
}
```
