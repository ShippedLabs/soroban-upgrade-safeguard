# Soroban Upgrade Safeguard: Unstable & Programmatic API Integration Guide

This guide describes the library API boundaries, stable vs. unstable feature gates, and integration patterns for building automated tools on top of `soroban-upgrade-safeguard`.

## API Stability Policy

`soroban-upgrade-safeguard` defines two distinct programmatic surfaces:
1. **Stable Public API**: Exposed at the crate root. Guaranteed stable across minor and patch releases. Recommended for CI builders, custom CLI wrappers, and production audit pipelines.
2. **Unstable/Internal API**: Exposed under the `unstable` feature flag. Includes underlying spec parsers, diff builders, and raw representation types. Subject to change without semver breaks.

---

## The Stable API

Stable integration points are simple, hermetic, and hide internal parser details.

### Core Entry Points

The crate root exposes four main structs/enums:
- [`SafetyReport`](crate::report::SafetyReport)
- [`ReportedFinding`](crate::report::ReportedFinding)
- [`Finding`](crate::diff::Finding)
- [`Severity`](crate::diff::Severity)

And two main verification functions:
- `compare_wasm_bytes(old: &[u8], new: &[u8]) -> Result<SafetyReport>`
- `compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport>`

### Simple Comparison Example

```rust
use std::path::Path;
use soroban_upgrade_safeguard::{compare_wasm_files, SafetyReport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old_wasm = Path::new("fixtures/contract_v1.wasm");
    let new_wasm = Path::new("fixtures/contract_v2.wasm");

    // Perform static upgrade comparison
    let report: SafetyReport = compare_wasm_files(old_wasm, new_wasm)?;

    // Check overall status
    if report.is_safe() {
        println!("Passed! The upgrade is backwards-compatible.");
    } else {
        println!("FAILED: Upgrade contains breaking interface changes.");
        println!("Critical issues: {}", report.critical_count());
        println!("Warnings: {}", report.warning_count());
        println!("Info items: {}", report.info_count());
    }

    Ok(())
}
```

---

## Gated Unstable Features

By default, the `unstable` feature is enabled. To consume ONLY the stable API, import the crate with `default-features = false` in your `Cargo.toml`.

### Cargo Dependency Setup

```toml
[dependencies]
# Stable API only (locks internal modules as private/pub(crate))
soroban-upgrade-safeguard = { version = "0.2.0", default-features = false }
```

### Why Use Default Features?
Enabling the default `unstable` feature allows you to explore intermediate compiler constructs, custom XDR specs, and internal AST definitions:
- Inspecting direct contract function XDR specs via `spec::ContractSpec`.
- Intercepting intermediate differences before suppressions are applied.
- Building custom output formatters using raw layout mapping.

---

## Detailed Data Models (Stable View)

Under the stable configuration, all data struct fields are private/`pub(crate)`. Use the public getters:

### Finding
```rust
impl Finding {
    pub fn severity(&self) -> &Severity;
    pub fn category(&self) -> &str;
    pub fn message(&self) -> &str;
    pub fn type_name(&self) -> Option<&str>;
    pub fn target(&self) -> Option<&str>;
    pub fn root_target(&self) -> Option<&str>;
}
```

### SafetyReport
```rust
impl SafetyReport {
    pub fn is_safe(&self) -> bool;
    pub fn critical_count(&self) -> usize;
    pub fn warning_count(&self) -> usize;
    pub fn info_count(&self) -> usize;
    pub fn suppressed_count(&self) -> usize;
    pub fn total_findings(&self) -> usize;
    pub fn findings_by_category(&self) -> &HashMap<String, Vec<ReportedFinding>>;
}
```

---

## Integration Patterns

### CI/CD Workflow Script

Here is a full integration script designed to be run in a GitHub Action or local pre-commit hook:

```rust
use std::path::Path;
use soroban_upgrade_safeguard::{compare_wasm_files, Severity};

fn run_audit() -> Result<(), &'static str> {
    let report = compare_wasm_files(
        Path::new("old.wasm"),
        Path::new("new.wasm")
    ).map_err(|_| "Failed to analyze contract files")?;

    if !report.is_safe() {
        // Iterate through categorised findings to print issues
        for (category, list) in report.findings_by_category() {
            for rf in list {
                let finding = rf.finding();
                if finding.severity() == &Severity::Critical && !rf.suppressed() {
                    eprintln!(
                        "CRITICAL [{}] on target {:?}: {}",
                        category,
                        finding.target(),
                        finding.message()
                    );
                }
            }
        }
        return Err("Compatibility check failed");
    }

    println!("All upgrade compatibility checks passed!");
    Ok(())
}
```
