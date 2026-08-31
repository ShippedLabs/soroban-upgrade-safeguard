//! Lightweight check that `docs/compatibility-table.md` is up to date.
//!
//! The test reads the table file and asserts that the current
//! `CARGO_PKG_VERSION`, the `stellar-xdr` dependency version resolved in
//! `Cargo.lock`, and the current `REPORT_SCHEMA_VERSION` all appear as
//! literal strings in the table.  A missing entry means the table was not
//! updated alongside a version bump — this test is the tripwire.
//!
//! The check is intentionally narrow: it does not parse the Markdown structure
//! or validate every cell.  It only asks "is the current version string present
//! somewhere in the file?", which is enough to catch the common case of bumping
//! a version without updating the docs.

use std::fs;
use std::path::Path;

/// Path to the compatibility table, relative to the crate manifest root.
const TABLE_PATH: &str = "docs/compatibility-table.md";

/// Read the table file.  Returns `None` if the file cannot be opened so the
/// test can skip gracefully in environments where the docs directory is not
/// present (e.g. minimal docker builds that copy only the `src/` tree).
fn read_table() -> Option<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir).join(TABLE_PATH);
    fs::read_to_string(&path).ok()
}

/// Extract the resolved version of a package from `Cargo.lock`.
///
/// Searches for the first `[[package]]` block whose `name` matches and
/// returns the associated `version` value.  Returns `None` if the lock
/// file is missing or the package is not found.
fn cargo_lock_version(package_name: &str) -> Option<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lock_path = Path::new(manifest_dir).join("Cargo.lock");
    let lock = fs::read_to_string(lock_path).ok()?;

    let mut in_block = false;
    let mut found_name = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_block = true;
            found_name = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if line.starts_with("name = ") {
            let name = line.trim_start_matches("name = ").trim_matches('"');
            found_name = name == package_name;
        }
        if found_name && line.starts_with("version = ") {
            return Some(
                line.trim_start_matches("version = ")
                    .trim_matches('"')
                    .to_string(),
            );
        }
        // A blank line ends the current block.
        if line.is_empty() {
            in_block = false;
        }
    }
    None
}

/// Read `REPORT_SCHEMA_VERSION` from `src/render.rs` by scanning for the
/// `pub const REPORT_SCHEMA_VERSION: u32 = <N>;` line.
///
/// This avoids importing the symbol (which requires the `unstable` feature)
/// while still reading the authoritative source rather than duplicating the
/// value here.
fn report_schema_version_from_source() -> Option<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let render_path = Path::new(manifest_dir).join("src").join("render.rs");
    let source = fs::read_to_string(render_path).ok()?;
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("pub const REPORT_SCHEMA_VERSION: u32 =") {
            // Extract the numeric literal between '=' and ';'
            let after_eq = line.splitn(2, '=').nth(1)?;
            let value = after_eq.trim().trim_end_matches(';').trim();
            return Some(value.to_string());
        }
    }
    None
}

#[test]
fn table_contains_current_tool_version() {
    let table = match read_table() {
        Some(t) => t,
        None => {
            println!(
                "⚠️  {} not found — skipping compatibility table check.",
                TABLE_PATH
            );
            return;
        }
    };

    let tool_version = env!("CARGO_PKG_VERSION");
    assert!(
        table.contains(tool_version),
        "docs/compatibility-table.md does not contain the current tool version '{}'.\n\
         Update the table to include a row for this release before merging.",
        tool_version,
    );
}

#[test]
fn table_contains_current_stellar_xdr_version() {
    let table = match read_table() {
        Some(t) => t,
        None => {
            println!(
                "⚠️  {} not found — skipping compatibility table check.",
                TABLE_PATH
            );
            return;
        }
    };

    let xdr_version = match cargo_lock_version("stellar-xdr") {
        Some(v) => v,
        None => {
            println!(
                "⚠️  Could not determine stellar-xdr version from Cargo.lock — \
                 skipping that portion of the compatibility table check."
            );
            return;
        }
    };

    assert!(
        table.contains(&xdr_version),
        "docs/compatibility-table.md does not contain the resolved stellar-xdr \
         version '{}'.\n\
         Update the table to record the current stellar-xdr version before merging.",
        xdr_version,
    );
}

#[test]
fn table_contains_current_report_schema_version() {
    let table = match read_table() {
        Some(t) => t,
        None => {
            println!(
                "⚠️  {} not found — skipping compatibility table check.",
                TABLE_PATH
            );
            return;
        }
    };

    let schema_version = match report_schema_version_from_source() {
        Some(v) => v,
        None => {
            println!(
                "⚠️  Could not determine REPORT_SCHEMA_VERSION from src/render.rs — \
                 skipping that portion of the compatibility table check."
            );
            return;
        }
    };

    assert!(
        table.contains(&schema_version),
        "docs/compatibility-table.md does not contain the current report schema \
         version '{}'.\n\
         Update the table to record REPORT_SCHEMA_VERSION = {} before merging.",
        schema_version,
        schema_version,
    );
}
