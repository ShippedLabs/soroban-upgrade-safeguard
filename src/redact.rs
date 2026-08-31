//! Redaction helpers for local filesystem paths embedded in reports.
//!
//! Absolute paths are useful for audits but can leak a username, workspace
//! layout, or a private repository name. These helpers replace the
//! directory portion of a local path with a stable, non-identifying label
//! while keeping the file name — the part a reader actually needs to
//! identify which build was analyzed.
//!
//! Remote identifiers (RPC contract IDs, OCI references, HTTP(S) URLs) are
//! not filesystem paths and are left untouched here; RPC endpoints already
//! go through [`crate::rpc::redact_url`] independently.

/// Stable label substituted for a local path's directory components.
pub const REDACTED_ROOT_LABEL: &str = "<redacted>";

/// Replace a local path's directory components with [`REDACTED_ROOT_LABEL`],
/// keeping only the file name.
pub fn redact_local_path(path: &str) -> String {
    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    format!("{REDACTED_ROOT_LABEL}/{file_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_file_name_and_replaces_directory() {
        assert_eq!(
            redact_local_path("/home/raymond/secret-repo/target/contract.wasm"),
            "<redacted>/contract.wasm"
        );
    }

    #[test]
    fn windows_style_path_is_redacted_too() {
        assert_eq!(
            redact_local_path(r"C:\Users\raymond\project\contract.wasm"),
            "<redacted>/contract.wasm"
        );
    }

    #[test]
    fn bare_file_name_is_still_labeled() {
        assert_eq!(
            redact_local_path("contract.wasm"),
            "<redacted>/contract.wasm"
        );
    }
}
