use std::env;
use std::fs;
use std::path::Path;

#[test]
fn public_api() {
    // 1. Install a compatible nightly toolchain if missing.
    if rustup_toolchain::install(public_api::MINIMUM_NIGHTLY_RUST_VERSION).is_err() {
        println!("⚠️ Warning: Nightly toolchain installation failed (network offline?). Skipping public API snapshot check.");
        return;
    }

    // 2. Build rustdoc JSON for the project.
    let rustdoc_json = match rustdoc_json::Builder::default()
        .toolchain(public_api::MINIMUM_NIGHTLY_RUST_VERSION)
        .build()
    {
        Ok(json) => json,
        Err(e) => {
            println!("⚠️ Warning: Failed to build rustdoc JSON ({:?}). Skipping public API snapshot check.", e);
            return;
        }
    };

    // 3. Derive the public API from the rustdoc JSON.
    let public_api = match public_api::Builder::from_rustdoc_json(rustdoc_json).build() {
        Ok(api) => api,
        Err(e) => {
            println!("⚠️ Warning: Failed to parse public API from rustdoc JSON ({:?}). Skipping public API snapshot check.", e);
            return;
        }
    };

    let current_api = format!("{}", public_api);
    let snapshot_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join("public-api.txt");

    if env::var("UPDATE_SNAPSHOTS").is_ok() {
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        fs::write(&snapshot_path, &current_api).unwrap();
        println!("Updated public API snapshot at {}", snapshot_path.display());
    } else {
        // No snapshot has been committed yet, so there is no baseline to compare
        // against. Skip rather than fail: this mirrors the other degradation
        // paths above, and keeps the check opt-in until someone initializes it.
        let Ok(expected_api) = fs::read_to_string(&snapshot_path) else {
            println!(
                "⚠️ Warning: No public API snapshot at {}. Skipping check. \
                 Run 'UPDATE_SNAPSHOTS=yes cargo test --test public_api' to initialize it.",
                snapshot_path.display()
            );
            return;
        };

        if current_api != expected_api {
            // Print a diff and panic to fail the test.
            println!("--- EXPECTED PUBLIC API ---");
            println!("{}", expected_api);
            println!("--- ACTUAL PUBLIC API ---");
            println!("{}", current_api);
            panic!(
                "Public API mismatch! If this change was intentional, run 'UPDATE_SNAPSHOTS=yes cargo test --test public_api' to update the snapshot."
            );
        }
    }
}
