# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# Pinned so the same commit builds the same image. To update, pick a newer
# tag from https://hub.docker.com/_/rust and bump it here.
FROM rust:1.100.0-slim-bookworm AS builder

# ring 0.17 compiles C code via the `cc` crate; gcc and pkg-config are required.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependency cache layer ────────────────────────────────────────────────────
# Copy manifests first. Create minimal stubs for both declared targets (lib +
# bin) so `cargo build --release` can resolve and compile all dependencies
# without any application source. This layer is only invalidated when
# Cargo.toml or Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs
RUN cargo build --release
# Remove stub root-crate artifacts so the real binary is always relinked.
RUN rm -f target/release/soroban-upgrade-safeguard \
         target/release/deps/soroban_upgrade_safeguard* \
         target/release/deps/soroban-upgrade-safeguard*

# ── Application build layer ───────────────────────────────────────────────────
# Only this layer rebuilds when src/ changes; all dependencies are already
# compiled and cached in the layer above.
COPY src/ ./src/
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Pinned to a dated snapshot. To update, pick a newer bookworm-YYYYMMDD-slim
# tag from https://hub.docker.com/_/debian and bump it here.
FROM debian:bookworm-20261123-slim AS runtime

# ca-certificates is required by rustls/ureq when using --rpc-url (HTTPS).
# Local-mode users (two WASM paths, no network) are unaffected but it is
# included so both modes work out of the box.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home --shell /bin/false appuser

COPY --from=builder /app/target/release/soroban-upgrade-safeguard /usr/local/bin/soroban-upgrade-safeguard

LABEL org.opencontainers.image.title="soroban-upgrade-safeguard" \
      org.opencontainers.image.description="Detect breaking changes in Soroban smart contract upgrades"

USER appuser

ENTRYPOINT ["soroban-upgrade-safeguard"]
