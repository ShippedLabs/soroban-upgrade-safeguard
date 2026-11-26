# Choosing an Input Source

Soroban Upgrade Safeguard can load contract builds from five different input sources: local files, stdin, RPC contract IDs, HTTPS URLs, and OCI registries. Each has different trade-offs around convenience, auditability, and security. This guide helps you choose the right one for your workflow.

## Quick comparison

| Source | Use when | Pros | Cons |
|--------|----------|------|------|
| **Local file** | You have the WASM on disk | Simple, no network required | Requires manual build management |
| **stdin** | Build is piped from another command | Integrates with shell pipelines | Single-use only, no caching |
| **RPC contract ID** | Comparing against deployed code | Fetches live on-chain baseline | Requires network access, needs endpoint trust |
| **HTTPS URL** | Build is in object storage or CDN | Immutable artifact with built-in verification | Requires public or authenticated URL |
| **OCI registry** | Using container-based workflows | Standard artifact distribution, versioning | Requires registry setup |

## Local file

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

**When to use:**
- Local development and testing
- CI pipelines with build artifacts in the workspace
- When you need reproducible comparisons without network dependencies

**Considerations:**
- You control which bytes are compared — no network trust required
- Supports symlinks (followed by default, rejected with `--no-symlinks`)
- Works offline
- No built-in version management — you track which file is which

**See also:** [Symlinked inputs](../README.md#symlinked-inputs) for symlink behavior and `--redact-paths` for publishing reports.

## stdin

```bash
cat ./wasm/v2.wasm | soroban-upgrade-safeguard ./wasm/v1.wasm -
```

**When to use:**
- Integrating with build tools that output to stdout
- Shell pipelines where one artifact is streamed
- Ephemeral checks where caching isn't needed

**Considerations:**
- Only one input can be `-` per run (stdin can't be consumed twice)
- No caching — the bytes are read once and discarded
- Useful for one-off checks in scripts

**See also:** [Usage](../README.md#usage) for stdin examples.

## RPC contract ID

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://soroban-testnet.stellar.org \
  ./wasm/v2.wasm
```

**When to use:**
- Validating an upgrade candidate against what's currently deployed
- Pre-upgrade checks in staging or production
- When you need to verify compatibility with live on-chain code

**Considerations:**
- Fetches the WASM for a deployed contract directly from the network
- Requires trusting the RPC endpoint (see security checklist below)
- Hash-verified by default (compares fetched bytes against contract instance hash)
- Use `--expected-wasm-hash` for an additional independent verification
- Supports private endpoints with `--rpc-header` for authentication
- Use `--allow-http-local` for local test validators without TLS

**Security:**
- Only `https://` endpoints are allowed by default (except localhost with `--allow-http-local`)
- Never pass credentials on the command line — use `--rpc-header NAME=ENV_VAR` to read from environment
- See [RPC Security Checklist](rpc-security-checklist.md) for operational guidance

**See also:**
- [Comparing against a deployed contract](../README.md#comparing-against-a-deployed-contract-rpc-baseline)
- [Zero-Trust RPC Baseline Retrieval](documentation.md#zero-trust-rpc-baseline-retrieval)
- [RPC Security Checklist](rpc-security-checklist.md)

## HTTPS URL

```bash
soroban-upgrade-safeguard \
  ./wasm/v1.wasm \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."
```

**When to use:**
- Builds are published to object storage (S3, GCS, Azure Blob, etc.)
- Release pipelines with immutable artifacts
- When you want content-addressed verification without manual downloads

**Considerations:**
- **Requires** a `#sha256=<hex>` digest in the URL — no unverified fetches allowed
- Downloads are verified before analysis (mismatch fails immediately)
- Content-addressed caching by default (`--no-remote-cache` to disable)
- Supports size limits, timeouts, and redirect control
- Authorization headers never leak to redirect targets

**Size and timeout limits:**
- `--remote-max-bytes` (default: 64 MiB)
- `--remote-timeout-secs` (default: 30 seconds) — bounds every single
  request (including each redirect hop). **`--remote-timeout-secs 0` is
  a defined failure, not an unbounded wait**: the timeout is measured
  from when the request starts, so a zero-second budget is already
  exhausted before the connection — let alone a response — can complete.
  Every request fails immediately with a timeout error (reported as a
  transport error naming the failed URL) rather than hanging or
  silently succeeding. There's no "0 means unlimited" special case; use
  a large explicit value (e.g. `--remote-timeout-secs 3600`) if you
  actually want a long budget.
- `--remote-max-redirects` (default: 5)

**See also:**
- [Fetching inputs over HTTPS](../README.md#fetching-inputs-over-https)
- [Remote HTTPS Inputs](remote-https-inputs.md)

## OCI registry

```bash
soroban-upgrade-safeguard \
  oci://ghcr.io/myorg/contract:v1 \
  oci://ghcr.io/myorg/contract:v2
```

**When to use:**
- Your release process uses container registries
- You want standard artifact versioning and tagging
- Integrating with existing OCI-based workflows (Docker, GitHub Packages, etc.)

**Considerations:**
- Uses standard OCI distribution protocols
- Supports authentication via registry credentials
- Built-in versioning with tags and digests
- Can reference by tag (`oci://registry/image:v1`) or digest (`oci://registry/image@sha256:...`)

**Size and timeout limits:**
- `--oci-max-bytes` (default: see `--help`)
- `--oci-timeout-secs` (default: see `--help`) — bounds every single
  registry request (manifest fetch, blob fetch, each retry).
  **`--oci-timeout-secs 0` is a defined failure, not an unbounded wait**:
  the timeout is measured from when the request starts, so a zero-second
  budget is already exhausted before the connection — let alone a
  response — can complete. Every `oci://` request fails immediately with
  a timeout error (reported as a transport error naming the failed URL)
  rather than hanging or silently succeeding. There's no "0 means
  unlimited" special case; use a large explicit value (e.g. `--oci-timeout-secs 3600`)
  if you actually want a long budget.

**See also:** Check `soroban-upgrade-safeguard --help` for OCI-specific flags and authentication options.

## Choosing between sources

**Use local files when:**
- Working locally or in a CI workspace with build artifacts already present
- You need offline operation
- Full control over which bytes are compared matters most

**Use stdin when:**
- Integrating with build pipelines that stream output
- One-off scripted checks where caching isn't needed

**Use RPC contract ID when:**
- The baseline is what's currently deployed on-chain
- You're performing a pre-upgrade validation check
- You have a trusted RPC endpoint available

**Use HTTPS URLs when:**
- Artifacts are published to object storage or a CDN
- You want immutable, content-addressed builds in a release pipeline
- Multiple systems need access to the same verified artifact

**Use OCI registries when:**
- Your infrastructure already uses container registries
- You want standard versioning and distribution
- Integration with existing OCI tooling is important

## Mixing sources

You can mix input sources in a single comparison. For example, compare a local candidate build against a deployed baseline:

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://soroban-testnet.stellar.org \
  ./wasm/candidate.wasm
```

Or compare two remote artifacts:

```bash
soroban-upgrade-safeguard \
  "https://releases.example.com/v1/contract.wasm#sha256=aabbccdd..." \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."
```

Each input is loaded independently with its own verification rules. The comparison runs after both sides are verified and decoded.

## Related documentation

- [Usage](../README.md#usage) — command-line examples for each source
- [RPC Security Checklist](rpc-security-checklist.md) — operational guidance for RPC endpoints
- [Remote HTTPS Inputs](remote-https-inputs.md) — digest format and caching details
- [Batch Manifests](batch_manifests.md) — using multiple input sources in a single manifest
