# RPC Security Checklist

A concise, operational checklist for running Soroban Upgrade Safeguard against
a live RPC endpoint (`--contract-id` / `--rpc-url`). It is organized around
one distinction: what the tool **guarantees** on every RPC run, and what
remains the **operator's responsibility** to configure or assume.

For the full mechanics behind the guarantees below, see
[Zero-Trust RPC Baseline Retrieval](documentation.md#zero-trust-rpc-baseline-retrieval).
For the authenticated-endpoint flag reference, see
[Authenticated RPC endpoints](documentation.md#authenticated-rpc-endpoints).

## What the tool guarantees

These hold on every RPC fetch, unconditionally, and require no flags:

- **Bytecode integrity.** The fetched WASM's SHA-256 is compared against the
  hash recorded in the contract instance's `ContractExecutable::Wasm` entry
  returned in the *same* RPC response. A mismatch aborts with
  `IntegrityError[HashMismatch]` before any comparison runs.
- **Response entry matching.** Every `getLedgerEntries` entry is checked
  against the ledger key that was requested. Empty entry arrays, duplicate
  entries, and entries missing `key` or `xdr` are all rejected rather than
  trusted via an `entries[0]` shortcut.
- **HTTPS by default.** Only `https://` RPC URLs are accepted unless you
  explicitly opt out (see below).
- **No downgrade via redirects.** The HTTP client never follows redirects, so
  a compromised or misconfigured endpoint cannot silently redirect a request
  to `http://` or to a different origin.
- **Built-in contract detection.** `StellarAsset` contracts (no WASM
  bytecode) are detected upfront with a clear error instead of a confusing
  downstream failure.
- **Credential scoping.** Header-based credentials (`--rpc-header`) are never
  forwarded across a redirect, and are never written into reports or debug
  output.

None of this requires trusting the RPC endpoint's judgment — it is verified
cryptographically or structurally on every run.

## What you must still assume or configure

The guarantees above verify **internal consistency of one response** — that
the returned bytecode matches the hash the same endpoint also reported, and
that the response shape wasn't tampered with in transit. They do not prove
the endpoint is telling the truth about the chain. A fully malicious or
compromised RPC endpoint could still fabricate a self-consistent response
(matching fake bytecode to a fake instance hash). Treat the following as
things *you* are responsible for, not things the tool enforces for you.

### 1. Endpoint trust

- [ ] Point `--rpc-url` at an endpoint you trust — a Stellar-run node, a
      reputable provider, or infrastructure you operate yourself. The
      zero-trust pipeline defends against tampering and malformed responses;
      it does not substitute for choosing a trustworthy operator.
- [ ] For anything gating a production deploy, prefer an endpoint you
      control or that comes from a well known provider over an arbitrary
      third-party URL pasted into a one-off command.
- [ ] Run `soroban-upgrade-safeguard preflight --rpc-url <URL>` before
      wiring a new endpoint into CI. It validates transport and JSON-RPC
      protocol shape without fetching any contract code, so you can smoke
      test connectivity and auth without pulling bytecode over a link you
      haven't vetted yet. A passing preflight confirms connectivity only —
      it does not certify a specific contract or network.

### 2. HTTPS and the local-development escape hatch

- [ ] Leave the default (`https://`-only) in place for anything that isn't a
      local node.
- [ ] `--allow-http-local` permits `http://` **only** to `localhost` /
      `127.0.0.1`; remote `http://` URLs are rejected even with the flag
      set. Never pass it when pointing at a remote host.
- [ ] Treat `--allow-http-local` as a local-dev flag that should not appear
      in a CI or production invocation.

### 3. Expected-hash pinning

- [ ] For CI/CD gates that already know the deployment they're validating
      against, pass `--expected-wasm-hash <HEX>`. This adds a second,
      operator-supplied check on top of the automatic instance-hash
      verification, so a run fails immediately if the on-chain hash ever
      drifts from what the pipeline expects — independent of whether the
      RPC response itself was internally consistent.
- [ ] Source the expected hash from a trusted record (a release artifact, a
      signed deployment manifest, or the interface lockfile flow), not from
      the same RPC call you're validating.

### 4. Credentials

- [ ] Never put a token or API key directly on the command line, in
      `.safeguard.toml`, or in a manifest file. Use
      `--rpc-header NAME=ENV_VAR` and export the secret as an environment
      variable at run time.
- [ ] In CI, source the secret from the runner's secret store into the
      environment for that step only — not as a literal workflow argument
      that ends up in logs.
- [ ] Rotate provider tokens on a normal credential-rotation schedule; the
      tool has no mechanism to detect a leaked or stale token on its own.
- [ ] Remember redirects are refused outright for authenticated requests, so
      a header credential can never leak to a redirected origin — but that
      protection only covers this tool's own request, not whatever else
      that token is valid for. Scope provider tokens as narrowly as the
      provider allows.

### 5. Report retention

- [ ] Reports from an RPC run carry `baseline_source: "RPC"` and
      `verified_code_hash`, plus whatever contract ID and RPC URL context
      you passed in. Header credential *values* are never serialized into a
      report, but the RPC URL itself is — redact or avoid archiving reports
      publicly if the endpoint URL is private infrastructure you don't want
      disclosed.
- [ ] Apply your normal audit/retention policy to saved JSON reports and
      DSSE attestations the same way you would any other build provenance
      record — they're durable evidence of what was verified, and are
      designed to be re-rendered later (see [`render`](documentation.md#rendering-a-saved-report))
      without needing network access again.
- [ ] If you sign reports with `attest`, the signed statement is exactly as
      trustworthy as the private key behind it — key handling and rotation
      guidance lives in the [attestation guide](attestations.md).

## Quick reference

| Concern            | Guarantee (automatic)                              | Operator action                                             |
| ------------------- | --------------------------------------------------- | ------------------------------------------------------------- |
| Tampered bytecode   | SHA-256 checked against instance entry              | —                                                              |
| Malformed response  | Key matching, duplicate/empty rejection             | —                                                              |
| Transport downgrade | HTTPS enforced, redirects disabled                  | Don't pass `--allow-http-local` for remote hosts               |
| Malicious endpoint  | *(not covered — see above)*                          | Choose a trusted `--rpc-url`; run `preflight` before wiring in |
| Known-good hash     | *(opt-in)*                                           | Pass `--expected-wasm-hash <HEX>` in CI                        |
| Credential exposure | Never logged/serialized; stripped from redirects    | Use `--rpc-header NAME=ENV_VAR`; scope and rotate tokens       |
| Report handling     | Header secrets excluded from output                 | Apply retention policy; redact private endpoint URLs           |
