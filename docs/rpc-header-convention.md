# RPC Header Environment-Variable Convention

When an RPC endpoint requires authentication — an API key, a bearer token,
or any other credential sent as an HTTP header — supply it with
`--rpc-header NAME=ENV_VAR`. The tool reads the secret from the named
environment variable at request time and never from the command line itself.

## Why the secret lives in an environment variable

Command-line arguments are visible in process listings (`ps aux`), CI log
output, and shell history. A token passed literally as `--rpc-header
Authorization=Bearer mysecrettoken` would appear in all three. The
`NAME=ENV_VAR` convention keeps the secret out of every one of those
surfaces:

- The command line only carries the variable **name** (`SOROBAN_RPC_TOKEN`),
  not the value.
- The secret is resolved from the environment a single time, immediately
  before the HTTP request is sent, and exists in memory only for the
  duration of that call.
- `--show-config` and all debug output print the env-var name and the
  literal string `<redacted>` — the value is never resolved just to display
  configuration.
- Reports and DSSE attestations contain no header information whatsoever.

## Basic usage

```bash
# Export the secret in the shell (or let CI inject it).
export SOROBAN_RPC_TOKEN="your-api-key-here"

soroban-upgrade-safeguard \
  --contract-id CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 \
  --rpc-url https://soroban-testnet.stellar.org \
  --rpc-header Authorization=SOROBAN_RPC_TOKEN \
  new.wasm
```

The flag value is always `HEADER_NAME=ENV_VAR_NAME`:

- `Authorization` — the HTTP header sent with every RPC request
- `SOROBAN_RPC_TOKEN` — the environment variable whose value becomes the
  header's value

## Multiple headers

Repeat `--rpc-header` for each additional header a provider requires:

```bash
export SOROBAN_RPC_TOKEN="..."
export SOROBAN_RPC_PROJECT="my-project-id"

soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://rpc.provider.example \
  --rpc-header Authorization=SOROBAN_RPC_TOKEN \
  --rpc-header X-Project-Id=SOROBAN_RPC_PROJECT \
  new.wasm
```

Duplicate header names (case-insensitive) are rejected as a configuration
error before any request is attempted.

## In CI

Store the secret in the runner's secret store and inject it as an
environment variable for the step that runs the tool. Never put a literal
value in a workflow argument, a step name, or an `echo` command — those all
appear in logs.

**GitHub Actions example:**

```yaml
- name: Check upgrade safety
  env:
    SOROBAN_RPC_TOKEN: ${{ secrets.SOROBAN_RPC_TOKEN }}
  run: |
    soroban-upgrade-safeguard \
      --contract-id $CONTRACT_ID \
      --rpc-url https://soroban-testnet.stellar.org \
      --rpc-header Authorization=SOROBAN_RPC_TOKEN \
      new.wasm
```

The secret is available to the step via the environment but is masked from
the log by GitHub's secret store. The command line logged by the runner
shows `Authorization=SOROBAN_RPC_TOKEN`, not the token value.

## Header name validation

Header names are validated against the HTTP specification before any
request is made. A name is rejected if it:

- is empty
- contains ASCII control characters (bytes ≤ `0x20`)
- contains non-ASCII bytes (bytes ≥ `0x7F`)
- contains a colon (`:`)

These are the characters that would corrupt an HTTP/1.1 header line. The
check runs at flag-parse time, so a misconfigured header name fails
immediately with a clear error rather than at the point of a network
request.

## When and how the value is resolved

The value is read from the environment exactly once, immediately before
the RPC request is sent. This means:

- If the environment variable is not set when the tool starts, no error is
  raised yet — the error only fires when the tool is about to make an RPC
  call.
- In `--show-config` mode, where no RPC call is made, secret values are
  never looked up at all. The output reports the env-var name and
  `<redacted>` as the value.

## Redirect policy for authenticated requests

RPC requests are sent with redirects **disabled entirely**. A provider
endpoint that returns a redirect causes an immediate error rather than a
followed redirect. This is intentional: `ureq`'s built-in redirect
handling strips only the standard `Authorization` header; a provider-
specific `X-API-Key` or `X-Token` header would otherwise be forwarded to
whatever the redirect points at. Disabling redirects means no credential
can ever reach an unintended origin, regardless of header name.

## Error reference

| Error | Cause | Fix |
|-------|-------|-----|
| `Invalid --rpc-header '…'; expected NAME=ENV_VAR` | Value does not contain `=` | Use `HEADER_NAME=ENV_VAR_NAME` format |
| `invalid header name '…'` | Header name contains control chars, non-ASCII, or `:` | Use a plain ASCII header name with no special characters |
| `secret environment variable name cannot be empty` | Nothing after the `=` | Provide the environment variable name: `Authorization=MY_TOKEN_VAR` |
| `duplicate RPC header '…'` | Same header name given twice (case-insensitive) | Each header name may appear at most once |
| `required RPC secret environment variable '…' is not set` | The named env var is absent at request time | Export the variable before invoking the tool |
| `required RPC secret environment variable '…' is empty` | The named env var exists but has an empty value | Set the variable to a non-empty secret value |

## See also

- [RPC Security Checklist](rpc-security-checklist.md) — full operational
  guidance for running against a live RPC endpoint, including endpoint
  trust, HTTPS enforcement, expected-hash pinning, and report retention
- [Documentation: Authenticated RPC endpoints](documentation.md#authenticated-rpc-endpoints) —
  the quick-start summary in the main reference
