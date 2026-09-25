# Remote HTTPS Inputs

Anywhere the CLI accepts a local path — the positional WASM arguments,
`--old-storage-schema` / `--new-storage-schema`, manifest `pairs.old` /
`pairs.new` fields, and spec inputs to `attest` / `verify-attestation` —
it also accepts an `https://` URL. This lets a release pipeline compare
immutable build artifacts published to object storage without a separate
download-and-verify step.

## Supplying the digest

There is no separate `--digest` flag. The expected digest is embedded
directly in the URL as a `#sha256=<hex>` fragment:

```text
https://cdn.example.com/releases/v2/contract.wasm#sha256=3b1a2c9e4d5f60718293847566172839405162738495061728394051627384950
```

The fragment is **mandatory**. A bare `https://` URL with no `#sha256=`
is rejected before any network request is made:

```
Error: remote input 'https://cdn.example.com/...' is missing the required
'#sha256=<hex>' digest fragment; every remote artifact must pin an expected
digest
```

An unverified remote fetch has no integrity guarantee, so the tool refuses
to proceed without one.

### Digest requirements

- **Algorithm:** SHA-256 only. Any other prefix (e.g. `#md5=`, `#sha512=`)
  is rejected with "unsupported digest fragment; expected `#sha256=<hex>`".
- **Format:** exactly 64 hexadecimal characters, upper- or lower-case.
  A value that is the wrong length or contains non-hex characters is
  rejected before connecting.
- The fragment is a client-side-only part of the URL — it is stripped
  before the request is sent and never reaches the server.

### Quick examples

```bash
# Single comparison: new side is a published artifact.
soroban-upgrade-safeguard old.wasm \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."

# Both sides from object storage.
soroban-upgrade-safeguard \
  "https://releases.example.com/v1/contract.wasm#sha256=aabbccdd..." \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."

# Storage-schema spec from a URL (same syntax).
soroban-upgrade-safeguard old.wasm new.wasm \
  --old-storage-schema "https://cdn.example.com/v1/schema.json#sha256=11223344..."

# In a batch manifest, pairs.old / pairs.new accept the same syntax.
soroban-upgrade-safeguard --manifest pairs.toml
```

A manifest entry looks like:

```toml
[[pairs]]
old  = "https://releases.example.com/v1/contract.wasm#sha256=aabbccdd..."
new  = "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."
name = "my-contract"
```

## How verification works

1. The URL and digest are parsed and validated locally, before any network
   connection is attempted.
2. If caching is enabled (the default), the cache is checked first. A hit
   skips the download entirely — re-hashing the cached bytes confirms the
   on-disk content still matches the key before returning it. A mismatch
   is silently treated as a miss, not an error.
3. On a cache miss the artifact is downloaded. The response body is read
   through a hard byte cap (see [Limits](#remote-fetch-limits) below).
4. The SHA-256 of every downloaded byte is computed locally. This is then
   compared against the expected digest from the URL fragment,
   case-insensitively.
5. **On a mismatch the bytes are discarded and the run fails immediately:**

   ```
   Error: integrity failure: digest mismatch for 'https://cdn.example.com/v2/contract.wasm':
   expected sha256:3b1a2c9e... but downloaded content hashed to sha256:deadbeef...
   ```

   No analysis runs. The mismatched bytes are never returned to any caller.

6. On a match the verified bytes are written to the content-addressed cache
   (unless `--no-remote-cache` is set), then passed to the normal WASM or
   spec loader for structural validation.

After a successful fetch a progress line is printed:

```
🌐 Remote input: https://cdn.example.com/v2/contract.wasm
   (sha256:3b1a2c9e..., cache miss, application/wasm)
```

The final (post-redirect) URL, digest, cache status (`hit`, `miss`, or
`bypassed`), and `Content-Type` are all recorded in the run's provenance
so a CI log identifies exactly which bytes were analyzed.

## Remote fetch limits

Four CLI flags control the fetch policy. Their defaults are conservative
enough to cover any real Soroban contract artifact while still bounding
memory and time use:

| Flag | Default | What it caps |
|------|---------|--------------|
| `--remote-max-bytes` | 64 MiB | Maximum response body size, enforced by capping the byte stream rather than trusting `Content-Length` |
| `--remote-timeout-secs` | 30 s | Total per-request wall time |
| `--remote-max-redirects` | 5 | Number of redirect hops before the fetch is aborted |
| `--remote-cache-dir` | OS temp dir | Directory for the content-addressed cache (see below) |

All four can be tightened for pipelines that need stricter bounds, or
loosened if a legitimate artifact exceeds the defaults.

**Transport hardening that cannot be overridden from the CLI:**

- Every redirect hop must be `https://` — a redirect to plain `http://`
  is refused, not followed.
- `Authorization` and `Cookie` headers are never forwarded to a redirected
  request, including a same-origin one.

## Caching

Every verified download is cached by its SHA-256 digest. Because the digest
is part of the reference, a cached entry is never stale — the reference
itself changes when the artifact changes.

**Cache location**, resolved in this order:
1. `--remote-cache-dir <DIR>` (CLI flag)
2. `SOROBAN_SAFEGUARD_REMOTE_CACHE` environment variable
3. `<OS_TEMP_DIR>/soroban-upgrade-safeguard/remote-cache` (default)

**Cache bypass and clearing:**

```bash
# Skip reading and writing the cache for one run (download anyway).
soroban-upgrade-safeguard --no-remote-cache old.wasm "https://...#sha256=..."

# Delete the entire cache directory and exit.
soroban-upgrade-safeguard --clear-remote-cache
```

`--no-remote-cache` does not delete anything already cached; it only
bypasses the cache for the current run, reporting `bypassed` in provenance
instead of `hit` or `miss`.

## Error reference

| Error message | Cause | Fix |
|---------------|-------|-----|
| `missing the required '#sha256=<hex>' digest fragment` | URL has no `#` | Append `#sha256=<64-hex-char-digest>` to the URL |
| `unsupported digest fragment '#…'; expected '#sha256=<hex>'` | Fragment uses a non-SHA-256 prefix | Replace with `#sha256=` |
| `invalid sha256 digest (expected 64 hex characters, got '…')` | Digest is wrong length or contains non-hex characters | Verify the digest string |
| `response body exceeded the maximum download size of … bytes` | Artifact is larger than `--remote-max-bytes` | Raise `--remote-max-bytes` if the artifact is legitimately that large |
| `digest mismatch for '…': expected sha256:… but downloaded content hashed to sha256:…` | Downloaded bytes do not match the pinned digest | Check that the URL still points at the same artifact; re-derive the digest with `sha256sum` if needed |
| `unexpected HTTP status <N>` | Server returned a non-2xx response | Check the URL is correct and the object is publicly accessible |
| `transport error: …` | Network failure, TLS error, or redirect policy violation | Check connectivity; ensure no redirect goes to `http://` |

## See also

- [Loader Troubleshooting](loader-troubleshooting.md) — WASM validation
  errors that can appear after a successful fetch
- [RPC Security Checklist](rpc-security-checklist.md) — security guidance
  for RPC-fetched baselines, which uses a different trust model
- [Batch Manifests](batch_manifests.md) — using `https://` references
  inside manifest `[[pairs]]` entries
