# Signed safeguard attestations

Safeguard can bind an analysis to its inputs and verdict with a versioned
in-toto statement wrapped in a DSSE envelope. The statement is canonical JSON;
rendered text, Markdown, and JSON reports are never signed directly.

## Worked example: generate a key, attest, and verify

This walks through the whole lifecycle end to end: generate a signing key,
produce a report and sign it, then verify the attestation exactly the way a
*consumer* would — someone who received the envelope, the public key, and
the artifacts, but didn't run `attest` themselves.

### 0. Generate an Ed25519 key pair

The CLI has no key-generation subcommand — bring your own key from your
organization's key management (see
[Predicate and security guidance](#predicate-and-security-guidance) below
for how to handle it once you have one), or generate one locally with
`openssl` for local testing:

```bash
# Unencrypted PKCS#8 private key, the form --private-key expects.
openssl genpkey -algorithm ed25519 -out signing-key.pk8

# The raw 32-byte public key --trusted-key expects: an Ed25519 SubjectPublicKeyInfo
# DER is always 44 bytes, the last 32 of which are the raw key.
openssl pkey -in signing-key.pk8 -pubout -outform DER -out /tmp/pub.der
tail -c 32 /tmp/pub.der > release-public-key.raw
```

### 1. Create an attestation

Generate a deterministic report first, then sign it. Both PKCS#8 v1 and v2
keys are accepted.

```bash
soroban-upgrade-safeguard old.wasm new.wasm \
  --format json --no-timestamp > report.json
soroban-upgrade-safeguard attest report.json \
  --old-wasm old.wasm --new-wasm new.wasm \
  --private-key signing-key.pk8 --key-id release-2026 \
  --output report.dsse.json
```

Use `--policy policy.json` to bind a complete resolved policy/configuration
document. Without it, the attestation records the report schema, gated axes,
axis verdicts, and strictness used to produce the report. Optional storage
schema files can be supplied as a matched `--old-storage-schema` and
`--new-storage-schema` pair.

Ship `report.dsse.json` (the envelope) to whoever needs to verify the
result, alongside `release-public-key.raw` (out of band, over a channel you
trust — the public key is not itself inside the envelope) and the artifacts
the statement references (`report.json`, `old.wasm`, `new.wasm`, and any
storage schema files you included).

### 2. Verify offline, as a consumer

A consumer needs only the envelope, the trusted public key, and the
referenced artifacts — nothing is fetched over the network:

```bash
soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-2026=release-public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

**What this checks**, all offline, against exactly the artifacts given on
the command line:

- The DSSE payload is canonical JSON (rejects a payload that was re-encoded
  or re-ordered after signing).
- The signature itself, and that the signing identity (`--trusted-key`'s
  `ID=`) is one you explicitly declared as trusted — an envelope signed by
  an unrecognized key is rejected even if the signature is otherwise valid.
- The SHA-256 digest of every supplied artifact (`--report`, `--old-wasm`,
  `--new-wasm`, `--old-storage-schema`/`--new-storage-schema`) against the
  digest recorded in the statement — any artifact that was swapped or
  edited after signing fails here.
- `--policy-expires-at <UNIX_SECONDS>`, if given: rejects an attestation
  whose policy has expired as of that timestamp.

Omitting `--report`/`--old-wasm`/`--new-wasm` simply skips verifying that
particular artifact's digest (useful if a consumer only has some of the
referenced files) — it does not fail the run by itself, but anything
`attest` recorded a digest for and verification was never given a matching
file to check stays unverified.

**On success**, verification prints this and exits `0`:

```json
{
  "verified": true,
  "signer_identities": ["release-2026"],
  "failures": []
}
```

**On failure** — for example, `new.wasm` was swapped for a different build
after signing — verification prints the same shape with `verified: false`
and a non-empty `failures` array, and **exits `1`**:

```json
{
  "verified": false,
  "signer_identities": ["release-2026"],
  "failures": [
    {
      "kind": "artifact_digest_mismatch",
      "subject": "new.wasm",
      "message": "sha256 mismatch for 'new.wasm': expected <hex>, got <hex>"
    }
  ]
}
```

A CI step should treat "process exited non-zero" as the signal, not try to
parse `failures` for specific wording — `kind` is the stable field for
that if you need to branch on *why* it failed. The complete set of
`kind` values is: `missing_artifact`, `artifact_digest_mismatch`,
`untrusted_signer`, `invalid_signature`, `non_canonical_payload`,
`invalid_statement`, and `expired_policy`.

## Predicate and security guidance

The predicate type is
`https://github.com/ShippedLabs/soroban-upgrade-safeguard/attestation/v1`.
It contains the tool version, WASM and extracted-spec digests, storage schema
digests, resolved policy, report digest, and both directional call-ABI verdicts.
The in-toto subjects are the old and new WASM artifacts.

Keep private keys in a secret manager or protected build workspace. Never place
them in reports, envelopes, CI logs, diagnostics, or source control. The CLI
reads key bytes only while signing and never serializes them. Verification is
offline and trusts only identities explicitly supplied with `--trusted-key`.
Rotate keys by changing the key identity and trust-store entry; do not edit an
existing envelope. Any changed input requires a newly signed statement.

## Example envelope shape

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 canonical in-toto statement>",
  "signatures": [{"keyid": "release-2026", "sig": "<base64 Ed25519 signature>"}]
}
```

The signature covers the DSSE pre-authentication encoding of the canonical
payload, including its payload type and byte length.
