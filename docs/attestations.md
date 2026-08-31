# Signed safeguard attestations

Safeguard can bind an analysis to its inputs and verdict with a versioned
in-toto statement wrapped in a DSSE envelope. The statement is canonical JSON;
rendered text, Markdown, and JSON reports are never signed directly.

## Create an attestation

Generate a deterministic report first, then sign it with an unencrypted
Ed25519 PKCS#8 key. Both PKCS#8 v1 and v2 keys are accepted.

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

## Verify offline

The verifier needs only the envelope, trusted raw 32-byte Ed25519 public key,
and the referenced artifacts. It checks payload canonicalization, the DSSE
signature, signer identity, every SHA-256 digest, and policy expiry.

```bash
soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-2026=release-public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

Verification prints structured JSON and exits non-zero when it cannot trust the
verdict. Failure kinds are intentionally distinct: `missing_artifact`,
`artifact_digest_mismatch`, `untrusted_signer`, `invalid_signature`,
`non_canonical_payload`, `invalid_statement`, and `expired_policy`.

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
