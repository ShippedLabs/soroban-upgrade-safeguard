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

The `verify-attestation` command verifies a DSSE attestation envelope and all referenced artifacts completely offline. A downstream verifier needs only the envelope, the trusted raw 32-byte Ed25519 public key, and the referenced build artifacts.

### Worked example: Consumer verification workflow

A consumer receives an attestation bundle containing:
1. `report.dsse.json` (signed DSSE envelope)
2. `release-public-key.raw` (trusted 32-byte raw public key)
3. `report.json` (unmodified analysis report)
4. `old.wasm` & `new.wasm` (original contract artifacts)

To verify the integrity and provenance of the analysis offline:

```bash
soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-2026=release-public-key.raw \
  --report report.json \
  --old-wasm old.wasm \
  --new-wasm new.wasm
```

### What `verify-attestation` checks offline

`verify-attestation` runs with zero network dependencies and validates:
1. **DSSE Envelope Canonicalization**: Verifies that the payload contains a valid in-toto statement following canonical JSON serialization rules.
2. **Cryptographic Signature**: Validates the Ed25519 signature over the pre-authentication encoding (PAE) using the provided public key.
3. **Signer Identity Match**: Verifies that the `keyid` specified in the envelope matches an identity supplied in `--trusted-key`.
4. **Artifact Integrity Digests**: Computes SHA-256 hashes for all local files (`report.json`, `old.wasm`, `new.wasm`, and storage schemas if present) and matches them against statement subjects.
5. **Policy Expiration**: Confirms that the current verification timestamp is within the bound policy's validity window (if `--policy` was included).

### Exit behavior and failure modes

- **Success (`exit 0`)**: Verification succeeded. Structured JSON describing the verified verdict and subjects is printed to stdout.
- **Verification Failure (`exit 1`)**: When any check fails, the CLI outputs structured JSON to stderr/stdout detailing the failure reason and exits non-zero (`1`). Failure kinds are intentionally distinct:
  - `missing_artifact`: A required artifact file was not found on disk.
  - `artifact_digest_mismatch`: Local file SHA-256 does not match the signed digest.
  - `untrusted_signer`: Envelope key identity was not passed in `--trusted-key`.
  - `invalid_signature`: Cryptographic signature verification failed.
  - `non_canonical_payload`: Payload deviates from canonical JSON encoding.
  - `invalid_statement`: Malformed statement schema or missing fields.
  - `expired_policy`: The evaluation falls outside the policy validity window.

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
