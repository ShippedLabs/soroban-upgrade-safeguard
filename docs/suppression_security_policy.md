# Upgrade Safeguard Suppression Security Policy

This document defines the security model, operational best practices, and verification constraints for the suppression configuration in `soroban-upgrade-safeguard`.

---

## 1. Executive Summary

Static validation of smart contract upgrades enforces strict API and storage schema compatibility. However, intentional breaks (such as structural migrations or renaming legacy parameters) are sometimes unavoidable. 

The **Suppression Engine** provides an opt-in mechanism to whitelist specific findings via a local `.safeguard.toml` configuration. Because suppressions override default compiler safeguards, this policy defines constraints to prevent the misuse, decay, or bypass of safety verdicts.

---

## 2. Threat Model & Safeguards

Suppression rules represent deliberate overrides of safety violations. To maintain audit accountability, the engine supports multiple security validation layers.

### Threat 1: Stale Rules (Decay)
* **Risk**: A suppression rule is introduced for a temporary migration, but remains active in the codebase forever, potentially masking future accidental regressions on the same target.
* **Mitigation**: **Rule Expiration**. Rules can define an optional `expiry` parameter formatted as a `YYYY-MM-DD` ISO date string. The validation pipeline checks the current system clock and treats any expired rule as invalid, forcing a build failure until the rule is removed or explicitly renewed.

### Threat 2: Finding Modification (Fingerprint Drift)
* **Risk**: A rule is written to suppress a structural change (e.g. changing parameter type from `u32` to `u64`). Later, the developer modifies the code further to change the parameter type to a completely different type (e.g. `String`). The rule matches the target entity and category, silently masking the new unreviewed break.
* **Mitigation**: **Content Fingerprints**. The `fingerprint` property in `SuppressionRule` stores a SHA-256 hash of the specific finding's attributes (such as the detailed error message or structural change representation). The matcher verifies that the actual finding's hash matches the declared fingerprint exactly. If the code drifts, the fingerprint invalidates, and the tool raises a compile error.

### Threat 3: Anonymous Rules (Accountability)
* **Risk**: A rule is added to bypass a critical upgrade safety check in CI, but there is no record of who reviewed and authorized the bypass.
* **Mitigation**: **Author Declaration**. All non-trivial suppression rules require an explicit `author` string (Git handle, email, or corporate identity) and a descriptive `reason` explanation. Automated PR checks can parse these attributes and trigger mandatory secondary reviewer approvals if specific high-risk categories are bypassed.

---

## 3. Configuration Format Example

The configuration structure enforces accountability. Here is a fully compliant example of `.safeguard.toml`:

```toml
# Max permitted suppressions in the codebase (enforces strict limits)
max_suppressions = 5
allow_targetless = false

[[suppress]]
category = "Struct Field Type Changed"
target = "Data.amount"
author = "Alice <alice@company.com>"
reason = "Widening balance field from u64 to i128 to match Soroban v2 specifications."
expiry = "2026-12-31"
fingerprint = "a6f8b2c4d9e0123456789abcdef0123456789abcdef0123456789abcdef01234"
```

---

## 4. Policy Enforcement Rules

### Mandatory Expiry for Testnets
Teams should configure a security policy requiring all suppressions targeting test/staging environments to have an expiry date not exceeding 30 days.

### Fingerprint Generation
To generate a valid SHA-256 fingerprint for a new suppression rule, run the check command with `--explain` to output the exact finding JSON, hash the serialized representation, and populate the configuration:

```bash
echo -n "Finding message + target content" | shasum -a 256
```

### Regular Audits
We recommend running a regular quarterly audit of active `.safeguard.toml` files to remove obsolete rules and rotate expiring authorizations.
