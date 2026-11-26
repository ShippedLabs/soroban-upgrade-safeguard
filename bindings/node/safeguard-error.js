'use strict';

/**
 * Typed error for every comparison failure.
 *
 * `kind` is the stable string form of the Rust library's `ErrorKind`
 * (e.g. `"WasmValidation"`, `"InvalidInput"`) — match on it instead of
 * parsing `.details` or `.message`, since `details` is free text for
 * humans and may change wording between releases.
 */
class SafeguardError extends Error {
  constructor(kind, details) {
    super(`${kind}: ${details}`);
    this.name = 'SafeguardError';
    this.kind = kind;
    this.details = details;
  }
}

module.exports = { SafeguardError };
