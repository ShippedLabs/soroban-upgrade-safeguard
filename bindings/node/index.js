'use strict';

// Hand-written loader for local development: a single compiled addon for
// the current host, built with `npm run build:debug` (debug) or
// `npm run build` (release) via `@napi-rs/cli`, producing
// `soroban_upgrade_safeguard.node` in this directory. There is no
// multi-platform prebuilt-binary matrix yet — see docs/bindings.md in the
// main repository for what that would take and why it isn't wired up in
// this first pass.
const native = require('./soroban_upgrade_safeguard.node');
const { SafeguardError } = require('./safeguard-error.js');

function unwrap(outcome) {
  if (outcome.ok) {
    return outcome.report;
  }
  throw new SafeguardError(outcome.error.kind, outcome.error.details);
}

/**
 * Compare two Soroban contract builds given as raw WASM bytes.
 *
 * @param {Buffer} oldWasm
 * @param {Buffer} newWasm
 * @param {object} [options]
 * @returns {object} the report, matching the CLI's `--format json` shape
 * @throws {SafeguardError}
 */
function compareBytes(oldWasm, newWasm, options) {
  return unwrap(native.compareBytes(oldWasm, newWasm, options ?? null));
}

/**
 * Compare two Soroban contract builds read from WASM files on disk.
 *
 * The only I/O this performs is reading exactly `oldPath`/`newPath`; it
 * never consults the network or a cache directory.
 *
 * @param {string} oldPath
 * @param {string} newPath
 * @param {object} [options]
 * @returns {object} the report, matching the CLI's `--format json` shape
 * @throws {SafeguardError}
 */
function compareFiles(oldPath, newPath, options) {
  return unwrap(native.compareFiles(oldPath, newPath, options ?? null));
}

/**
 * The version of soroban-upgrade-safeguard (the Rust engine) this addon
 * was built against. See docs/bindings.md for the version-compatibility
 * policy between this number and this package's own version.
 *
 * @returns {string}
 */
function engineVersion() {
  return native.engineVersion();
}

module.exports = { compareBytes, compareFiles, engineVersion, SafeguardError };
