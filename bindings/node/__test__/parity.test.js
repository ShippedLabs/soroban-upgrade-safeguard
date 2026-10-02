'use strict';

// Cross-language parity: the Node binding's report must match the CLI's
// `--format json` report for the same inputs, field for field.
//
// Not wired into any CI job yet (see docs/bindings.md), and not run as
// part of this change — it requires the native addon to be built first
// (`npm run build:debug` in bindings/node) and the main crate's binary to
// be built (`cargo build`). Run manually with:
//
//   cd bindings/node && npm install && npm run build:debug
//   cargo build --manifest-path ../../Cargo.toml --bin soroban-upgrade-safeguard
//   node --test __test__/parity.test.js

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const WASM_DIR = path.join(REPO_ROOT, 'tests', 'wasm');
const CLI_BIN = path.join(REPO_ROOT, 'target', 'debug', 'soroban-upgrade-safeguard');
const NATIVE_ADDON = path.join(__dirname, '..', 'soroban_upgrade_safeguard.node');

function runCli(oldPath, newPath) {
  const stdout = execFileSync(CLI_BIN, [oldPath, newPath, '--format', 'json', '--no-color'], {
    encoding: 'utf8',
  });
  return JSON.parse(stdout);
}

test('compareBytes matches the CLI JSON report', { skip: !fs.existsSync(CLI_BIN) || !fs.existsSync(NATIVE_ADDON) }, () => {
  const safeguard = require('..');

  const oldPath = path.join(WASM_DIR, 'v1.wasm');
  const newPath = path.join(WASM_DIR, 'v2.wasm');

  const cliReport = runCli(oldPath, newPath);
  const nodeReport = safeguard.compareBytes(fs.readFileSync(oldPath), fs.readFileSync(newPath));

  for (const key of ['is_safe', 'critical_count', 'warning_count', 'info_count']) {
    assert.strictEqual(nodeReport[key], cliReport[key], `field ${key} diverged`);
  }
  assert.deepStrictEqual(nodeReport.findings_by_category, cliReport.findings_by_category);
});
