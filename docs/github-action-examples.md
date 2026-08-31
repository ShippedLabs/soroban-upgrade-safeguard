# GitHub Action Examples

The reusable action at `.github/actions/soroban-upgrade-safeguard/` wraps the
CLI and posts a Markdown report as a PR comment. This page documents the
available inputs and outputs, the required permissions for each scenario, and
three complete workflow examples covering the most common usage modes.

## Table of Contents

1. [Action inputs and outputs](#action-inputs-and-outputs)
2. [Permissions reference](#permissions-reference)
3. [Example 1 – Pull request check](#example-1--pull-request-check)
4. [Example 2 – Release gate](#example-2--release-gate)
5. [Example 3 – Fork pull request](#example-3--fork-pull-request)
6. [Common `args` combinations](#common-args-combinations)
7. [Artifact paths](#artifact-paths)
8. [Fork limitations](#fork-limitations)
9. [Fallback behavior](#fallback-behavior)

---

## Action inputs and outputs

### Inputs

| Input | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `old-wasm` | yes | — | Path to the baseline (deployed) WASM file. |
| `new-wasm` | yes | — | Path to the candidate (new) WASM file. |
| `token` | no | `${{ github.token }}` | GitHub token used to post the PR comment. Must have `pull-requests: write`. |
| `args` | no | `''` | Additional CLI flags passed verbatim to `soroban-upgrade-safeguard` (e.g. `--strict --explain --config .safeguard.toml`). |

### Outputs

| Output | Description |
| :--- | :--- |
| `is_safe` | `'true'` when the upgrade passes with no critical findings; `'false'` otherwise. |
| `comment_id` | ID of the created or updated PR comment. Empty when running outside a PR context or when the write permission is not available. |

---

## Permissions reference

| Scenario | `pull-requests` | `contents` | Notes |
| :--- | :--- | :--- | :--- |
| Standard PR (same-repo branch) | `write` | `read` | Token can post comments directly. |
| Release gate (tag push) | not needed | `write` (if creating a release) | No PR comment is posted; report is saved as a workflow artifact. |
| Fork PR – analysis job | not needed | `read` | Fork context; write permissions are not available. |
| Fork PR – comment job | `write` | `read` | Runs in the base-repo context via `workflow_run`; never executes fork code. |

The default `GITHUB_TOKEN` satisfies these requirements for same-repo PRs and
release workflows with no extra configuration. Repository secrets (including
`GITHUB_TOKEN`) are **not** available to fork PR analysis jobs by design.

---

## Example 1 – Pull request check

**Use this when:** a pull request comes from a branch inside the same
repository (not a fork). This is the standard configuration for most teams.

Full workflow: [`docs/workflow-examples/pr-check.yml`](workflow-examples/pr-check.yml)

```yaml
name: Soroban Upgrade Safety – PR Check

on:
  pull_request:
    branches: [main]
    paths:
      - 'wasm/**'
      - 'contracts/**'

jobs:
  upgrade-safeguard:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: Build soroban-upgrade-safeguard
        run: cargo build --release

      - name: Add tool to PATH
        run: echo "${{ github.workspace }}/target/release" >> "$GITHUB_PATH"

      - name: Run upgrade safety check
        id: safeguard
        uses: ./.github/actions/soroban-upgrade-safeguard
        with:
          old-wasm: ./wasm/v1.wasm
          new-wasm: ./wasm/v2.wasm
          token: ${{ secrets.GITHUB_TOKEN }}
          args: --strict --explain

      - name: Gate on safety verdict
        if: steps.safeguard.outputs.is_safe != 'true'
        run: |
          echo "::error::Upgrade safety check failed."
          exit 1
```

**What it does:**
- Triggers on PRs that change any file under `wasm/` or `contracts/`.
- Builds the tool from source (or use a pre-built binary if you publish one).
- Posts an in-place Markdown report as a PR comment on each push.
- `--strict` causes warnings to fail the job as well as critical findings.
- `--explain` appends per-finding remediation guidance to the report.
- The explicit gate step makes the failure reason visible in the job summary.

---

## Example 2 – Release gate

**Use this when:** you push a version tag and want to verify the candidate
WASM is safe before the release is published. No PR comment is posted; the
report is saved as a workflow artifact and written to the job summary.

Full workflow: [`docs/workflow-examples/release-gate.yml`](workflow-examples/release-gate.yml)

```yaml
name: Soroban Upgrade Safety – Release Gate

on:
  push:
    tags: ['v*']

jobs:
  upgrade-safeguard:
    runs-on: ubuntu-latest
    permissions:
      contents: write   # only if you also create a GitHub release
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Build soroban-upgrade-safeguard
        run: cargo build --release

      - name: Add tool to PATH
        run: echo "${{ github.workspace }}/target/release" >> "$GITHUB_PATH"

      - name: Run upgrade safety check (JSON)
        run: |
          soroban-upgrade-safeguard \
            ./wasm/released.wasm \
            ./wasm/candidate.wasm \
            --format json \
            --explain \
            --expect-bump minor \
            > safeguard-report.json

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: safeguard-report-${{ github.ref_name }}
          path: safeguard-report.json
          retention-days: 90
```

**What it does:**
- Runs the tool directly (not via the composite action) for full output
  format control.
- `--format json` produces a machine-readable report suitable for archiving
  alongside the release or ingesting into a dashboard.
- `--expect-bump minor` fails the job if the detected changes do not
  warrant at least a minor version bump. Adjust to `patch` or `major` as
  needed.
- `if: always()` on the artifact upload ensures the report is saved even
  when the safety check fails, so you can diagnose the issue without
  re-running.

---

## Example 3 – Fork pull request

**Use this when:** your repository accepts contributions from forks. Fork PR
jobs run with a read-only token and cannot post comments directly.

Full workflow (two files): [`docs/workflow-examples/fork-pr.yml`](workflow-examples/fork-pr.yml)

The pattern splits work across two jobs:

**Job 1 — analysis** (runs in the fork context, read-only token):
```yaml
on:
  pull_request:
    branches: [main]
    paths: ['wasm/**', 'contracts/**']

jobs:
  upgrade-safeguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read   # no write access in fork context
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: echo "${{ github.workspace }}/target/release" >> "$GITHUB_PATH"

      - name: Run upgrade safety check
        run: |
          soroban-upgrade-safeguard \
            ./wasm/v1.wasm ./wasm/v2.wasm \
            --format markdown --explain \
            > safeguard-report.md

      - run: echo "${{ github.event.number }}" > pr-number.txt
        if: always()

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: safeguard-report-pr-${{ github.event.number }}
          path: |
            safeguard-report.md
            pr-number.txt
          retention-days: 7
```

**Job 2 — comment** (runs in the base-repo context via `workflow_run`,
`pull-requests: write`). Save this as a **separate workflow file**:

```yaml
on:
  workflow_run:
    workflows: ["Soroban Upgrade Safety – Fork PR"]
    types: [completed]

jobs:
  post-comment:
    runs-on: ubuntu-latest
    if: github.event.workflow_run.event == 'pull_request'
    permissions:
      pull-requests: write
      actions: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: safeguard-report-pr-${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          run-id: ${{ github.event.workflow_run.id }}

      - id: pr
        run: echo "number=$(cat pr-number.txt)" >> "$GITHUB_OUTPUT"

      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const body = '## Soroban Upgrade Safeguard Report\n\n'
              + fs.readFileSync('safeguard-report.md', 'utf8')
              + '\n\n<!-- soroban-upgrade-safeguard-report -->';
            const prNumber = parseInt('${{ steps.pr.outputs.number }}', 10);
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: prNumber,
            });
            const existing = comments.find(c =>
              c.body.includes('soroban-upgrade-safeguard-report'));
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner, repo: context.repo.repo,
                comment_id: existing.id, body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner, repo: context.repo.repo,
                issue_number: prNumber, body,
              });
            }
```

**Why two files?** Job 2 is triggered by `workflow_run`, which always fires in
the base-repo context regardless of where the code originated. This is the only
safe way to get `pull-requests: write` for a fork PR. Combining both jobs in
one file would expose the write token to fork-supplied code.

---

## Common `args` combinations

Pass any of these via the `args` input (or directly on the CLI):

| Goal | `args` value |
| :--- | :--- |
| Fail on warnings too | `--strict` |
| Show remediation guidance | `--explain` |
| Use a custom suppression config | `--config .safeguard.toml` |
| Enforce a minimum semver bump | `--expect-bump minor` |
| Strict + explain + config | `--strict --explain --config .safeguard.toml` |
| Storage schema analysis | `--old-storage-schema schemas/v1.toml --new-storage-schema schemas/v2.toml` |

All flags are documented in `--help` and in [documentation.md](documentation.md).

---

## Artifact paths

| Input | What to pass | Notes |
| :--- | :--- | :--- |
| `old-wasm` | Path relative to the workspace root | Must exist before the action step runs. |
| `new-wasm` | Path relative to the workspace root | Produce it in a prior `cargo build` or download step. |

The action calls the tool with these paths verbatim. If your build produces the
WASM in `target/wasm32-unknown-unknown/release/my_contract.wasm`, pass that
path directly. You do not need to copy the file to a fixed location unless you
prefer to.

For the release-gate pattern, both WASMs must be present in the same runner.
Fetch the deployed baseline from your artifact store, OCI registry, or crates
release in a step before the analysis runs:

```yaml
- name: Download deployed baseline
  run: |
    curl -fsSL "https://releases.example.com/v1.0.0/contract.wasm" \
      -o wasm/released.wasm
```

---

## Fork limitations

- **No secrets.** Repository secrets (including additional tokens beyond
  `GITHUB_TOKEN`) are not available to fork PR jobs. Do not reference them
  in job 1 of the fork pattern.
- **No direct comment posting.** Job 1 runs with a read-only token. Posting
  a comment requires the two-job `workflow_run` pattern described in
  [Example 3](#example-3--fork-pull-request).
- **Approval gate.** If your repository requires approval for outside
  collaborator workflows, job 1 waits for a maintainer to approve before
  any code runs. The safety check therefore does not block a fork PR
  automatically until it has been approved to run.
- **Artifact hand-off.** The PR number must be passed through a file in the
  uploaded artifact, not via an environment variable, because environment
  variables set by untrusted fork code cannot be trusted in job 2.

---

## Fallback behavior

The composite action handles the following edge cases without failing the
overall workflow:

| Situation | What happens |
| :--- | :--- |
| Not running in a PR context (e.g. push to `main`) | The comment step is skipped; `is_safe` is still set from the tool exit code. |
| Token lacks `pull-requests: write` | The comment POST fails silently; `comment_id` output is empty; the tool exit code is preserved. |
| PR comment already exists | The existing comment is updated in-place rather than creating a duplicate. |
| Tool exits with code 1 (critical findings) | `is_safe` is `'false'`; the job continues to the gate step. |
| Tool exits with code 2 (resource limit exceeded) | `is_safe` is `'false'`; treat this as a configuration issue (raise the relevant limit). |

To make the workflow fail when the token cannot write comments (rather than
silently continuing), check `steps.safeguard.outputs.comment_id` explicitly:

```yaml
- name: Verify comment was posted
  if: steps.safeguard.outputs.comment_id == ''
  run: echo "::warning::PR comment could not be posted — check token permissions."
```
