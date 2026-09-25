# Configuration Resolution Precedence

The suppression config (`.safeguard.toml` and the `--config` / `--no-config`
family of flags) is resolved from up to five sources, consulted in a fixed
priority order. The first source that produces a path wins; all later sources
are ignored.

```
1. --no-config          (bypass everything — no suppressions applied)
2. --config <PATH>      (explicit CLI flag)
3. SOROBAN_SAFEGUARD_CONFIG  (environment variable)
4. .safeguard.toml in the current directory  (auto-discovered default)
5. .safeguard.toml in an ancestor directory  (opt-in, --search-parent-config)
```

## Tier 1 — `--no-config`

Passing `--no-config` disables all config loading. No file is read, no
environment variable is consulted, no directory is searched. The tool runs
with an empty suppression list. This is useful for a clean baseline run or
for confirming that a suppression is doing what you expect.

`--no-config` conflicts with `--config` and with `--search-parent-config`
at the flag level — combining them is rejected before any analysis runs.

## Tier 2 — `--config <PATH>`

An explicit path on the command line takes highest precedence after the
bypass tier:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --config /path/to/.safeguard.toml
```

If the file is missing or malformed, the run fails immediately with a hard
error. There is no silent fallback to a lower tier — if you named a path,
the tool expects it to exist.

## Tier 3 — `SOROBAN_SAFEGUARD_CONFIG`

When `--config` is not given, the environment variable is checked next.
This is the standard way for a CI system to configure a config path once
rather than repeating `--config` on every invocation:

```bash
# Set once, e.g. in a workflow's env: block or in a .envrc.
export SOROBAN_SAFEGUARD_CONFIG=/repo/.safeguard.toml

# Every subsequent invocation picks it up automatically.
soroban-upgrade-safeguard old.wasm new.wasm
```

An explicit `--config` flag always wins over the environment variable. Like
`--config`, a path that is set but points at a missing or malformed file is
a hard error — setting the variable implies you expect it to resolve.

## Tier 4 — `.safeguard.toml` in the current directory

When neither `--config` nor `SOROBAN_SAFEGUARD_CONFIG` resolves a path, the
tool looks for `.safeguard.toml` in the current working directory. This is
the default workflow for a single-contract repository:

```
my-contract/
├── .safeguard.toml   ← picked up automatically
├── old.wasm
└── new.wasm
```

```bash
# No flags needed; .safeguard.toml in the current directory is found.
soroban-upgrade-safeguard old.wasm new.wasm
```

This tier is **silently optional**: if `.safeguard.toml` is not present,
the tool proceeds with no suppressions. It is not an error. This is the
only tier where absence is treated as "no config" rather than a failure —
the reasoning is that a missing default file is the normal state for a
project that hasn't created one yet, whereas a missing explicitly-named
path is almost certainly a mistake.

A present-but-malformed `.safeguard.toml` is still a hard error.

## Tier 5 — Ancestor directory search (`--search-parent-config`)

In a monorepo or multi-package workspace, the current directory is often
a package subdirectory that has no `.safeguard.toml` of its own, while the
repository root does. The plain current-directory check (Tier 4) misses
that file. `--search-parent-config` enables an opt-in walk up the directory
tree for exactly that case:

```bash
# services/payments has no .safeguard.toml; the repo root does.
cd services/payments
soroban-upgrade-safeguard old.wasm new.wasm --search-parent-config
```

The walk starts from the current directory's **parent** (the current
directory itself was already covered by Tier 4) and moves upward,
looking for `.safeguard.toml` at each level. It stops at the first of
two boundaries:

- **The workspace root** — the first ancestor directory that contains a
  `.git` entry. This is both a directory (normal checkout) and a file (git
  worktree or submodule pointer); either form stops the search. The
  boundary directory itself is still searched before stopping.
- **The filesystem root**, if no `.git` is ever found.

**More than one candidate is a hard error.** If two ancestor directories
each contain a `.safeguard.toml`, the tool cannot know which one you
intended, and silently picking the nearest would make the effective config
depend on which subdirectory you happened to run from. Instead, the run
fails and lists every candidate found:

```
Error: Ambiguous --search-parent-config: found 2 candidate suppression configs
between 'services/payments' and the workspace boundary:
  - /repo/services/.safeguard.toml
  - /repo/.safeguard.toml
Pass --config explicitly to choose one.
```

This tier is still the lowest-priority source: `--config`,
`SOROBAN_SAFEGUARD_CONFIG`, and the current-directory default all win
over it.

## How to tell which config was used

Regardless of which tier resolved the config, the tool prints a diagnostic
line at the start of every run:

```
Suppression config: /repo/.safeguard.toml (source: --search-parent-config)
```

The `source` label maps directly to the tier that produced the path:

| Source label | Tier |
|---|---|
| `--config` | Tier 2 — explicit CLI flag |
| `SOROBAN_SAFEGUARD_CONFIG env var` | Tier 3 — environment variable |
| `auto-discovered .safeguard.toml` | Tier 4 — current directory |
| `--search-parent-config` | Tier 5 — ancestor directory |

In `--manifest` batch mode, the same information is available per pair
via `--explain-manifest`, where the config setting's `origin` field shows
`cli`, `env`, `built-in`, or the manifest file that set it.

`--show-config` prints the fully resolved configuration, including the
config path and its source, without running any analysis. Secret values
(RPC header values) are never resolved or printed by `--show-config`.

## Behavior summary

| Source | Missing file | Malformed file |
|--------|-------------|----------------|
| `--config <PATH>` | Hard error | Hard error |
| `SOROBAN_SAFEGUARD_CONFIG` | Hard error | Hard error |
| Current directory `.safeguard.toml` | Silent skip (no suppressions) | Hard error |
| `--search-parent-config` ancestor | Continues search / no config if none found | Hard error |

## Practical patterns

**Single repository, config at the root:**

```
my-repo/
├── .safeguard.toml
└── contracts/
    ├── old.wasm
    └── new.wasm
```

```bash
# Run from the repo root — Tier 4 picks it up automatically.
soroban-upgrade-safeguard contracts/old.wasm contracts/new.wasm

# Or run from inside the contracts directory with the ancestor search.
cd contracts
soroban-upgrade-safeguard old.wasm new.wasm --search-parent-config
```

**CI pipeline, config injected via environment:**

```yaml
env:
  SOROBAN_SAFEGUARD_CONFIG: ${{ github.workspace }}/.safeguard.ci.toml

steps:
  - run: soroban-upgrade-safeguard old.wasm new.wasm
```

**Multiple configs for different environments, selected at the call site:**

```bash
# Developer local run — relaxed.
soroban-upgrade-safeguard old.wasm new.wasm --config .safeguard.dev.toml

# Release gate — strict.
soroban-upgrade-safeguard old.wasm new.wasm --config .safeguard.release.toml --strict
```

**Confirm no suppressions are applied (audit / baseline run):**

```bash
soroban-upgrade-safeguard old.wasm new.wasm --no-config
```

## See also

- [`.safeguard.example.toml`](../.safeguard.example.toml) — annotated
  template covering suppression rules, `[require_reason]`, and named
  profiles
- [Named Policy Profiles](named_policy_profiles.md) — selecting a profile
  within a resolved config via `--profile` or `SAFEGUARD_PROFILE`
- [Documentation: Config file](documentation.md#config-file) — quick
  reference in the main docs
- [Suppression Security Policy](suppression_security_policy.md) — when
  suppressions require a `reason` and how that is enforced
