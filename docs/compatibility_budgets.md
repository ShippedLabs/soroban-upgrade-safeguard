# Compatibility Budgets

Axis gating (`[policy]` in `.safeguard.toml`) and `--strict` decide **which
kinds** of findings can fail a run, but they are boolean: an axis either
gates the run or it doesn't. A budget expresses a bounded **count** instead
-- "at most 2 new events this release", "zero warnings in this specific
rule" -- evaluated after analysis, without changing how any individual
finding is classified, suppressed, or gated.

## Config shape

Add one or more `[[budget]]` tables to `.safeguard.toml`, alongside any
`[[suppress]]` rules:

```toml
[[budget]]
scope  = "global"
metric = "unsuppressed"
limit  = 0

[[budget]]
scope  = "axis"
axis   = "event_indexer"
metric = "raw"
limit  = 3

[[budget]]
scope    = "rule"
rule_id  = "enum_case_added"
severity = "warning"
metric   = "unsuppressed"
limit    = 1
```

| Field      | Required for                | Values |
|---|---|---|
| `scope`    | always                       | `"global"`, `"axis"`, `"rule"` |
| `axis`     | `scope = "axis"`             | `storage_layout`, `call_abi`, `event_indexer`, `source_level`, `runtime_surface` |
| `rule_id`  | `scope = "rule"`             | the canonical, snake_case form of a finding category (e.g. `"Enum Case Added"` -> `"enum_case_added"`) -- the same identifier already used by `[[suppress]] rule_id` and shown in reports as `ReportedFinding::rule_id` |
| `severity` | optional, any scope          | `critical`, `warning`, `info` -- narrows the scope to findings of that severity only |
| `metric`   | optional (default `unsuppressed`) | `raw` (every finding the scope claims, suppressed or not) or `unsuppressed` (only findings not acknowledged by a `[[suppress]]` rule) |
| `limit`    | always                       | a non-negative integer; measured count must not exceed this |

## Precedence

Scopes narrow from `global` to `axis` to `rule`, and a **narrower budget
replaces a broader one** for the findings it covers -- it does not stack
with it:

1. Every finding whose `rule_id` matches a configured `rule` budget is
   claimed by that budget alone.
2. Every remaining finding that carries an axis matching a configured `axis`
   budget is claimed by that budget alone.
3. Whatever is left is evaluated against the `global` budget, if any.

So `limit = 0` globally plus `limit = 2` for one specific rule allows
exactly 2 findings of that rule and zero of everything else -- the rule
budget overrides the global default for its own findings rather than adding
to them.

Two `[[budget]]` entries with the same effective scope (and, for rule
scopes, the same `severity`) but different `metric`/`limit` are rejected as
contradictory at load time, since the outcome would otherwise depend on
config ordering rather than a deterministic rule.

## Validation

A `.safeguard.toml` with an invalid `[[budget]]` section fails to load (the
same way a malformed `[[suppress]]` rule does) with a specific error naming
the problem:

- an unknown `scope` string,
- `scope = "axis"` without `axis`, or `scope = "rule"` without `rule_id`,
- a `rule_id` naming no known finding rule,
- a negative `limit`,
- two entries contradicting each other on the same scope.

## How violations show up

A `BudgetViolation` records the scope label (e.g. `"rule:enum_case_added"`),
the metric, the measured count, and the configured limit. It is always
listed separately from ordinary findings -- a budget violation is a policy
decision about a *count*, not a new finding about the artifact -- and it
**always fails the run**, independent of `--strict` and axis gate policy,
because a configured budget is an explicit opt-in a team chose, not a
default.

- **Text**: a `COMPATIBILITY BUDGETS` section listing each exceeded budget.
- **Markdown**: a `### Compatibility Budgets Exceeded` table.
- **JSON**: a `budget_violations` array on the report (omitted entirely when
  empty, so existing consumers of the JSON schema are unaffected).
- **Exit codes**: unchanged -- a budget violation sets `is_safe = false`
  exactly like a gated critical finding does, so it follows the same exit
  code path (`1`) rather than introducing a new one.

## Batch and manifest workflows

Budgets are validated as part of the same `.safeguard.toml` load that
already resolves `[[suppress]]` rules and `[policy]` gating, so single-run,
batch (`--old-dir`/`--new-dir`), and manifest (`--manifest`) modes all pick
up `[[budget]]` automatically through the config file each pair already
loads -- no separate flag or per-mode plumbing is needed. A pair's manifest
policy overrides (`docs/batch_manifests.md`) apply to axis gating only;
budgets always come from the pair's own resolved config file.

## Scope note: `lint` and `extract`

Budgets evaluate `Finding`/`ReportedFinding` records, which only exist for
a two-build comparison. The `lint` subcommand (`docs/lint_rules_reference.md`)
validates a single artifact and emits a structurally different kind of
finding (no axes, no comparison-relative severity scale), and `extract`
performs no analysis at all. Neither loads a `[[budget]]` section, so
introducing budgets changes nothing about their default behavior --
consistent with the acceptance criteria's requirement that lint, extraction,
single comparison, and batch workflows all keep their existing default
behavior unchanged.
