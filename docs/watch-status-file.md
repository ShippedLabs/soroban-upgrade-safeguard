# Watch Status File

Give a watch run a status file and it publishes a small, machine-readable JSON
document that tells an external supervisor what the watcher is doing right now:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --watch --watch-status-file /var/run/safeguard-status.json
```

The flag is available with every form of watch mode — a single pair, a
directory comparison, or a batch manifest — and requires `--watch`. After each
cycle transition (start, completion, or error) the JSON document is replaced
atomically, so a poller never observes a partially written file. A fourth
transition, shutdown, is written on a graceful stop and has its own quirks
described below.

Note that `--watch` needs local file paths. Combined with a `stdin` or RPC
source, the run prints a warning, does not watch anything, and exits — leaving
you with a single cycle's documents and a process that is already gone.

This page describes:

- [Why a status file](#why-a-status-file)
- [File format](#file-format)
- [Field semantics](#field-semantics)
- [Lifecycle of a cycle](#lifecycle-of-a-cycle)
  - [The shutdown document](#the-shutdown-document)
  - [When `shutting_down` is written](#when-shutting_down-is-written)
- [Findings are never written](#findings-are-never-written)
- [Polling for liveness](#polling-for-liveness)
- [Atomicity guarantees](#atomicity-guarantees)

## Why a status file

Watch mode is a long-running process. A build system or service manager that
supervises it needs a cheap answer to two questions: is it alive, and when did
it last finish a comparison? It does not want to parse (or wait for) the full
text/JSON comparison report — reports are large, carry schema versioning, and
only exist once a cycle completes.

The status file answers both questions with a tiny, stable document that is
always current. Because it contains no findings and no report content, it also
never goes stale the way a report buffer would: a poller can read it at any
moment and see exactly one cycle's operational state.

## File format

The document is JSON, pretty-printed, with snake_case field names:

```json
{
  "state": "completed",
  "cycle": 3,
  "started_at": 1737232142,
  "finished_at": 1737232146,
  "is_safe": true,
  "error": null
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `state` | string | One of `running`, `completed`, `error`, `shutting_down`. |
| `cycle` | integer | 1-based number of the comparison cycle this status describes. Starts at 1 and increments once per cycle. The `shutting_down` document is the exception — see [The shutdown document](#the-shutdown-document). |
| `started_at` | integer | Unix time in seconds (UTC) when the cycle started. Also reset on the `shutting_down` document. |
| `finished_at` | integer or `null` | Unix time in seconds (UTC) when the cycle finished. `null` while `state` is `running`. |
| `is_safe` | boolean or `null` | The cycle's verdict. `null` until the cycle reaches `completed`; also `null` on error. |
| `error` | string or `null` | A short, top-level failure reason when `state` is `error`. `null` otherwise. |

`state` values:

- `running` — a comparison cycle started and is still in progress.
- `completed` — the most recent cycle finished and produced a verdict in `is_safe`.
- `error` — the most recent cycle failed; `error` holds the reason.
- `shutting_down` — the watch process is exiting after a graceful stop request.
  This is written only in response to `SIGTERM`, and only on a unix host. See
  [When `shutting_down` is written](#when-shutting_down-is-written).

## Field semantics

- Timestamps are Unix seconds in UTC, truncated to whole seconds. They are
  wall-clock times, not elapsed durations.
- Every field is always present. A value that does not apply to the current
  `state` is written as an explicit `null` rather than omitted, so a poller can
  rely on the key set staying fixed across every document.
- `cycle` counts completed *starts*, so a freshly started cycle increments the
  counter before the comparison runs. The one exception is the shutdown document
  — see [The shutdown document](#the-shutdown-document).
- `finished_at`, `is_safe`, and `error` are relative to `state`:
  - While `running`, `finished_at` and `is_safe` are `null`.
  - On `completed`, `is_safe` carries the verdict and `error` is `null`.
  - On `error`, `is_safe` is `null` and `error` carries a short reason.
- Every write replaces the entire document. Starting a new cycle therefore
  always clears the previous verdict and error — a stale `is_safe` or `error`
  from an earlier cycle can never leak into the new one.

## Lifecycle of a cycle

A single cycle progresses through the document like this:

```json
{
  "state": "running",
  "cycle": 4,
  "started_at": 1737232151,
  "finished_at": null,
  "is_safe": null,
  "error": null
}
```

On success the same cycle becomes:

```json
{
  "state": "completed",
  "cycle": 4,
  "started_at": 1737232151,
  "finished_at": 1737232156,
  "is_safe": false,
  "error": null
}
```

On failure it becomes `error` instead — `is_safe` returns to `null` and only a
summary reason is recorded:

```json
{
  "state": "error",
  "cycle": 4,
  "started_at": 1737232151,
  "finished_at": 1737232153,
  "is_safe": null,
  "error": "failed to load ./wasm/v2.wasm: unexpected EOF"
}
```

Notice what none of these documents contain: the status file holds no report
content at all. `error` is a *reason* — a sentence a supervisor can surface or
log — never the findings from the failed comparison. See
[Findings are never written](#findings-are-never-written) for why that separation
is deliberate.

And when the watch process is asked to stop, the final document records that
transition without a verdict. Note that it describes the *shutdown*, not the last
cycle, so `started_at` is the moment of the stop request and `cycle` is `0`:

```json
{
  "state": "shutting_down",
  "cycle": 0,
  "started_at": 1737232209,
  "finished_at": 1737232209,
  "is_safe": null,
  "error": null
}
```

### The shutdown document

The `shutting_down` document is built from a fresh timestamp rather than from
the cycle that happened to be in flight, which gives it two properties worth
knowing before you write a poller against it:

- **`started_at` is the stop time, not the last cycle's start.** It is stamped
  the moment the shutdown transition is written, so it is equal to — or within a
  second of — `finished_at`. Do not read it as "when the work began."
- **`cycle` is `0` in single-pair and directory mode, but the real count in batch
  mode.** A single-pair or `--old-dir`/`--new-dir` run cannot see the live cycle
  counter at shutdown and writes `0`; a `--manifest` (batch) run preserves the
  actual count. This is a known inconsistency between the two loops, so treat
  `cycle` as meaningful only while `state` is `running`, `completed`, or `error`.
  If you need a reliable cycle count across modes, read it from the last
  `completed` or `error` document before the process exits.

Because the last verdict is not carried over either, a supervisor that needs the
final verdict must capture it from the preceding `completed` document rather than
expecting the shutdown document to repeat it.

### When `shutting_down` is written

Only a graceful `SIGTERM` produces this document, and only on a unix host with
the `watch` feature. That is a real limit on what a poller can conclude from it:

- `SIGTERM` is caught, recorded, and acted on at a safe point between cycles, so
  the shutdown write happens and the file is left complete and well-formed.
- `Ctrl+C` (`SIGINT`) is **not** caught. The default disposition terminates the
  process immediately, so the shutdown document is never written and the file
  keeps whatever the last cycle left in it.
- A non-unix host (Windows) has no interceptable equivalent, so the graceful path
  is unavailable there and the shutdown document does not appear.
- `SIGKILL` and any hard kill bypass the handler entirely.

The practical consequence: **the absence of `shutting_down` is not a fault
signal.** A file frozen at `completed` may mean a cleanly stopped process or a
hard-killed one. Use freshness, as described below, rather than expecting this
state to show up.

## Findings are never written

The status file contains operational state only: a state name, timestamps, the
cycle counter, and a pass/fail verdict. It never contains findings, and never
contains the report.

This is deliberate, for three reasons:

1. **It keeps the channel cheap.** A supervisor polls this file on a timer,
   possibly many times per second across many machines. Parsing a full report —
   dozens of finding categories, severity levels, structured targets — to learn
   "still alive?" would be wasteful and would couple the supervisor to the
   report schema.

2. **It keeps the two concerns separate.** The report is the *auditable record*
   of what changed and what it means; the status file is the *operational
   signal* for process supervision. A liveness channel that also carried
   analysis output would force a supervisor to understand analysis semantics to
   remain correct, and would let findings leak into an area with no retention or
   schema policy.

3. **It keeps pressure toward one contract.** Because the status file only
   answers "alive?" and "verdict?", its schema stays tiny and stable. Adding
   findings to it would be a schema change to every supervising system for no
   supervisory value.

Full results are already available through the ordinary report outputs — text,
markdown, or `--output json:<path>` — and that is where findings belong.

## Polling for liveness

Because the file is replaced atomically and contains no partial state, a poller
needs no locking or read-then-retry logic: read it, interpret it, act.

A basic poll loop that prints each cycle's verdict:

```bash
while true; do
    if [ -f "$STATUS_FILE" ]; then
        jq -r '"cycle=\(.cycle) state=\(.state) safe=\(.is_safe) started=\(.started_at) finished=\(.finished_at)"' "$STATUS_FILE"
    else
        echo "status file not present yet"
    fi
    sleep 2
done
```

Interpretation:

| Observed | Meaning |
| --- | --- |
| File does not exist | The watcher has not written its first document yet — startup, argument parsing, and input loading all happen before the first write. In batch mode the first two documents (`running` then `completed`) are written back-to-back *after* the initial comparison finishes, so a poller may never observe `running` at all for cycle 1. |
| `state == "running"` | A cycle is in progress — the process is alive and working. Confirm progress by watching `cycle` advance between polls, or by observing `started_at` not grow stale. |
| `state == "completed"` | The last cycle finished at `finished_at` and produced verdict `is_safe`. A recent `finished_at` is the strongest liveness signal. |
| `state == "error"` | The last cycle failed at `finished_at`; print `error` for the reason. The watcher keeps running and will start the next cycle. |
| `state == "shutting_down"` | The process received `SIGTERM` on a unix host and is exiting; expect it to disappear shortly. This state will **not** appear for `Ctrl+C` or a hard kill, so its absence proves nothing — see [When `shutting_down` is written](#when-shutting_down-is-written). |

A supervisor that restarts a hung watcher can combine state and staleness
without special-casing the report:

```bash
LAST_CHANGE=0
while true; do
    if [ -f "$STATUS_FILE" ]; then
        MOD_TIME=$(stat -c %Y "$STATUS_FILE")
        STATE=$(jq -r .state "$STATUS_FILE")
        # Running cycles are expected to change the file each transition.
        # If nothing has changed for a long interval and the last state was
        # not a running cycle, treat the watcher as hung and restart it.
        if [ "$STATE" = "running" ]; then
            cycle=$(jq -r .cycle "$STATUS_FILE")
            echo "cycle $cycle in progress — healthy"
        elif [ "$MOD_TIME" -ne "$LAST_CHANGE" ]; then
            echo "completed/errored cycle observed — healthy"
        else
            echo "status unchanged since $LAST_CHANGE — restarting watcher"
            # kill and relaunch soroban-upgrade-safeguard ... --watch ...
        fi
        LAST_CHANGE=$MOD_TIME
    else
        echo "no status file — watcher not ready"
    fi
    sleep 10
done
```

Two practical notes for pollers:

- **Freshness beats state.** `state` alone does not prove liveness — a process
  can be wedged with a "healthy" last document sitting on disk. Track the file's
  change time (or `started_at`/`finished_at` in the document) and require it to
  advance within a deadline sized to how long a comparison cycle can legitimately
  take.
- **The status file is safe to place inside a watched directory, but not by
  special-casing.** The watcher's ignore list is built only from report output
  paths and `--per-contract-output-dir`; the status file is never added to it.
  What actually saves you is that a filesystem event is only acted on when it
  names a manifest source, a known input, or a `.wasm` file inside a scanned
  directory — a `status.json` is none of those, and the `.<name>.<pid>.tmp` file
  used for the atomic write is ignored as build junk. Read-only `Access` events
  are dropped for the same reason. The guarantee therefore depends on where you
  point the flag: do not aim it at a `.wasm` path, at a manifest, or at any other
  file the run actually reads, or the watcher will react to its own writes.

## Atomicity guarantees

The document is written to a temporary file in the same directory (named
`.<name>.<pid>.tmp` beside the target), flushed and fsynced, then moved into
place with `rename`. On a single filesystem, renaming over an existing path is
atomic:

- A reader always sees either the previous complete document or the new one —
  never a partial write.
- If writing the temporary file fails (disk full, permissions, interrupted
  process), the destination is left entirely untouched rather than truncated or
  corrupted; a concurrent reader keeps seeing the last good document.
- Each write starts from scratch, so the new document is fully self-contained:
  a reader that read the previous document never needs to re-read fields that
  may have changed.

See the [Watch mode](../README.md#watch-mode) section of the README for how
watch cycles are triggered, debounced, and rendered.
