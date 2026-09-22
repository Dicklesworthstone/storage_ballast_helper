# Diagnostic storms must not exhaust the reclaim daemon

All clones of an `ActivityLoggerHandle` now share producer-side admission for
`Info`, `Warning`, and `Error` messages. Admission runs before the bounded event
channel, so a repeated diagnostic cannot occupy the queue with thousands of
copies while cleanup evidence waits behind it.

Within each sixty-second window, a normalized message template may emit three
examples. Each severity separately admits at most 64 diagnostics in that window.
An informational storm does not consume the error or warning quota. Changing
path tokens and numeric observations are normalized; the stable error code and
surrounding message words remain part of the key. The severity ceiling also
bounds high-cardinality messages that normalization cannot coalesce. At most
192 template entries are retained, with bounded Unicode-safe key lengths.

Admission uses a nonblocking lock attempt. Contention suppresses only operational
diagnostics and is counted explicitly; senders never wait for this lock or for
backend I/O. This is best-effort diagnostic delivery, not a guarantee that every
new failure is printed during a storm.

## Preserve evidence and account for suppression

Only the three diagnostic variants above are limited. Successful AND failed
deletion attempts, decision records, regret outcomes, ballast operations, pressure
changes, policy transitions, scan completions, lifecycle/config events, and
explicit emergency events are not filtered. Audit events retain the existing
bounded-channel back-pressure behavior; they are not promised lossless delivery.
No deletion count or reclaimed-byte statistic is synthesized from a summary.

The consumer emits `SBH-LOG-THROTTLED` through the existing JSONL/SQLite write
path. Its JSON `details` object contains `kind: diagnostic_throttle`, elapsed
seconds, per-severity suppressed counts, contention counts, and bounded sample
templates. Reports are checked on the idle heartbeat too, so no new producer
message is required. Shutdown and final-sender disconnect flush a partial
window before backend flush/fsync. Reports bypass admission and never recurse
through the event channel. Counts survive quota-window rotation until reported.

`handle.suppressed_diagnostics()` is a cumulative shared suppression counter.
It is separate from `handle.dropped_events()`, which still measures transport
back-pressure. Transport-loss warnings are also paced to one per minute, plus
a final shutdown report, instead of adding a warning for every received event
while the channel is overloaded.

## Scope and validation

This addresses structured diagnostic growth in the message-throttling portion
of `bd-1ar1`, complementing the active-log retry cooldown. Direct `eprintln!`
call sites and external service-manager logs are outside this admission path.
It does not establish the bead's sixty-minute production log-growth criterion.
The existing audit, rotation, fallback, and safety policies are unchanged.

Tests beside the admission code cover changing paths, severity isolation,
capacity, exact suppression accounting, expiry, delayed/forced reports, lock
contention, cloned producers, schema-valid JSONL, SQLite summaries, preservation
of failed-deletion audit rows, emergency events, and sender-disconnect flushing.
