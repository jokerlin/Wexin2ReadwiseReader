# WeChat KF Concurrent Callback Idempotency Design

Date: 2026-07-27

## Context

The webhook processor currently performs these steps without a shared lock:

1. Read the `open_kfid` cursor from Upstash KV.
2. Call WeChat `sync_msg`.
3. Save the latest link message to Readwise Reader.
4. Persist the next cursor.

Vercel may run webhook callbacks concurrently, and WeChat may retry a callback
before an earlier invocation finishes. Those invocations can read the same
cursor, receive the same `msgid`, and submit the same link to Readwise at the
same time. Cursor storage preserves ordering only after a request completes; it
does not make the read-process-write sequence atomic.

The current processor also logs KV and Readwise write failures and returns
success. This can either replay an already-saved message or advance past a
message that Readwise did not save.

## Goals

- Process at most one synchronization request at a time for each `open_kfid`.
- Suppress duplicate Readwise saves for the same WeChat `msgid` when callbacks
  overlap or retry after completed processing.
- Permit the same URL to be saved again when it arrives in a new WeChat message
  with a different `msgid`.
- Preserve retry behavior when WeChat, Readwise, or KV fails.
- Keep the existing behavior of inspecting only the last message returned by
  `sync_msg`.

## Non-goals

- Processing every message or every pagination page returned by `sync_msg`.
- Canonicalizing WeChat article URLs.
- Deleting duplicate documents that already exist in Readwise.
- Introducing a background queue or a new external service.
- Providing strict exactly-once delivery across a crash between the Readwise
  response and the processed-message KV write. Readwise and KV do not share a
  transaction, so that guarantee is not possible without downstream
  idempotency support.

## Selected Approach

Use an Upstash-backed distributed lock per `open_kfid`, plus a processed-message
marker per `msgid`.

The lock serializes the entire cursor read, message synchronization, Readwise
save, processed-message write, and cursor write sequence across Vercel
instances. The marker provides a second defense when Readwise succeeds but a
later cursor write fails and the message is fetched again.

Alternatives rejected:

- A process-local mutex cannot coordinate separate Vercel instances.
- A `msgid` claim without stream-level locking lets a losing request advance
  the cursor while the winning request is still saving, which can lose a
  message when the winning request fails.
- A queue would provide stronger orchestration but adds unnecessary operational
  scope for the current workload.

## Components

### KV client

Add narrowly scoped operations to `internal/kv`:

- `AcquireLock(ctx, key, owner, ttl) (bool, error)` issues atomic
  `SET key owner NX EX seconds`.
- `ReleaseLock(ctx, key, owner) error` uses a short Lua compare-and-delete
  script so an expired lock cannot be deleted by its former owner after another
  invocation acquires it.
- `SetWithTTL(ctx, key, value, ttl) error` stores processed-message markers with
  bounded retention.

The existing `Get` and `Set` operations remain responsible for cursor and
marker reads and cursor writes.

### Processor

Express the WeChat, KV, and Readwise dependencies as small internal interfaces.
`NewProcessor` continues to construct the existing concrete clients, while
tests can inject deterministic fakes.

For each payload:

1. Parse `Token` and `OpenKfId`.
2. Require a configured KV client; idempotent processing cannot be guaranteed
   without it.
3. Generate a cryptographically random lock-owner value.
4. Acquire `wechat_kf_sync_lock:<open_kfid>` with a 15-second TTL.
5. If the lock is busy, return a typed retryable error without reading messages
   or changing the cursor.
6. After acquiring the lock, read the cursor. A KV read failure is fatal.
7. Fetch the access token and call `sync_msg`.
8. For the last returned link message:
   - Require a non-empty `msgid`.
   - Read
     `wechat_kf_processed:<open_kfid>:<msgid>`.
   - If the marker exists, skip Readwise.
   - Otherwise call Readwise. On success, write the marker with a seven-day
     TTL. Readwise or marker-write failure is fatal.
9. Persist `next_cursor`. A cursor-write failure is fatal.
10. Release the lock in a deferred cleanup. A release failure is logged because
    the TTL still bounds the lock; it does not turn an otherwise successful
    synchronization into a callback failure.

The lock TTL exceeds the handler's ten-second processing deadline while
remaining short enough for automatic recovery if an invocation exits without
cleanup.

### Handler

The handler continues to map processor failures to HTTP 500. In particular, a
busy lock produces a retryable response so a callback for a newly arrived
message is not acknowledged before another invocation has necessarily observed
that message.

## Storage Keys

- Cursor: `wechat_kf_cursor:<open_kfid>`
- Lock: `wechat_kf_sync_lock:<open_kfid>`
- Processed message:
  `wechat_kf_processed:<open_kfid>:<msgid>`

When `OpenKfId` is empty, use the existing `default` suffix consistently for
all three key types.

## Error and Delivery Semantics

- No KV configuration: fail closed; do not call Readwise.
- Lock busy: return a retryable error; do not read or write cursor state.
- KV read failure: return an error; do not synchronize from an empty cursor.
- Readwise failure: return an error; do not write the processed marker or
  advance the cursor.
- Processed-marker failure after Readwise success: return an error; do not
  advance the cursor. A later sequential retry may call Readwise again, but
  this preserves at-least-once delivery rather than silently losing the
  article.
- Cursor failure after marker success: return an error. The retry sees the
  marker, skips Readwise, and retries the cursor write.
- Lock release failure: log it and rely on the 15-second TTL.

## Testing

Add table-driven and concurrency-focused tests adjacent to the affected code.

### KV client tests

Using `httptest.Server`, verify:

- Lock acquisition sends `SET ... NX EX ...` and distinguishes acquired from
  busy responses.
- Lock release sends the compare-and-delete Lua command.
- Processed-message writes include the expected TTL.
- API and malformed-response errors are propagated.

### Processor tests

Using deterministic fakes, verify:

- Two simultaneous calls for the same `open_kfid` and `msgid` cause exactly one
  Readwise save.
- A busy lock does not call WeChat sync, Readwise, or cursor mutation.
- A pre-existing processed marker skips Readwise and still advances the cursor.
- A cursor-write failure after a successful marker write can be retried without
  a second Readwise save.
- KV read, Readwise save, marker write, and cursor write failures are returned.
- The same URL in two different `msgid` values is eligible for two saves.

Run the complete Go test suite, the race detector, formatting, and a full build
before completion.
