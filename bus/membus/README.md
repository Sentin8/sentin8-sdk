# Design Doc: sentin8-membus (In-Process Memory Bus Library)

## 1. Summary

`sentin8-membus` is an ultra-low-latency, library-only event bus for
latency-critical services. It is **not a service**: no HTTP server, no
ports, no per-message JWT verification, no inbox relay. Services embed the
crate and talk RESP directly to Valkey over a plaintext `valkey://`
connection, using two delivery classes — durable (Valkey Streams +
consumer groups) and ephemeral (Valkey Pub/Sub).

## 2. Motivation

The platform control-plane bus (Sentin8:Bus) is durable and audited but
carries HTTP authentication, JWT verification, and inbox persistence on
every message — orders of magnitude too slow for tick-level traffic. Realtime
services need a *fast plane*: microsecond publish latency, newest-wins
ephemeral delivery for state refresh, and durable-at-least-once streams for
event replay — without a network hop through a broker service.

The two-plane split also defines the trust boundary: MemBus runs **inside**
a service process over an internal network path to Valkey; the control
plane handles anything crossing tenant or service boundaries.

## 3. Architecture & High-Level Design

```mermaid
graph TD
    subgraph Service process
        A[ServiceBus — fail-soft composition] --> B[MemBus handle]
        B --> C[EnvBus — tenant-bound handle]
    end
    C -->|XADD MAXLEN ~ / XREADGROUP / XACK / XAUTOCLAIM| D[(Valkey Stream mbus:{env}:{family})]
    C -->|PUBLISH / SUBSCRIBE| E[(Valkey Pub/Sub mchan:{env}:{family})]
    F[Consumer group] --> D
```

Components:

- **`MemBus`** — the process-wide handle: one shared multiplexed command
  connection for all non-blocking commands, plus a connection factory for
  subscribers. Constructed once per process via `MemBus::connect`
  (PINGs once; fails fast when Valkey is unreachable).
- **`EnvBus`** — a tenant-bound handle from `MemBus::for_env(env_id)`. All
  keys derive from the bound env id: `mbus:{env}:{family}` (streams) and
  `mchan:{env}:{family}` (channels).
- **`ServiceBus`** — the adopter-facing composition helper that encodes the
  fail-soft policy once: empty URL disables silently; unreachable Valkey or
  bad env id disables with a WARN; **never an `Err`** — MemBus is a hot-path
  accelerator, never a startup dependency.
- **`Envelope`** — one flat RESP field envelope for both classes (§4).
- **`StreamSubscriber` / `PubSubscriber`** — the two consumer types, each
  owning a dedicated connection.
- **`validate`** — key-component validation before interpolation.
- **`hooks`** — optional sampled metrics sink (default no-op).

Delivery classes:

| Class  | Primitive                | Persistence | Loss semantics            |
|--------|--------------------------|-------------|---------------------------|
| Durable| `XADD` + consumer groups | Stream, trimmed | At-least-once (PEL + XAUTOCLAIM) |
| Ephemeral | `PUBLISH`/`SUBSCRIBE` | None        | Newest-wins; unsubscribed messages are gone by contract |

## 4. Key Traits and Data Structures

- **`Envelope`** — flat field-value pairs, RESP-native, no nested JSON, no
  `HashMap` allocation on parse. Wire order: `et` (event type, platform
  colon convention), `ts` (unix micros), `cid` (correlation id), `by`
  (producer), `sq` (per-(service, family) sequence), `p` (opaque payload
  bytes). **No `env_id` and no publisher token inside the message** —
  tenant identity is a property of the *key*, never the payload.
- **`MemBusConfig`** — Valkey URL (`valkey://`; TLS schemes rejected),
  producer service name, trim target, metrics hooks.
- **`EnvBus`** — publish side: `publish_stream` (XADD with mandatory
  approximate trim), `publish_stream_many` (pipelined), `publish_pubsub`
  (PUBLISH of the binary frame); subscribe side:
  `subscribe_stream(family, group)` and `subscribe_pubsub(family)`.
- **`StreamOpts`** — consumer tuning knobs (`count`, `block_ms`).
- **`StreamMessage`** — delivered entry: Valkey id + decoded envelope.
- **`MetricsHooks`** — sampled metrics sink: `on_publish`, `on_batch`,
  `on_gap` (sequence gaps distinguish trim-loss from real drops),
  `on_reconnect`. Default `NoopMetrics` has zero hot-path cost.
- **`MemBusError`** — every failure surfaces immediately to the caller:
  MemBus never queues and never retries internally.

## 5. Rationale, Trade-offs, and Alternatives

- **Library, not a service.** A broker service would add one HTTP hop and a
  serialization boundary on the hottest path in the platform. The trade-off
  is that every consumer links the crate and speaks Valkey RESP directly —
  accepted because the target adopters are Rust services already using the
  shared shell.
- **Blocking reads on dedicated connections (structural invariant).**
  Blocking subscribers NEVER share the multiplexed command connection.
  This is made structural: every subscriber owns a dedicated connection for
  its lifetime, so a consumer blocking in `XREADGROUP … BLOCK` or in
  `SUBSCRIBE` cannot stall anyone else's `XADD`/`XACK`/`PUBLISH`. Rejected
  alternative: one multiplexed connection for everything (would deadlock
  under a slow consumer).
- **Mandatory `MAXLEN ~` trim.** Untrimmed streams grow until Valkey's
  `maxmemory` evicts arbitrary keys; an approximate trim target per family
  keeps a bounded-memory Valkey survivable under hot-loop publish rates.
- **Library-owned `XAUTOCLAIM` sweep** (every ~5 s, min-idle 60 s, COUNT 20)
  for crash recovery: entries abandoned by a crashed sibling of the same
  consumer group are re-delivered without each adopter implementing PEL
  recovery. At-least-once + consumer-side dedupe on `sq` yields
  effectively-once.
- **Fail-soft `ServiceBus::connect`.** A realtime service must boot even
  with Valkey down; MemBus is an accelerator, so connection failures disable
  publishing (WARN) instead of failing startup. The cost is silent data loss
  on a degraded bus — accepted because the durable record of record lives in
  the service's own database/journal, not on the fast plane.
- **TLS-only certificate identity (group DESIGN.md §3.1).** MemBus
  connects via the SDK's cert-presenting GLIDE factory, which REQUIRES
  the `valkeys://` scheme — the Valkey data plane has no plaintext
  listener, and every connection presents the workload's Acme-issued
  m2m pair (the CN maps to the enroll-provisioned ACL user of the same
  name). A plaintext URL is a configuration error surfaced at connect
  time — never a silent downgrade.
- **Flat binary frames for pub/sub.** The ephemeral hot path skips serde
  entirely: a little-endian length-prefixed field walk with zero
  intermediate allocations. Decode errors are lenient (unknown fields
  skipped) for forward compatibility, and a truncated frame never decodes to
  a *wrong* sequence number.

## 6. Internal Implementation & Invariants (Private Design)

- **Connection split.** `MemBus.cmd` is a `ConnectionManager` used only for
  non-blocking commands (XADD, XACK, PUBLISH, PING, XGROUP). Every
  subscriber opens its own multiplexed (or pub/sub) connection and holds it
  for its lifetime.
- **Tenant binding.** `for_env` accepts only a UUID env id (rejected
  outright otherwise — no silent fallback to a system env); the key
  namespace is derived once at bind time and there is no API to cross
  tenants on one handle.
- **Sequence assignment.** Per-(service, family) monotonic `sq` counters
  are assigned at publish time by the library (`fetch_add` + 1, so the
  first message is 1 and gap detection is the natural "expected = last +
  1"). The map is write-once per family and race-safe under the mutex.
- **Group creation.** `subscribe_stream` creates the consumer group (`$`,
  MKSTREAM) if absent; `BUSYGROUP` is treated as success. Consequently a
  new group only sees entries published after subscription —
  subscribe-then-publish for fresh groups.
- **Ack coalescing.** Delivered ids accumulate in `unacked` and flush with
  the next `next_batch()` (before the blocking read, so ack latency never
  rides on the next message) or via `ack_now()`.
- **Undecodable entries** are acked and skipped: the fast plane has no DLQ;
  the durable record of record is the producer's own persistence.
- **Connect bounding.** Both `MemBus::connect` and `ServiceBus::connect`
  bound the handshake (2 s) — `ConnectionManager` retries indefinitely by
  default, which would hang a realtime service's startup on a dead endpoint.
- **Bench gate.** The `bench` example enforces the latency budget:
  stream publish P50 ≤ 200 µs and pub/sub end-to-end P50 ≤ 500 µs against
  the live Valkey, exiting non-zero on failure.

## 7. Unresolved Questions / Future Designs

- Sequence gaps (`on_gap`) are observable but not yet acted upon: trim loss
  and real drops are distinguished only at the metrics sink.
- Cross-instance sequence continuity is per-process; a restarted service
  restarts its `sq` from 1. Consumers relying on strict gap detection
  across restarts must treat it as producer identity + monotonic-within-run.
- The metrics sampling implementation (wiring `MetricsHooks` into
  Sentin8:Stat at ~1/1024 messages) is an adopter concern, not provided by
  the library.

---

**Design attribution:** sentin8:membus and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
