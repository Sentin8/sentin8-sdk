# sentin8-sdk - The Sentin8 Shared Library Workspace (SDD §2.1)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://sentin8.dev/docs/services/sdk)
[![Website](https://img.shields.io/badge/website-sentin8.dev-1a73e8.svg)](https://sentin8.dev)

## Summary

One cargo workspace holding the platform's shared-plane crates: the core
layer (errors, crypto, config, build-info, idempotency, registration, rfw,
openapi, middleware, service-discovery), the identity layer (jwt, fapi,
m2m, auth-client), the TLS plane, the bus plane (contracts, client, membus,
outbox), the Shield policy engine, the service shell + audit, and the
`sentin8` facade. Every platform and vertical repo consumes it as a single
pinned git dependency (`tag = "sdk-vX.Y.Z"`).

Service-scoped SDK crates (`{svc}-client`/`{svc}-contracts`) do **not**
live here - each lives in its owning service repo behind a per-service
mini-facade (`sdk/` directory, package `sentin8-{svc}-sdk`). The
stay/move boundary is shared-plane linkage: a crate stays in the SDK iff
some shared-plane crate links it (`shell` links `auth-client`,
`bus-client`, `outbox`; `shield` links `auth-client`, `m2m`, the bus
plane; `middleware` links `tls`).

## Motivation

- **One-repo dev story**: a service team clones one repo and builds - the
  SDK arrives as a pinned git dependency; no platform checkout, no live
  database (committed `.sqlx` caches).
- **No dependency-direction defects**: the shared plane links no
  service-scoped client. Telemetry (policy decisions, service metrics)
  publishes through MemBus (`stat:telemetry` Pub/Sub family) instead of an
  HTTP stat client - the `{leaf}-policy` M2M workloads are gone. A
  service's recurring internal work is declared at enroll time
  (`schedules` registration section) or runs on an internal timer - never
  via boot-time cross-service self-registration.
- **Compile-scope honesty**: the facade re-exports only the shared plane;
  a consumer compiles the service SDKs it actually pins, nothing more.
- **No legacy naming**: no hand-rolled facade clients, no stale module
  aliases, vendor names only in the manifest mapping (Shield is the
  engine's only name).

## Architecture & High-Level Design

```mermaid
graph TD
    subgraph CORE["core layer (L0/L1)"]
        ERR[errors] --- CRY[crypto]
        CFG[config]
        BLD[build-info]
        IDE[idempotency]
        REG[registration]
        RFW[rfw]
        OAS[openapi]
        MW[middleware]
        SD[service-discovery]
    end
    subgraph ID["identity layer (L2)"]
        JWT[jwt]
        FAPI[fapi]
        AUTHC[auth-client]
        M2M[m2m]
    end
    subgraph TLS["tls plane (L3)"]
        TLS[tls]
        TLSC[tls-contracts]
    end
    subgraph BUS["bus plane (L3/L4)"]
        BC[bus-contracts]
        BC2[bus-client]
        MB[membus]
        OBX[outbox]
    end
    SHIELD[shield engine]
    subgraph SHELL["shell + audit"]
        SH[shell]
        AU[audit]
    end
    FAC[facade sentin8]
    CORE --> ID
    ID --> TLS
    CORE --> BUS
    ID --> BUS
    CORE --> SHIELD
    ID --> SHIELD
    TLS --> SHIELD
    BUS --> SHIELD
    CORE --> SHELL
    ID --> SHELL
    TLS --> SHELL
    SHIELD --> SHELL
    SHELL --> FAC
    SHIELD --> FAC
    CORE --> FAC
    ID --> FAC
    TLS --> FAC
    BUS --> FAC
    STATTEL[stat telemetry<br/>via membus] -.->|publish_pubsub| MB
```

**What is deliberately NOT here**: service binaries, service-scoped
HTTP clients/contracts (`{svc}-client`/`{svc}-contracts` - owner repos),
registration files (each repo ships its own), vertical knowledge of any
kind.

## Key Traits and Data Structures

- `Sentin8Config` (`core/config`): the single source of truth for runtime
  derivation - every domain/URL derives from `SENTIN8_DOMAIN`; Valkey and
  Bus URLs, pool caps (`pg_pool`).
  `sentin8_config::pg_pool::connect` is the fleet's ONE PostgreSQL
  connection factory: it enforces the pool cap AND the certificate-
  identity TLS plane (group DESIGN.md §3.2 - `sslmode=verify-full`
  against the published Acme CA chain, the workload's m2m client pair,
  and a hard rejection of password-bearing DSNs; there are no database
  passwords anywhere).
- `Registration` + `ScheduleDecl` + `EventTriggerDecl`
  (`core/registration`): the declarative self-description surface a
  service emits via `--print-registration`; `schedules` provisions
  `cron.schedules` at enroll time.
- `shield` (`sentin8-shield`): the declarative policy engine (RBAC + ABAC
  + ReBAC). Decision events and service metrics publish to MemBus
  (`stat.telemetry`), fire-and-forget, log-only on failure.
- `shell` (`sentin8-shell`): the canonical boot sequence (10 steps) every
  service runs - TLS acceptor, auth client, Shield boot, outbox relay,
  audit push loop.
- `membus` (`sentin8-membus`): embedded Valkey client for MemBus
  Pub/Sub (ephemeral, newest-wins - telemetry class) and Streams
  (durable, consumer groups). No HTTP, no auth - tenant isolation by key
  derivation.
- facade `sentin8`: `use sentin8::…` for the shared plane only
  (`sentin8::shell`, `sentin8::shield`, `sentin8::auth::…`,
  `sentin8::tls::…`, `sentin8::bus::…`).

## Rationale, Trade-offs, and Alternatives

- **Why one workspace, not per-crate repos**: the facade depends on every
  shared crate; a whole-workspace tag keeps one version ring and one pin.
  Alternative - per-crate repos with independent semver - rejected: pin
  combinatorics across 90 consumer repos, no atomic cross-layer change.
- **Why service crates moved out (SDD)**: the facade-for-all pin made
  every repo compile all 40 crates; contract changes spun the global ring
  for repos that never imported them. Owner-repo hosting gives per-service
  version rings and honest compile scope. Rejected alternative -
  feature-gated facade - keeps one ring and a facade that *knows about*
  services (SDD §2 placement discussion).
- **Why MemBus for telemetry**: the shared plane cannot link a
  service-scoped client without inverting the DAG; telemetry is
  fire-and-forget by contract (loss on outage is acceptable -
  "non-important updates"), so the ephemeral Pub/Sub class fits exactly.
  Rejected - durable Streams for telemetry - would impose DLQ/retry
  semantics on a loss-tolerant class and hold unbounded stream entries.
- **Why boot-time self-registration was removed**: acme (tier 1) and auth
  (tier 2) registered cron schedules before cron (tier 4) existed - the
  registration could only ever land on the next boot; and a root service
  depending on cron inverts the dependency pyramid (everything depends on
  auth; auth must not depend on anything tier-4).
- **Dispatching**: MemBus uses Valkey GLIDE's typed client surface with a
  dedicated pub/sub connection for subscribers - the connection invariant
  documented in membus DESIGN.
- **Concurrency**: shield's telemetry emitter is a `OnceLock`-held client
  replaced by a `OnceLock`-held `EnvBus` publish path - same
  init-once-then-fire pattern, no locks on the emit path.

## Internal Implementation & Invariants (Private Design)

- **** - crate placement by shared-plane linkage, not naming.
  `auth-client` stays (shell/shield link it); `bus-client`/`outbox`/
  `bus-contracts` stay (shell links them). If a future shared-plane crate
  needs a service client, that is a design defect - publish a domain
  event or MemBus frame instead.
- **** - the facade never re-exports a mini-facade (would invert the
  DAG - the SDK repo would pin service repos).
- **Envelope discipline** (membus): tenant identity is a property of the
  key (`mbus:{env}:…` / `mchan:{env}:…`), never of the payload.
- **sqlx offline**: the workspace carries a committed `.sqlx/` cache;
  consumer builds need no live PG.

## Unresolved Questions / Future Designs

- CI pin-freshness automation for per-service `{svc}-sdk-vX.Y.Z` tags -
  aggregation-CI territory (SDD §7).
- Whether `membus` gains a frame-schema registry for payload validation
  at decode time - deferred until more families exist.

---

**Architecture & Design:** sentin8 and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
