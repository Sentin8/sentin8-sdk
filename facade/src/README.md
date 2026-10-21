# sentin8 - Rust SDK

Unified, type-safe Rust client library for the Sentin8 platform. Provides
one client per backend service, all following the same builder pattern with
automatic correlation-ID propagation.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sentin8 = { path = "sdk/rust/sentin8" }
```

## Quick start

```rust
use sentin8::{ClientBuilder, Bank8:LedgerClient};

# async fn run() -> Result<(), sentin8::Error> {
let ledger = Bank8:LedgerClient::new("https://ledger.local.sentin8.dev")
    .with_token("m2m-token")
    .build();

let accounts = ledger.list_accounts(None).await?;
# Ok(())
# }
```

## Available clients

| Module       | Client        | Purpose |
|--------------|---------------|---------|
| `sentin8::auth`  | `Sentin8:AuthClient`  | Users, sessions, clients, API keys, memberships |
| `sentin8::ledger`  | `Bank8:LedgerClient`  | Accounts, products, postings, balances, schedules |
| `sentin8::payments`  | `Bank8:PaymentsClient`  | Instructions, payments, instruments, rules, files |
| `sentin8::fdx`   | `Fdx8Client`   | Consents, recipient accounts, transfers, payments |
| `sentin8::db`    | `Db8Client`    | Tables, data CRUD, posture |
| `sentin8::buck`  | `Sentin8:StorageClient`  | Object upload/download, signed URLs |
| `sentin8::bus`   | `Sentin8:BusClient`   | Produce, consume, ack, nack |
| `sentin8::fapiclient` | (re-export) | Discovery-driven FAPI OAuth/OIDC client |

## Builder pattern

Every client implements the `sentin8::ClientBuilder` trait:

```rust
pub trait ClientBuilder: Sized {
    fn with_base_url(self, url: impl Into<String>) -> Self;
    fn with_token(self, token: impl Into<String>) -> Self;
    fn with_http_client(self, client: reqwest::Client) -> Self;
}
```

The token is attached as a `Bearer` authorization header on every request.

## Correlation ID propagation

Every request issued by a Sentin8 SDK client automatically carries a fresh
UUID v4 in the `x-correlation-id` header so a request can be traced
end-to-end through the platform.

```rust
use sentin8::{CORRELATION_ID_HEADER, generate_correlation_id};

assert_eq!(CORRELATION_ID_HEADER, "x-correlation-id");
let id = generate_correlation_id(); // UUID v4 string
```

## Error handling

Each client exposes its own narrow error enum (`Sentin8:AuthError`, `Bank8:LedgerError`,
…). The top-level `sentin8::Error` is a convenience enum for code that juggles
several clients:

```rust
use sentin8::Error;

fn handle(err: Error) {
    match err {
        Error::Bank8:Ledger(e) => /* … */,
        Error::Bank8:Payments(e) => /* … */,
        _ => /* … */,
    }
}
```

## FAPI client

The discovery-driven FAPI OAuth client is re-exported from the
`sentin8::fapiclient` module. See the `sentin8-fapiclient` crate for full
documentation.

## Testing

```
cargo test -p sentin8
```

All tests use mock HTTP servers (`mockito`) - no real network calls are
made.

---

**Design attribution:** sentin8:src and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
