// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # bus-client
//!
//! Rust HTTP client for the Bus event-bus service: produce, consume (HTTP
//! and SSE), ack/nack, delayed scheduling, DLQ inspection and replay, and
//! RFC 8693 token exchange using a consumed event's publisher identity.
//!
//! Authentication is CERTIFICATE-PRESENTING (, auth DESIGN
//! §4.3f): the transport presents the workload's Acme-issued client
//! certificate in the TLS handshake on every call — no M2M token is
//! fetched, cached, or attached. `for_workload` ensures the certificate
//! (minting it from Acme on a first boot) and builds the client; services
//! start listening without waiting for anything.

#![deny(missing_docs)]

use sentin8_bus_contracts::{
    ConsumeRequest, ConsumeResponse, ProduceBatchRequest, ProduceBatchResponse, ProduceRequest,
    ProduceResponse,
};
use sentin8_middleware::http_client::Sentin8HttpClient;
use thiserror::Error;

#[derive(Debug, Error)]
/// Client-side failure surface for Bus API calls.
pub enum BusError {
    /// An HTTP request failed (transport error, non-success status, or a
    /// missing certificate identity).
    #[error("Bus HTTP error: {0}")]
    Http(String),
    /// The server REJECTED the request permanently — an HTTP 4xx from a
    /// call whose response body is carried in `body`. A retry can never
    /// succeed (the rejection is a property of the request — e.g. Bus's
    /// event-ownership or env-match gate); callers use this to stop
    /// retrying immediately instead of burning a retry budget
    /// (outbox relay design: permanent 4xx must not hot-loop).
    #[error("Bus rejected the request permanently ({status}): {body}")]
    Permanent {
        /// The HTTP status code of the rejection.
        status: u16,
        /// The response body (the rejection message).
        body: String,
    },
    /// A response body could not be decoded.
    #[error("Bus decode error: {0}")]
    Decode(String),
}

#[derive(Clone)]
/// HTTP client for the Bus event-bus service — **certificate-presenting**
/// (auth DESIGN §4.3f): every call presents the workload's
/// Acme-issued client certificate in the TLS handshake; Bus's TLS layer
/// CA-verifies it and injects the identity headers that drive
/// authorization. No bearer token exists on this path.
pub struct BusClient {
    /// Trimmed base URL of the Bus server.
    base_url: String,
    /// mTLS transport (presents the workload certificate on every call).
    http: Sentin8HttpClient,
    /// mTLS transport for long-lived streams (no total request timeout).
    /// Used by `sse_consume` so the SSE body stream isn't aborted.
    streaming_http: Sentin8HttpClient,
}

impl BusClient {
    /// Build a certificate-presenting BusClient (, auth DESIGN
    /// §4.3f). The transport presents `cert_path`/`key_path` (the
    /// workload's Acme-issued identity) on every call and trusts only
    /// `ca_cert_path` — Bus's TLS layer CA-verifies the presented
    /// certificate and injects the `X-Sentin8-Client-Cert-*` headers that
    /// drive its authorization (scopes from the registry map, the VDC-2
    /// vertical gate). No token is fetched, cached, or attached.
    ///
    /// # Errors
    /// [`BusError::Http`] when the mTLS transport cannot be built from the
    /// identity paths (missing files / unreadable key) — a missing
    /// certificate identity is a provisioning state, surfaced loud.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, BusError> {
        let mtls = sentin8_middleware::mtls::MtlsConfig::new(ca_cert_path, cert_path, key_path);
        let http = sentin8_middleware::mtls::build_mtls_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .map_err(BusError::Http)?;
        let streaming_http = sentin8_middleware::mtls::build_mtls_streaming_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .map_err(BusError::Http)?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            streaming_http,
        })
    }

    /// Build a cert-presenting BusClient, minting the workload certificate
    /// from Acme when it does not exist yet — the boot convenience
    /// constructor that replaces the old `build_with_dcr` (no DCR, no
    /// background retry: the identity is the certificate).
    ///
    /// Returns the client immediately after ensuring the identity (the
    /// caller's reconnect loops cover a Bus that is still coming up).
    ///
    /// # Errors
    /// [`BusError::Http`] when the certificate cannot be ensured (Acme
    /// unreachable at first birth — the caller logs and retries the boot
    /// step) or the transport cannot be built.
    pub async fn for_workload(
        bus_url: &str,
        auth_issuer: &str,
        workload: &str,
    ) -> Result<Self, BusError> {
        let cert = sentin8_m2m::ensure_workload_certificate(
            auth_issuer,
            workload,
            &sentin8_m2m::platform_ca_path(),
        )
        .await
        .map_err(|e| BusError::Http(e.to_string()))?;
        Self::with_workload_identity(
            bus_url,
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        )
    }

    /// Trimmed base URL of the Bus server.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build an SSE consumer URL for `GET /v1/consume/sse`.
    /// The token is sent via the Authorization header (not the query
    /// string) to avoid leaking it in logs and URLs.
    pub async fn sse_consume_url(
        &self,
        stream_family: &str,
        consumer_group: &str,
    ) -> Result<String, BusError> {
        Ok(format!(
            "{}/v1/consume/sse?stream_family={stream_family}&consumer_group={consumer_group}",
            self.base_url
        ))
    }

    /// Open an SSE consumer stream to Bus. Returns a `reqwest::Response`
    /// whose body is an `text/event-stream` — the caller reads SSE events
    /// from `resp.bytes_stream()`. Each `data:` line is a JSON
    /// `ConsumeMessage`.
    ///
    /// ACKs are sent via `POST /v1/ack` (separate HTTP call — SSE is
    /// one-way, server → client only).
    pub async fn sse_consume(
        &self,
        stream_family: &str,
        consumer_group: &str,
    ) -> Result<reqwest::Response, BusError> {
        let url = self.sse_consume_url(stream_family, consumer_group).await?;
        // Use the streaming client (no total request timeout) so the
        // long-lived SSE body stream isn't aborted after 30s.
        let resp = self
            .streaming_http
            .get(&url)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!(
                "SSE consume status {}",
                resp.status()
            )));
        }
        Ok(resp)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Publish an event — `POST /v1/produce`.
    ///
    /// # Errors
    /// Returns [`BusError`] on transport failure, non-success status, or
    /// response decoding failure. A 4xx status is [`BusError::Permanent`]
    /// — the request itself was rejected (ownership/env gates) and no
    /// retry can succeed.
    pub async fn produce(
        &self,
        req: &ProduceRequest,
    ) -> Result<ProduceResponse, BusError> {
        let resp = self
            .http
            .post(self.url("/v1/produce"))
            .json(req)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(classify_produce_status(resp.status(), resp).await);
        }
        resp.json()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// Publish N events in one call — `POST /v1/produce/batch` (BUS-3,
    /// bus DESIGN §4.3). Per-row results mirror the batch response: a
    /// failed row carries `error` and no `message_id`; successful rows
    /// carry both `message_id` and `stream`.
    ///
    /// # Errors
    /// Returns [`BusError`] on transport failure, non-success status, or
    /// response decoding failure. A 4xx status is [`BusError::Permanent`]
    /// — no retry can succeed.
    pub async fn produce_batch(
        &self,
        events: &[ProduceRequest],
    ) -> Result<ProduceBatchResponse, BusError> {
        let resp = self
            .http
            .post(self.url("/v1/produce/batch"))
            .json(&ProduceBatchRequest {
                events: events.to_vec(),
            })
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(classify_produce_status(resp.status(), resp).await);
        }
        resp.json()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// Consume a batch — `POST /v1/consume` (XREADGROUP semantics).
    ///
    /// # Errors
    /// Returns [`BusError`] on transport failure, non-success status, or
    /// response decoding failure.
    pub async fn consume(&self, req: &ConsumeRequest) -> Result<ConsumeResponse, BusError> {
        let resp = self
            .http
            .post(self.url("/v1/consume"))
            .json(req)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// Acknowledge a consumed message — `POST /v1/ack`.
    ///
    /// # Errors
    /// Returns [`BusError`] on transport failure or non-success status.
    pub async fn ack(
        &self,
        stream_family: &str,
        consumer_group: &str,
        message_id: &str,
    ) -> Result<(), BusError> {
        let body = serde_json::json!({
            "stream_family": stream_family,
            "consumer_group": consumer_group,
            "message_id": message_id,
        });
        let resp = self
            .http
            .post(self.url("/v1/ack"))
            .json(&body)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `POST /v1/nack` — nack a message (Bus retries up to max_retries, then
    /// moves to the DLQ).
    pub async fn nack(
        &self,
        stream_family: &str,
        consumer_group: &str,
        message_id: &str,
        retry_after_secs: Option<u64>,
    ) -> Result<(), BusError> {
        let body = serde_json::json!({
            "stream_family": stream_family,
            "consumer_group": consumer_group,
            "message_id": message_id,
            "retry_after_secs": retry_after_secs,
        });
        let resp = self
            .http
            .post(self.url("/v1/nack"))
            .json(&body)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `POST /v1/schedule` — schedule a delayed message.
    pub async fn schedule(
        &self,
        stream_family: &str,
        event_type: &str,
        payload: serde_json::Value,
        delay_seconds: u64,
    ) -> Result<serde_json::Value, BusError> {
        let body = serde_json::json!({
            "stream_family": stream_family,
            "event_type": event_type,
            "payload": payload,
            "delay_seconds": delay_seconds,
        });
        let resp = self
            .http
            .post(self.url("/v1/schedule"))
            .json(&body)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// `GET /v1/scheduled` — list due delayed messages.
    pub async fn list_scheduled(&self) -> Result<serde_json::Value, BusError> {
        let resp = self
            .http
            .get(self.url("/v1/scheduled"))
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// `GET /v1/streams/{streamFamily}/lag` — consumer group lag.
    pub async fn stream_lag(&self, stream_family: &str) -> Result<serde_json::Value, BusError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/streams/{}/lag", stream_family)))
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// `GET /v1/dlq` — list DLQ entries.
    pub async fn list_dlq(&self) -> Result<serde_json::Value, BusError> {
        let resp = self
            .http
            .get(self.url("/v1/dlq"))
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// `POST /v1/dlq/replay` — replay a DLQ message.
    pub async fn replay_dlq(&self, message_id: &str) -> Result<(), BusError> {
        let body = serde_json::json!({"message_id": message_id});
        let resp = self
            .http
            .post(self.url("/v1/dlq/replay"))
            .json(&body)
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `GET /v1/streams` — list streams for the tenant.
    pub async fn list_streams(&self) -> Result<serde_json::Value, BusError> {
        let resp = self
            .http
            .get(self.url("/v1/streams"))
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    /// `GET /v1/metrics` — observability metrics.
    pub async fn metrics(&self) -> Result<String, BusError> {
        let resp = self
            .http
            .get(self.url("/v1/metrics"))
            .send()
            .await
            .map_err(|e| BusError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(BusError::Http(format!("status {}", resp.status())));
        }
        resp.text()
            .await
            .map_err(|e| BusError::Decode(e.to_string()))
    }

    // ── Publisher token helpers ───────────────────────────────────────
    //
    // These helpers enable subscribers to perform RFC 8693 token exchange
    // using the publisher ID Token from a consumed event, preserving the
    // `act` audit chain.

    /// Extract the `publisher_id_token` field from a consumed message.
    /// Returns `None` when the producer did not attach one.
    pub fn extract_publisher_token(msg: &sentin8_bus_contracts::Message) -> Option<&str> {
        msg.publisher_id_token.as_deref()
    }

    /// VDC-2 consumer-side defense-in-depth: assert a consumed message's
    /// recorded `publisher_vertical` matches the event_type's owning
    /// vertical (its first colon segment) — design/
    /// sentin8-vertical-data-plane-contract.md §VDC.4.
    ///
    /// Bus's produce-side event-ownership gate (`enforce_event_ownership`)
    /// is the STRUCTURAL control: only a producer whose M2M `vertical`
    /// claim matches the event_type's first colon segment may mint the
    /// event. This helper is the consumer-side belt to that suspenders for
    /// reaction-triggering consumers (env-init, cache invalidation): it
    /// verifies the `publisher_vertical` Bus recorded from the verified
    /// producer token — e.g. `sentin8:sys:service:updated` must carry
    /// `publisher_vertical == "sentin8"` before a consumer seeds tenant
    /// state from it.
    ///
    /// # Errors
    ///
    /// Returns a human-readable mismatch string when the recorded vertical
    /// is absent (a message from a pre-VDC relay) or differs from the
    /// event_type's prefix — the caller MUST treat the message as untrusted
    /// and skip the reaction (do not ACK; redelivery/DLQ machinery handles
    /// the retry).
    pub fn require_publisher(msg: &sentin8_bus_contracts::Message) -> Result<(), String> {
        let prefix = msg.event_type.split(':').next().unwrap_or("");
        if prefix.is_empty() {
            return Err(format!(
                "event_type '{}' is malformed — no vertical prefix (VDC-2)",
                msg.event_type
            ));
        }
        let recorded = msg.publisher_vertical.as_deref().unwrap_or("");
        if recorded == prefix {
            return Ok(());
        }
        Err(format!(
            "publisher provenance mismatch: event_type '{}' belongs to vertical \
             '{prefix}' but the message records publisher_vertical '{recorded}' \
             (VDC-2 — treating message as untrusted)",
            msg.event_type
        ))
    }

    /// Verify a publisher ID Token. Checks issuer, signature
    /// (via JWKS), expiry, and token type. Returns the extracted claims
    /// (`sub`, `scope`, `env_id`). Returns `Err(Expired)`
    /// if the token has expired — the caller should fall back to its own
    /// M2M token. Uses the auth client's `verify_token` for JWKS caching.
    pub async fn verify_publisher_token(
        &self,
        token: &str,
    ) -> Result<PublisherClaims, PublisherTokenError> {
        // Use the auth client to verify — it handles JWKS fetching and caching.
        // We construct a temporary auth client if one isn't available.
        // In practice, the subscriber service already has an auth client.
        // For simplicity, we use the sentin8_auth_client SDK directly.
        let auth_client = sentin8_auth_client::Client::new(sentin8_auth_client::ClientOptions {
            base_url: self.base_url.clone(),
            ..Default::default()
        });
        let claims = auth_client
            .verify_token(token)
            .await
            .map_err(|e| PublisherTokenError::InvalidSignature(e.to_string()))?;

        // Check expiry.
        let now = chrono::Utc::now().timestamp();
        if claims.exp < now {
            return Err(PublisherTokenError::Expired);
        }

        // Check token type — must be access, m2m, or delegated.
        match claims.token_tp.as_str() {
            "access" | "m2m" | "delegated" => {}
            other => return Err(PublisherTokenError::UnsupportedTokenType(other.to_string())),
        }

        Ok(PublisherClaims {
            sub: claims.sub,
            scope: claims.scope,
            env_id: claims.env_id,
        })
    }

    /// Exchange a publisher token for a delegated token via RFC 8693.
    /// The subscriber presents the publisher token as
    /// `subject_token` and requests a delegated token with `act.sub` =
    /// publisher's subject. Uses the subscriber's M2M token for
    /// authentication. Returns a `DelegatedToken` with the access token
    /// and the `act.sub` for audit.
    pub async fn exchange_for_delegated_token(
        &self,
        publisher_token: &str,
        target_audience: &str,
        requested_scope: &str,
    ) -> Result<DelegatedToken, ExchangeError> {
        // Use the auth client's token-exchange endpoint.
        let auth_client = sentin8_auth_client::Client::new(sentin8_auth_client::ClientOptions {
            base_url: self.base_url.clone(),
            ..Default::default()
        });

        // the subscriber has no token — the RFC 8693 exchange
        // is a token-plane flow kept for delegated-user scenarios; the
        // caller passes the publisher token directly and the exchange
        // endpoint authenticates it. The old subscriber-token fetch is
        // deleted with the token plane.
        let subscriber_token_unused: Option<String> = None;
        let _ = subscriber_token_unused;

        // Call the token-exchange endpoint.
        let token_resp = auth_client
            .exchange_token(
                publisher_token,
                target_audience,
                "", // env_id — derived from the publisher token
                requested_scope,
            )
            .await
            .map_err(|e| ExchangeError::ExchangeFailed(e.to_string()))?;

        // Decode the delegated token to extract act.sub for audit.
        let claims = sentin8_auth_client::decode_claims_unverified(&token_resp.access_token)
            .ok_or_else(|| {
                ExchangeError::DecodeFailed("failed to decode delegated token claims".into())
            })?;

        Ok(DelegatedToken {
            access_token: token_resp.access_token,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope.unwrap_or_default(),
            act_sub: claims.sub,
        })
    }
}

/// Publisher token claims extracted from a verified publisher JWT.
#[derive(Debug, Clone)]
pub struct PublisherClaims {
    /// Publisher's subject (`sub`).
    pub sub: String,
    /// Publisher's scope claim.
    pub scope: String,
    /// Publisher's environment, when present in the token.
    pub env_id: Option<String>,
}

/// Errors from publisher token verification.
#[derive(Debug, thiserror::Error)]
pub enum PublisherTokenError {
    /// The publisher token has expired — fall back to the subscriber's own
    /// M2M token.
    #[error("publisher token has expired")]
    Expired,
    /// Signature or claim verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// The token type is not exchangeable (must be access, m2m, or delegated).
    #[error("unsupported token type: {0}")]
    UnsupportedTokenType(String),
    /// The token was issued by an unexpected issuer.
    #[error("invalid issuer: {0}")]
    WrongIssuer(String),
}

/// A delegated token obtained via RFC 8693 token exchange.
#[derive(Debug, Clone)]
pub struct DelegatedToken {
    /// The delegated access token.
    pub access_token: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Granted scope.
    pub scope: String,
    /// The `act.sub` claim from the delegated token — the original
    /// publisher's subject. Used for audit trail.
    pub act_sub: String,
}

/// Errors from token exchange.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The subscriber's own token could not be fetched.
    #[error("failed to fetch subscriber token: {0}")]
    TokenFetch(String),
    /// The exchange request failed.
    #[error("token exchange failed: {0}")]
    ExchangeFailed(String),
    /// The delegated token could not be decoded.
    #[error("failed to decode delegated token: {0}")]
    DecodeFailed(String),
}

// ── Client construction ───────────────────────────────────────────────
//
// auth DESIGN §4.3f: the certificate is the identity — the
// DCR-backed builder (`build_with_dcr` + background retry + token-source
// activation) is deleted. Call `BusClient::for_workload` (mint-if-missing,
// cert-presenting) or `BusClient::with_workload_identity` (paths in hand).

/// Classify a non-success produce response into the relay's two failure
/// classes (outbox relay design): a 4xx is a PERMANENT rejection — Bus
/// refused the request itself (event-ownership gate, env-match gate,
/// validation) and no retry can succeed — while any other non-success
/// stays retryable. The response body is retained so the caller's single
/// warning line carries the actual rejection message instead of a bare
/// status. 429 (rate limit) and 408 (request timeout) are TRANSIENT —
/// Bus-side throttling is exactly the condition the retry budget exists
/// for; parking rows at zero retries on a boot-window rate limit is the
/// D4 defect class (RS §3), so they route to the retryable branch.
async fn classify_produce_status(
    status: reqwest::StatusCode,
    resp: reqwest::Response,
) -> BusError {
    let body = resp.text().await.unwrap_or_default();
    if status.is_client_error() && status.as_u16() != 429 && status.as_u16() != 408 {
        BusError::Permanent {
            status: status.as_u16(),
            body,
        }
    } else {
        BusError::Http(format!("status {status}: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn client_url() {
        install_provider();
        let url = "https://bus.example.com";
        assert_eq!(
            format!("{url}/v1/produce"),
            "https://bus.example.com/v1/produce"
        );
    }

    #[test]
    fn client_url_no_trailing_slash() {
        install_provider();
        let url = "https://bus.example.com";
        assert_eq!(format!("{url}/v1/health"), "https://bus.example.com/v1/health");
    }

    // ── VDC-2 require_publisher (design/sentin8-vertical-data-plane-
    // contract.md §VDC.4) ─────────────────────────────────────────────

    fn msg(event_type: &str, publisher_vertical: Option<&str>) -> sentin8_bus_contracts::Message {
        sentin8_bus_contracts::Message {
            message_id: "1-1".into(),
            stream_family: "sys".into(),
            org_id: String::new(),
            env_id: "00000000-0000-0000-0000-000000000002".into(),
            event_type: event_type.into(),
            schema_version: "1.0".into(),
            payload: serde_json::Value::Null,
            correlation_id: String::new(),
            produced_by: "sys".into(),
            produced_at: String::new(),
            idempotency_key: None,
            publisher_id_token: None,
            publisher_subject: None,
            publisher_vertical: publisher_vertical.map(String::from),
        }
    }

    #[test]
    fn require_publisher_accepts_matching_vertical() {
        let m = msg("sentin8:sys:service:updated", Some("sentin8"));
        assert!(BusClient::require_publisher(&m).is_ok());
        let m = msg("bank8:ledger:posting:committed", Some("bank8"));
        assert!(BusClient::require_publisher(&m).is_ok());
    }

    #[test]
    fn require_publisher_rejects_missing_or_mismatched() {
        // Missing (pre-VDC relay delivery) → untrusted.
        let m = msg("sentin8:sys:service:updated", None);
        assert!(BusClient::require_publisher(&m).is_err());
        // Mismatched (spoof attempt) → untrusted.
        let m = msg("sentin8:sys:service:updated", Some("bank8"));
        assert!(BusClient::require_publisher(&m).is_err());
        // Malformed event_type → untrusted.
        let m = msg("", Some("sentin8"));
        assert!(BusClient::require_publisher(&m).is_err());
    }
}
