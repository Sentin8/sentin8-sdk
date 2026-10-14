// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-auth-client
//!
//! Rust client library for the Auth identity service.
//!
//! Covers stories 1.1b.1–1.1b.25 (P0 + P1).

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use sentin8_middleware::http_client::Sentin8HttpClient;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;
use tokio::sync::RwLock as TokioRwLock;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Auth HTTP error: {0}")]
    Http(String),
    /// An HTTP response with a known status code and body. Carries the
    /// `reqwest::StatusCode` so callers can distinguish a 403 deny from a
    /// 5xx transient failure (used by BFF token-exchange fallback policy).
    #[error("Auth HTTP error: {status} {body}")]
    HttpStatus {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("Auth decode error: {0}")]
    Decode(String),
    #[error("Auth config error: {0}")]
    Config(String),
}

/// Configuration for creating an Auth client.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub base_url: String,
    pub api_key: Option<String>,
    /// Discovery cache TTL (default 5 minutes).
    pub discovery_ttl: Duration,
    /// JWKS cache TTL (default 5 minutes).
    pub jwks_ttl: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            api_key: None,
            discovery_ttl: Duration::from_secs(300),
            jwks_ttl: Duration::from_secs(300),
        }
    }
}

impl ClientOptions {
    pub fn builder() -> ClientOptionsBuilder {
        ClientOptionsBuilder::default()
    }
}

/// Builder for [`ClientOptions`].
#[derive(Default)]
pub struct ClientOptionsBuilder {
    opts: ClientOptions,
}

impl ClientOptionsBuilder {
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.opts.base_url = url.into();
        self
    }
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.opts.api_key = Some(key.into());
        self
    }
    pub fn discovery_ttl(mut self, ttl: Duration) -> Self {
        self.opts.discovery_ttl = ttl;
        self
    }
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.opts.jwks_ttl = ttl;
        self
    }
    pub fn build(self) -> Result<ClientOptions, AuthError> {
        if self.opts.base_url.trim().is_empty() {
            return Err(AuthError::Config("base_url is required".into()));
        }
        Ok(self.opts)
    }
}

/// The Auth client. Cheap to clone (wraps an `Arc`).
#[derive(Clone, Debug)]
pub struct Client {
    base_url: String,
    auth_token: Arc<Option<String>>,
    /// HTTP client behind a lock so callers can install an mTLS-capable
    /// client at runtime (`set_http_client`) — credentials become known
    /// only after DCR activation.
    http: Arc<RwLock<Sentin8HttpClient>>,
    discovery: Arc<TokioRwLock<Option<CachedDiscovery>>>,
    jwks: Arc<TokioRwLock<Option<CachedJwks>>>,
    opts: Arc<ClientOptions>,
}

#[derive(Debug)]
struct CachedDiscovery {
    doc: DiscoveryDocument,
    fetched_at: Instant,
}

#[derive(Debug)]
struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

impl Client {
    /// Create a new Auth client.
    pub fn new(opts: ClientOptions) -> Self {
        Self {
            base_url: opts.base_url.trim_end_matches('/').to_string(),
            auth_token: Arc::new(opts.api_key.clone()),
            http: Arc::new(RwLock::new(Sentin8HttpClient::new())),
            discovery: Arc::new(TokioRwLock::new(None)),
            jwks: Arc::new(TokioRwLock::new(None)),
            opts: Arc::new(opts),
        }
    }

    /// Install a custom HTTP client (e.g. an mTLS client built via
    /// `sentin8_middleware::mtls::build_mtls_client`) for calls that
    /// present cert-bound M2M tokens to RFC 8705 sender-constrained
    /// endpoints — TLS must inject `X-Sentin8-Client-Cert-Thumbprint`
    /// from the handshake, which a plain client cannot do (SEC-2.4.10).
    /// Opt-in; the default correlation-propagating client is unchanged.
    pub fn set_http_client(&self, http: Sentin8HttpClient) {
        *self.http.write().unwrap() = http;
    }

    /// Build a client via a [`ClientOptionsBuilder`].
    pub fn builder() -> ClientOptionsBuilder {
        ClientOptions::builder()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.read().unwrap().request(method, self.url(path));
        if let Some(ref token) = *self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }

    // ── Frontend API ──────────────────────────────────────────────────────

    /// `POST /v1/sign-in` — email/password authentication.
    pub async fn sign_in(&self, email: &str, password: &str) -> Result<SignInResponse, AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/sign-in")
            .json(&serde_json::json!({"email": email, "password": password}))
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/sign-up` — customer registration.
    pub async fn sign_up(
        &self,
        email: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<SignInResponse, AuthError> {
        let mut body = serde_json::json!({"email": email, "password": password});
        if let Some(f) = first_name {
            body["first_name"] = serde_json::Value::String(f.into());
        }
        if let Some(l) = last_name {
            body["last_name"] = serde_json::Value::String(l.into());
        }
        let resp = self
            .request(reqwest::Method::POST, "/v1/sign-up")
            .json(&body)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/sign-out` — session termination.
    pub async fn sign_out(&self) -> Result<(), AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/sign-out")
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `GET /v1/session` — return current session.
    pub async fn get_session(&self) -> Result<SessionInfo, AuthError> {
        let resp = self
            .request(reqwest::Method::GET, "/v1/session")
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    // ── OAuth endpoints ────────────────────────────────────────────────────

    /// Fetch and cache the OIDC discovery document (TTL-based, 1.1b.24).
    pub async fn discover(&self) -> Result<DiscoveryDocument, AuthError> {
        {
            let cache = self.discovery.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() < self.opts.discovery_ttl {
                    return Ok(c.doc.clone());
                }
            }
        }
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .get(self.url("/.well-known/openid-configuration"))
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        let doc: DiscoveryDocument = resp
            .json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))?;
        let mut cache = self.discovery.write().await;
        *cache = Some(CachedDiscovery {
            doc: doc.clone(),
            fetched_at: Instant::now(),
        });
        Ok(doc)
    }

    /// Build an authorize URL with PKCE S256 (1.1b.7).
    ///
    /// Returns `(authorize_url, pkce_verifier)` so the caller can store the
    /// verifier for the later code exchange.
    pub async fn authorize_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
    ) -> Result<(String, String), AuthError> {
        let doc = self.discover().await?;
        let verifier = generate_pkce_verifier();
        let challenge = pkce_s256_challenge(&verifier);

        let params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            urlencode(client_id), urlencode(redirect_uri), urlencode(scope), urlencode(state),
            urlencode(&challenge),
        );

        Ok((
            format!("{}?{}", doc.authorization_endpoint, params),
            verifier,
        ))
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AuthError> {
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", client_id),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// Refresh an access token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<TokenResponse, AuthError> {
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// Exchange a token for a downscoped, audience-bound, tenant-scoped token
    /// (RFC 8693). Used by BFF to exchange platform-scoped tokens for
    /// env-scoped tokens before proxying to backend services. Also used by the CLI to
    /// obtain env-scoped tokens for direct API calls.
    ///
    /// # Parameters
    /// - `subject_token`: The access token to exchange.
    /// - `audience`: The target service audience (e.g. `https://bank8-ledger.ops.sys.sentin8.local`).
    /// - `env_id`: The target environment ID.
    /// - `scope`: The requested scope (space-separated, already downscoped to
    ///   the target service's scopes). If empty, all subject scopes are kept.
    pub async fn exchange_token(
        &self,
        subject_token: &str,
        audience: &str,
        env_id: &str,
        scope: &str,
    ) -> Result<TokenResponse, AuthError> {
        let mut form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ),
            ("subject_token", subject_token.to_string()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token".to_string(),
            ),
            ("audience", audience.to_string()),
            ("requested_tenancy.env_id", env_id.to_string()),
        ];
        if !scope.is_empty() {
            form.push(("scope", scope.to_string()));
        }

        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/oauth/token"))
            .form(&form)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::HttpStatus { status, body });
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// Request a delegated access token via the Delegation Gateway (Story 12.4.31).
    ///
    /// BFF calls this with its cert-bound M2M token + the staff user's
    /// identity + target env. Auth validates the caller's CERTIFICATE
    /// identity ( — the mTLS transport presents the
    /// `bff-delegator` workload certificate; the TLS layer injects the
    /// identity headers), checks `may_act` for the staff user, and mints
    /// a cert-bound delegated token.
    ///
    /// - `act_sub`: Staff user's Auth user ID.
    /// - `act_email`: Staff user's email (for audit).
    /// - `env_id`: Target env ID.
    /// - `scope`: Requested scopes (will be downscoped).
    /// - `audience`: Target service audience (RFC 8707 resource indicator).
    ///
    /// The call MUST ride an mTLS-configured transport (BFF installs it
    /// via `install_mtls_auth_client`) — a plain transport carries no
    /// certificate and Auth fail-closed rejects the exchange.
    pub async fn delegate_access_token(
        &self,
        act_sub: &str,
        act_email: &str,
        env_id: &str,
        scope: &str,
        audience: &str,
    ) -> Result<TokenResponse, AuthError> {
        let body = serde_json::json!({
            "act_sub": act_sub,
            "act_email": if act_email.is_empty() { None } else { Some(act_email) },
            "env_id": env_id,
            "scope": scope,
            "audience": audience,
        });

        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/delegate/access-token"))
            .json(&body)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::HttpStatus { status, body });
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// Revoke a token.
    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/oauth/revoke"))
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// Introspect a token.
    pub async fn introspect_token(&self, token: &str) -> Result<IntrospectionResponse, AuthError> {
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .post(self.url("/oauth/introspect"))
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// Fetch UserInfo for an access token.
    pub async fn user_info(&self, access_token: &str) -> Result<serde_json::Value, AuthError> {
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .get(self.url("/oauth/userinfo"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    // ── JWKS caching (1.1b.24) ───────────────────────────────────────────

    /// Fetch and cache the JWKS from `jwks_uri` (TTL-based).
    pub async fn jwks(&self) -> Result<JwkSet, AuthError> {
        {
            let cache = self.jwks.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() < self.opts.jwks_ttl {
                    return Ok(c.keys.clone());
                }
            }
        }
        let doc = self.discover().await?;
        // Clone out (reqwest clients share the pool; Arc-clone is cheap) so
        // the lock guard never lives across the .await — the future must stay
        // Send for the axum Handler bounds.
        let http = self.http.read().unwrap().clone();
        let resp = http
            .get(&doc.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        let keys: JwkSet = resp
            .json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))?;
        let mut cache = self.jwks.write().await;
        *cache = Some(CachedJwks {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
        Ok(keys)
    }

    // ── Admin API (1.1b.13–1.1b.22) ──────────────────────────────────────

    /// Verify a JWT access token against the Auth JWKS.
    ///
    /// This is the primary method used by all Sentin8 services (DB, Buck,
    /// BFF, Ledger, Payments, etc.) to verify Bearer tokens. It fetches the
    /// JWKS (cached with TTL), finds the matching key by `kid`, verifies the
    /// RS256 signature, checks expiry, and returns the decoded claims.
    pub async fn verify_token(&self, token: &str) -> Result<VerifiedClaims, AuthError> {
        // Parse the JWT header to find the key ID and algorithm.
        // We use sentin8_jwt because jsonwebtoken::decode_header fails on
        // non-standard algorithms like MLDSA65.
        let header_json = sentin8_jwt::decode_header(token)
            .map_err(|e| AuthError::Decode(format!("invalid JWT header: {e}")))?;
        let kid = header_json
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::Decode("missing kid in JWT header".into()))?;
        let jwt_alg = header_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Fetch JWKS (cached).
        let jwks = self.jwks().await?;

        // Find the matching key.
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| AuthError::Decode(format!("key {kid} not found in JWKS")))?;

        // Determine the algorithm from the JWK's alg field or the JWT header.
        let alg = jwk.alg.as_deref().unwrap_or(jwt_alg);

        // Extract the verified claims — support both RS256 (RSA) and ML-DSA-65.
        use base64::Engine;
        let claims_json: serde_json::Value = if alg == "MLDSA65" || jwk.kty == "MLWE" {
            // ML-DSA-65 verification (manual — jsonwebtoken doesn't support ML-DSA).
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| AuthError::Decode("missing x in MLWE JWK".into()))?;
            let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| AuthError::Decode(format!("invalid JWK x: {e}")))?;

            // Build the ML-DSA-65 verifying key from the raw public key bytes.
            use ml_dsa::{KeyInit, MlDsa65, Verifier};
            let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(&pk_bytes)
                .map_err(|e| AuthError::Decode(format!("invalid ML-DSA verifying key: {e}")))?;

            // Verify the signature using sentin8_jwt helpers.
            let signing_input = sentin8_jwt::signing_input(token)
                .map_err(|e| AuthError::Decode(format!("invalid JWT: {e}")))?;
            let sig_bytes = sentin8_jwt::decode_signature(token)
                .map_err(|e| AuthError::Decode(format!("decode signature: {e}")))?;
            let signature =
                <ml_dsa::Signature<MlDsa65> as std::convert::TryFrom<&[u8]>>::try_from(&sig_bytes)
                    .map_err(|e| AuthError::Decode(format!("decode ML-DSA signature: {e}")))?;

            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .map_err(|e| {
                    AuthError::Decode(format!("ML-DSA signature verification failed: {e}"))
                })?;

            // Decode claims from the verified payload.
            sentin8_jwt::decode_payload(token)
                .map_err(|e| AuthError::Decode(format!("failed to parse claims: {e}")))?
        } else {
            // RS256 verification (jsonwebtoken crate) — existing RSA path.
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| AuthError::Decode("missing n in JWK".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| AuthError::Decode("missing e in JWK".into()))?;
            let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|e| AuthError::Decode(format!("invalid JWK n: {e}")))?;
            let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(e)
                .map_err(|e| AuthError::Decode(format!("invalid JWK e: {e}")))?;

            // Build RSA public key.
            let n_bigint = rsa::BigUint::from_bytes_be(&n_bytes);
            let e_bigint = rsa::BigUint::from_bytes_be(&e_bytes);
            let pub_key = rsa::RsaPublicKey::new(n_bigint, e_bigint)
                .map_err(|e| AuthError::Decode(format!("invalid RSA key: {e}")))?;

            // Build the jsonwebtoken DecodingKey from the RSA public key.
            use rsa::pkcs8::EncodePublicKey;
            let pem = pub_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| AuthError::Decode(format!("RSA PEM encoding failed: {e}")))?;
            let dec_key = jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| AuthError::Decode(format!("RSA decode key failed: {e}")))?;

            // Verify the token.
            let doc = self.discover().await?;
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.set_issuer(&[&doc.issuer]);
            validation.validate_aud = false;

            let data = jsonwebtoken::decode::<serde_json::Value>(token, &dec_key, &validation)
                .map_err(|e| AuthError::Decode(format!("JWT verification failed: {e}")))?;
            data.claims
        };

        // Extract the verified claims.
        let claims: VerifiedClaims = serde_json::from_value(claims_json)
            .map_err(|e| AuthError::Decode(format!("failed to parse claims: {e}")))?;

        Ok(claims)
    }

    /// `GET /v1/admin/users` — list users (admin).
    pub async fn admin_list_users(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<UserSummary>, AuthError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/v1/admin/users?limit={limit}&offset={offset}"),
            )
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/admin/users` — create a user (admin).
    pub async fn admin_create_user(
        &self,
        req: &CreateUserRequest,
    ) -> Result<UserSummary, AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/admin/users")
            .json(req)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/admin/applications` — register an OAuth application (admin).
    pub async fn admin_register_application(
        &self,
        req: &RegisterApplicationRequest,
    ) -> Result<OAuthApplication, AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/admin/applications")
            .json(req)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/admin/api-keys` — create an API key (admin).
    pub async fn admin_create_api_key(
        &self,
        req: &CreateApiKeyRequest,
    ) -> Result<ApiKeySummary, AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/admin/api-keys")
            .json(req)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `DELETE /v1/admin/api-keys/{id}` — revoke an API key (admin).
    pub async fn admin_revoke_api_key(&self, id: &str) -> Result<(), AuthError> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/v1/admin/api-keys/{id}"))
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `GET /v1/admin/sessions` — list active sessions (admin).
    pub async fn admin_list_sessions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, AuthError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/v1/admin/sessions?limit={limit}&offset={offset}"),
            )
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `DELETE /v1/admin/sessions/{id}` — terminate a session (admin).
    pub async fn admin_terminate_session(&self, id: &str) -> Result<(), AuthError> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/v1/admin/sessions/{id}"))
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `GET /v1/admin/audit` — query audit events (admin).
    pub async fn admin_list_audit_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEvent>, AuthError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/v1/admin/audit?limit={limit}&offset={offset}"),
            )
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `GET /v1/admin/memberships` — list org memberships (admin).
    pub async fn admin_list_memberships(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<MembershipSummary>, AuthError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/v1/admin/memberships?limit={limit}&offset={offset}"),
            )
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| AuthError::Decode(e.to_string()))
    }

    /// `POST /v1/admin/invitations` — send an invitation (admin).
    pub async fn admin_send_invitation(
        &self,
        req: &SendInvitationRequest,
    ) -> Result<(), AuthError> {
        let resp = self
            .request(reqwest::Method::POST, "/v1/admin/invitations")
            .json(req)
            .send()
            .await
            .map_err(|e| AuthError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }
}

// ── PKCE helpers ────────────────────────────────────────────────────────

/// Generate a random PKCE code verifier (43 chars, URL-safe base64).
pub fn generate_pkce_verifier() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute the PKCE S256 code challenge from a verifier.
pub fn pkce_s256_challenge(verifier: &str) -> String {
    use base64::Engine;
    let hash = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ── JWT decoding utilities (no signature verification) ──────────────────
//
// These helpers are re-exported from the `sentin8-jwt` crate. They decode
// JWT headers and payloads without verifying the signature, and work with
// both standard algorithms (RS256, ES256, EdDSA) and non-standard ones
// like ML-DSA-65 (`"MLDSA65"`).
//
// `jsonwebtoken::decode_header()` and `jsonwebtoken::decode()` fail on
// `alg: "MLDSA65"` because the `alg` field is deserialized into
// `jsonwebtoken::Algorithm`, an enum that only knows HS/ES/RS/PS/EdDSA.
// Any code that just needs to read JWT claims without verification should
// use these helpers instead.

/// Decode a JWT header (`alg`, `kid`, `typ`, etc.) without verifying the
/// signature.
///
/// Returns the raw JSON value of the header. Common fields:
/// - `alg` — the signing algorithm (e.g. `"MLDSA65"`, `"RS256"`)
/// - `kid` — the key ID used to look up the signing key in JWKS
/// - `typ` — the JWT type (e.g. `"JWT"`, `"dpop+jwt"`)
pub fn decode_jwt_header(token: &str) -> Result<serde_json::Value, String> {
    sentin8_jwt::decode_header(token)
}

/// Decode a JWT payload (claims) without verifying the signature.
///
/// Returns the raw JSON value of the claims. The caller is responsible for
/// deserializing into a specific type if needed.
///
/// **Security note**: This does NOT verify the token signature. Never use
/// this for authorization decisions — use `Client::verify_token()` for that.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    sentin8_jwt::decode_payload(token)
}

/// Decode a JWT payload into a typed struct without verifying the signature.
///
/// Convenience wrapper around `decode_jwt_payload` that deserializes into
/// the caller's type. Returns `None` if the JWT is malformed or the payload
/// doesn't match `T` (for use in `Option`-returning call sites).
///
/// **Security note**: This does NOT verify the token signature.
pub fn decode_jwt_payload_typed<T: serde::de::DeserializeOwned>(token: &str) -> Option<T> {
    sentin8_jwt::decode_payload_typed(token)
}

/// Decode JWT claims without signature verification. This is a lightweight
/// helper for inspecting token claims (token_tp, env_id, sub) when
/// full verification is not needed — e.g. BFF checking the token type before
/// deciding whether to exchange a token, or the CLI inspecting a cached
/// token's expiry.
///
/// **Security note**: This does NOT verify the token signature. Never use
/// this for authorization decisions — use `Client::verify_token()` for that.
/// Only use this for routing/optimization decisions (e.g. "is this an
/// M2M token that needs exchange?").
pub fn decode_claims_unverified(token: &str) -> Option<UnverifiedClaims> {
    let claims = decode_jwt_payload(token).ok()?;
    Some(UnverifiedClaims {
        sub: claims["sub"].as_str().unwrap_or("").to_string(),
        token_tp: claims["token_tp"].as_str().unwrap_or("").to_string(),
        env_id: claims["env_id"].as_str().map(|s| s.to_string()),
        scope: claims["scope"].as_str().unwrap_or("").to_string(),
        exp: claims["exp"].as_i64(),
        email: claims["email"].as_str().map(|s| s.to_string()),
    })
}

/// Lightweight claims decoded from a JWT without signature verification.
/// Used for routing decisions, not authorization.
#[derive(Debug, Clone)]
pub struct UnverifiedClaims {
    pub sub: String,
    pub token_tp: String,
    pub env_id: Option<String>,
    pub scope: String,
    pub exp: Option<i64>,
    pub email: Option<String>,
}

impl UnverifiedClaims {
    /// Check if the token has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }
}

/// Extract scopes matching a service prefix (e.g. "bank8:ledger:") from a
/// scope string. Used to downscope the exchanged token to only the scopes
/// needed for the target service. Also keeps `sentin8:sys:admin`
/// (platform-admin bypass; uniform RBAC naming, architecture-principles
/// of the naming convention).
pub fn extract_scopes_for_service(scope: &str, prefix: &str) -> String {
    scope
        .split_whitespace()
        .filter(|s| s.starts_with(prefix) || *s == "sentin8:sys:admin")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Minimal URL-encoding (RFC 3986 unreserved set).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

// ── Response types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignInResponse {
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
}

/// Claims verified from a JWT access token. Used by all services to verify
/// Bearer tokens via the auth-client SDK.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiedClaims {
    /// Subject — user ID or client_id.
    pub sub: String,
    /// Issuer — Auth issuer URL.
    pub iss: String,
    /// Audience — space-separated list of intended audiences (RFC 9068 `aud`).
    #[serde(default)]
    pub aud: String,
    /// JWT ID.
    pub jti: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiry timestamp.
    pub exp: i64,
    /// Token type marker: `"access"`, `"refresh"`, `"m2m"`, `"id"`.
    #[serde(rename = "token_tp")]
    pub token_tp: String,
    /// Space-separated scope string.
    #[serde(default)]
    pub scope: String,
    /// Environment ID (tenant binding — globally unique, sole tenant key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
    /// Email (for user tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// RFC 8693 `act` claim — the ORIGINAL actor for delegated/token-exchange
    /// tokens (`{sub, email}`) or the external IdP identity for federated M2M.
    /// Absent on plain user/M2M tokens. Services that resolve the acting
    /// USER for authorization/audit read `act.sub` when present (the plain
    /// `sub` of a delegated token is the DELEGATOR's client_id, not a user).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    /// The vertical this M2M workload belongs to (VDC-2, design/
    /// sentin8-vertical-data-plane-contract.md §VDC.4). Stamped by Auth from
    /// the `auth.m2m_scope_grants.vertical` row; consumed by Bus's
    /// event-ownership gate (the event_type's first colon segment must equal
    /// it). Absent on user/delegated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vertical: Option<String>,
    /// The service this M2M workload performs work FOR (VDC-4, §VDC.5) —
    /// stamped from the same enroll row; Sys's tenant-snapshot scoped
    /// discovery uses it (the caller sees only envs where its own service
    /// is enabled). Absent on user/delegated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
}

impl VerifiedClaims {
    /// Get the environment ID as a `Uuid`, falling back to the System Env ID.
    pub fn env_uuid(&self) -> uuid::Uuid {
        self.env_id
            .as_ref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or(sentin8_config::SYSTEM_ENV_ID)
    }

    /// The acting USER id — `act.sub` when the token is delegated (RFC 8693;
    /// the plain `sub` is the delegator's client_id), else `sub` for user
    /// tokens. Returns `None` when neither parses as a user UUID (plain M2M
    /// tokens carry a client_id subject — not a user).
    pub fn acting_user_uuid(&self) -> Option<uuid::Uuid> {
        if let Some(act) = &self.act {
            if let Some(sub) = act.get("sub").and_then(|v| v.as_str()) {
                if let Ok(id) = uuid::Uuid::parse_str(sub) {
                    return Some(id);
                }
            }
        }
        match self.token_tp.as_str() {
            "access" | "id" | "refresh" | "delegated" => uuid::Uuid::parse_str(&self.sub).ok(),
            _ => None,
        }
    }

    /// Check if the token has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }

    /// Check if the token has any of the given scopes (prefix match).
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        self.scope.split_whitespace().any(|token_scope| {
            scopes
                .iter()
                .any(|s| token_scope == *s || token_scope.starts_with(&format!("{s}:")))
        })
    }

    /// Check if the caller is a platform admin.
    /// Returns true if the token holder has the `sentin8:sys:admin` scope —
    /// granted via the `sentin8:org:sys:admins` group → `sentin8:org:sys:admin` role →
    /// `sentin8:sys:admin` role (nests all service-admin roles). This is
    /// **permission-based**, not identity-based: any caller (user or
    /// M2M) with `sentin8:sys:admin` in their resolved scope set is a platform
    /// admin. Authorization is based solely on `scope`, not on token type
    /// or subject identity.
    pub fn is_platform_admin(&self) -> bool {
        self.has_scope("sentin8:sys:admin")
    }

    /// Subject type for RLS holder-scoped policies.
    /// Derives the runtime subject-type from `token_tp`: user tokens
    /// (`access`/`id`/`refresh`) are real users; `m2m` covers service
    /// Auth user UUID parsed from the `sub` claim, if the subject is a
    /// user token (`access`/`id`/`refresh`). Returns `None` for M2M /
    /// delegated tokens whose `sub` is not a user id.
    /// Used by holder-scoped RLS to match the customer table's
    /// `sentin8_auth_user_id` column.
    pub fn sentin8_auth_user_uuid(&self) -> Option<uuid::Uuid> {
        match self.token_tp.as_str() {
            "access" | "id" | "refresh" => uuid::Uuid::parse_str(&self.sub).ok(),
            _ => None,
        }
    }

    /// Is the caller an org admin? (Epic 15.5 option a — resolved from
    /// scopes at context-set time, no per-row join.) True if the token
    /// carries the `sentin8:sys:org:admin` scope (granted via the `sentin8:sys:org:admin`
    /// role — see `sentin8-sentin8-auth-technical-design.md`
    /// the auth seed data).
    pub fn is_org_admin(&self) -> bool {
        self.has_scope("sentin8:sys:org:admin")
    }

    /// Is the caller an env admin? (Epic 15.5 option a.) True if the token
    /// carries the `sentin8:sys:env:admin` scope (granted via the `sentin8:sys:env:admin`
    /// role).
    pub fn is_env_admin(&self) -> bool {
        self.has_scope("sentin8:sys:env:admin")
    }

    /// Holder-scoping primitive: does the token carry the
    /// `sentin8:holder:view-all` scope? Callers with this scope see ALL records in
    /// the env (staff tooling); callers without it are "holders" and see
    /// only records that belong to them (`sentin8_auth_user_id` matches).
    pub fn is_holder_view_all(&self) -> bool {
        self.has_scope("sentin8:holder:view-all")
    }

    /// Holder-scoping primitive: is this caller a HOLDER (i.e. does
    /// the token LACK `sentin8:holder:view-all`)? Used by services to force
    /// `customer_id` / ownership predicates in the service layer;
    /// holder-scoped RLS is the backstop.
    pub fn is_holder(&self) -> bool {
        !self.is_holder_view_all()
    }
}

// ── AuthContext + verify_bearer_token (shared across all services) ──────

/// Authenticated request context — contains verified claims from the
/// Auth access token. Used by all Sentin8 backend services.
///
/// This struct replaces the per-service `auth.rs` files that duplicated
/// the same `AuthContext` wrapper + `verify_token` function in every
/// service. Services should use `verify_bearer_token()` to extract and
/// verify the token, then call methods on `AuthContext` for authorization.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub claims: VerifiedClaims,
    /// auth DESIGN §4.3f: the resolved certificate-only
    /// platform-workload identity, when the request presented an enrolled
    /// client certificate INSTEAD of a bearer token. `None` on the bearer
    /// path (user/delegated JWT flows). When set, `claims` carries the
    /// SYNTHETIC projection of the identity (see
    /// [`AuthContext::from_workload`]) — `has_scope`/`effective_*`
    /// consult the workload record first, the claims second.
    pub workload: Option<WorkloadIdentity>,
}

/// A platform workload's certificate identity as resolved from the
/// TLS-injected headers against the boot-loaded registry map
/// (auth DESIGN §4.3f). The certificate IS the
/// authentication; the enroll-published `m2m:workloads` map IS the
/// authorization record (scopes + vertical + enabled).
#[derive(Debug, Clone)]
pub struct WorkloadIdentity {
    /// The workload name (certificate CN minus `m2m-`).
    pub workload: String,
    /// The map-granted scopes (empty when missing/disabled — fail-closed).
    pub scopes: Vec<String>,
    /// The map-stamped vertical (VDC-2 gate input; `None` when
    /// missing/disabled — produce refuses).
    pub vertical: Option<String>,
    /// The service_type the workload performs work FOR (VDC-4 — Sys's
    /// tenant-snapshot scoped discovery keys on this claim; `None` when
    /// the map row carries no value).
    pub service_type: Option<String>,
    /// The presented certificate thumbprint (base64url SHA-256 of DER —
    /// the audit identity).
    pub thumbprint: String,
}

impl WorkloadIdentity {
    /// Whether the map grants this workload the given scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

impl AuthContext {
    /// Build the certificate-path context: a SYNTHETIC claims projection
    /// of the resolved identity (`sub = m2m-{workload}`, `token_tp =
    /// "m2m"`, scope/vertical from the map row, no expiry — the identity
    /// is the certificate) so the existing handler seams read the same
    /// fields they always did. `workload` marks the provenance for the
    /// effective accessors.
    #[must_use]
    pub fn from_workload(workload: WorkloadIdentity, env_id: Option<uuid::Uuid>) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            claims: VerifiedClaims {
                sub: format!("m2m-{}", workload.workload),
                iss: String::new(),
                aud: String::new(),
                jti: format!("cert:{}", workload.thumbprint),
                iat: now,
                // No expiry: the identity is the certificate (valid until
                // Acme-side expiry or map revocation, observed within the
                // TTL). The synthetic claims live for the REQUEST only.
                exp: i64::MAX,
                token_tp: "m2m".into(),
                scope: workload.scopes.join(" "),
                env_id: Some(
                    env_id
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| sentin8_config::SYSTEM_ENV_ID.to_string()),
                ),
                email: None,
                act: None,
                vertical: workload.vertical.clone(),
                service_type: workload.service_type.clone(),
            },
            workload: Some(workload),
        }
    }

    /// The caller's vertical for the VDC-2 event-ownership gate — the
    /// map-stamped vertical on the certificate path, the JWT claim on
    /// the bearer path.
    pub fn effective_vertical(&self) -> Option<String> {
        if let Some(w) = &self.workload {
            return w.vertical.clone();
        }
        self.claims.vertical.clone()
    }

    /// The caller's subject for audit stamps — the workload CN on the
    /// certificate path, the JWT `sub` on the bearer path.
    pub fn effective_subject(&self) -> String {
        if let Some(w) = &self.workload {
            return format!("m2m-{}", w.workload);
        }
        self.claims.sub.clone()
    }

    /// Get the environment ID as a `Uuid`.
    pub fn env_id(&self) -> uuid::Uuid {
        self.claims.env_uuid()
    }

    /// Check if the caller has a specific scope — map-granted on the
    /// certificate path, JWT claim on the bearer path.
    pub fn has_scope(&self, scope: &str) -> bool {
        if let Some(w) = &self.workload {
            return w.has_scope(scope);
        }
        self.claims.has_scope(scope)
    }

    /// Check if the token has any of the given scopes (prefix match).
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        self.claims.has_any_scope(scopes)
    }

    /// Check if the caller is a platform admin (has `sentin8:sys:admin` scope).
    pub fn is_platform_admin(&self) -> bool {
        self.claims.is_platform_admin()
    }

    /// Require that the token has at least one of the given scopes.
    /// Platform admins (`sentin8:sys:admin`) bypass the check.
    /// Returns `Ok(())` if authorized, `Err((StatusCode, message))` otherwise.
    pub fn require_any_scope(&self, scopes: &[&str]) -> Result<(), (http::StatusCode, String)> {
        if self.is_platform_admin() || self.has_any_scope(scopes) {
            Ok(())
        } else {
            Err((
                http::StatusCode::FORBIDDEN,
                format!("missing one of scopes: {:?}", scopes),
            ))
        }
    }

    /// Get the subject (user ID or client ID) from the token.
    pub fn sub(&self) -> &str {
        &self.claims.sub
    }

    /// Get the subject as an owned `String` (convenience alias for `sub()`).
    pub fn subject(&self) -> String {
        self.claims.sub.clone()
    }

    /// Subject ID from the token, if present (for identity stitching).
    /// Returns `None` if the `sub` claim is empty.
    pub fn subject_id(&self) -> Option<String> {
        if self.claims.sub.is_empty() {
            None
        } else {
            Some(self.claims.sub.clone())
        }
    }

    /// Holder-scoping primitive: does the token carry
    /// `sentin8:holder:view-all`? (Wraps [`VerifiedClaims::is_holder_view_all`].)
    pub fn is_holder_view_all(&self) -> bool {
        self.claims.is_holder_view_all()
    }

    /// Holder-scoping primitive: is this caller a HOLDER (lacks
    /// `sentin8:holder:view-all`)? (Wraps [`VerifiedClaims::is_holder`].)
    pub fn is_holder(&self) -> bool {
        self.claims.is_holder()
    }
}

/// Extract and verify the Bearer token from the `Authorization` header.
///
/// This is the single canonical implementation — all services should call
/// this instead of maintaining their own `auth.rs` with a duplicated
/// `verify_token` function.
///
/// # Example
/// ```ignore
/// use sentin8_auth_client::{verify_bearer_token, Client};
///
/// async fn example(client: &Client, headers: &http::HeaderMap)
/// -> Result<(), (http::StatusCode, String)> {
///     let auth = verify_bearer_token(client, headers).await?;
///     if !auth.has_scope("ledger:read") {
///         return Err((http::StatusCode::FORBIDDEN, "insufficient scope".into()));
///     }
///     Ok(())
/// }
/// ```
pub async fn verify_bearer_token(
    sentin8_auth_client: &Client,
    headers: &http::HeaderMap,
) -> Result<AuthContext, (http::StatusCode, String)> {
    let auth_header = headers
        .get(http::header::AUTHORIZATION)
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                http::StatusCode::UNAUTHORIZED,
                "missing Authorization header".into(),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            http::StatusCode::UNAUTHORIZED,
            "expected Bearer token".into(),
        )
    })?;

    let claims = sentin8_auth_client.verify_token(token).await.map_err(|e| {
        (
            http::StatusCode::UNAUTHORIZED,
            format!("token verification failed: {e}"),
        )
    })?;

    Ok(AuthContext {
        claims,
        workload: None,
    })
}

/// Resolve a platform-workload identity from the TLS-injected certificate
/// headers against the boot-loaded registry map (, auth DESIGN
/// §4.3f — request-path read, in-memory snapshot, no I/O).
///
/// Returns `Ok(None)` when the request carried NO client certificate
/// (the caller falls through to the bearer path or 401s — user flows keep
/// their JWTs). The TLS layer injects these headers ONLY after
/// CA-verifying the presented certificate (client-supplied copies are
/// stripped before injection) — the same trust model as
/// `X-Sentin8-Env-Id`.
///
/// # Errors
/// Returns the rejection (status + message) for an unenrolled or disabled
/// workload — the authorization record is the map row.
pub async fn resolve_workload_identity(
    registry: &sentin8_workload_registry::WorkloadMap,
    headers: &http::HeaderMap,
) -> Result<Option<crate::WorkloadIdentity>, (http::StatusCode, String)> {
    let Some(subject) = headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None); // no client certificate presented
    };
    let Some(workload) = subject.strip_prefix("m2m-").filter(|w| !w.is_empty()) else {
        return Err((
            http::StatusCode::UNAUTHORIZED,
            format!("certificate CN '{subject}' is not a platform workload identity"),
        ));
    };
    let thumbprint = headers
        .get("x-sentin8-client-cert-thumbprint")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    match registry.get(workload).await {
        Some(rec) if rec.enabled => Ok(Some(crate::WorkloadIdentity {
            workload: workload.to_string(),
            scopes: rec.scopes,
            vertical: Some(rec.vertical),
            service_type: Some(rec.service_type),
            thumbprint,
        })),
        Some(_) => Err((
            http::StatusCode::UNAUTHORIZED,
            format!("workload '{workload}' is disabled (revoked)"),
        )),
        None => Err((
            http::StatusCode::UNAUTHORIZED,
            format!(
                "workload '{workload}' is not enrolled (run vertical enroll for the owning service)"
            ),
        )),
    }
}

/// Like `verify_bearer_token` but returns `Ok(None)` if no Authorization
/// header is present (instead of returning an error). Used by services
/// that accept both authenticated and anonymous requests (e.g. stat
/// public metrics, flow optional auth).
pub async fn verify_bearer_token_opt(
    sentin8_auth_client: &Client,
    headers: &http::HeaderMap,
) -> Result<Option<AuthContext>, (http::StatusCode, String)> {
    if !headers.contains_key(http::header::AUTHORIZATION) && !headers.contains_key("authorization")
    {
        return Ok(None);
    }
    verify_bearer_token(sentin8_auth_client, headers)
        .await
        .map(Some)
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

// ── JWKS types (1.1b.24) ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
}

// ── Admin API types (1.1b.13–1.1b.22) ───────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserSummary {
    pub id: uuid::Uuid,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    pub realm: String,
    pub status: String,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub realm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterApplicationRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthApplication {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeySummary {
    pub id: uuid::Uuid,
    pub name: String,
    pub key_prefix: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionSummary {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub status: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MembershipSummary {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub org_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendInvitationRequest {
    pub email: String,
    pub org_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<uuid::Uuid>,
}

// ── Tests (1.1b.25) ─────────────────────────────────────────────────────

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
    fn client_options_builder() {
        install_provider();
        let opts = ClientOptions::builder()
            .base_url("https://auth.ops.sys.sentin8.local")
            .api_key("test-key")
            .build()
            .unwrap();
        assert_eq!(opts.base_url, "https://auth.ops.sys.sentin8.local");
        assert_eq!(opts.api_key.as_deref(), Some("test-key"));
    }

    #[test]
    fn client_options_builder_validates() {
        assert!(ClientOptions::builder().build().is_err());
    }

    #[test]
    fn client_strips_trailing_slash() {
        install_provider();
        let client = Client::new(ClientOptions {
            base_url: "https://auth.ops.sys.sentin8.local/".into(),
            ..Default::default()
        });
        assert_eq!(client.base_url, "https://auth.ops.sys.sentin8.local");
    }

    #[test]
    fn pkce_s256_matches_rfc_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn generate_pkce_verifier_length() {
        let v = generate_pkce_verifier();
        assert!(v.len() >= 43 && v.len() <= 128, "len = {}", v.len());
    }

    #[test]
    fn url_encoding() {
        assert_eq!(urlencode("hello world"), "hello%20world");
        assert_eq!(urlencode("abc-123"), "abc-123");
    }

    #[test]
    fn discovery_document_deserializes() {
        let json = r#"{
            "issuer": "https://auth.ibank.local",
            "authorization_endpoint": "https://auth.ibank.local/oauth/authorize",
            "token_endpoint": "https://auth.ibank.local/oauth/token",
            "jwks_uri": "https://auth.ibank.local/.well-known/jwks.json",
            "userinfo_endpoint": "https://auth.ibank.local/oauth/userinfo",
            "revocation_endpoint": "https://auth.ibank.local/oauth/revoke",
            "introspection_endpoint": "https://auth.ibank.local/oauth/introspect",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "jwt"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://auth.ibank.local");
        assert_eq!(doc.response_modes_supported, vec!["query", "jwt"]);
        assert!(doc.authorization_response_iss_parameter_supported);
    }

    #[test]
    fn jwkset_deserializes() {
        let json = r#"{"keys":[{"kty":"RSA","kid":"test","alg":"RS256","use":"sig","n":"abc","e":"AQAB"}]}"#;
        let set: JwkSet = serde_json::from_str(json).unwrap();
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].kty, "RSA");
        assert_eq!(set.keys[0].kid.as_deref(), Some("test"));
    }

    #[test]
    fn introspection_response_deserializes() {
        // `realm`/`org_id` were removed from the identity model (see the
        // realm-org-id-removal design note) — env_id is the sole tenant key.
        let json = r#"{"active":true,"scope":"openid profile","sub":"user-123","exp":1700000000,"env_id":"env-1"}"#;
        let resp: IntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(resp.active);
        assert_eq!(resp.sub.as_deref(), Some("user-123"));
        assert_eq!(resp.env_id.as_deref(), Some("env-1"));
    }
}
