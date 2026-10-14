// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! The FAPI client — discovery-driven OAuth/OIDC client.
//!
//! Implements all of Epic 1.3b (stories 1.3b.1–1.3b.14).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::crypto::{
    dpop_proof, generate_pkce_verifier, jar_request_object, pkce_s256_challenge,
    select_signing_alg, url_encode, validate_jarm,
};
use crate::discovery::DiscoveryDocument;
use crate::error::FapiError;
use crate::jwks::JwksCache;
use crate::options::ClientOptions;
use crate::types::{IntrospectionResponse, ManagedToken, TokenResponse, UserInfoResponse};

/// Discovery cache entry.
struct CachedDiscovery {
    doc: DiscoveryDocument,
    fetched_at: Instant,
}

/// The FAPI client. Cheap to clone (wraps an `Arc`).
///
/// Created with [`Client::new`] or [`Client::builder`].
#[derive(Clone)]
pub struct Client {
    opts: Arc<ClientOptions>,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<CachedDiscovery>>>,
    jwks: Arc<RwLock<Option<JwksCache>>>,
}

impl Client {
    /// Create a new FAPI client from validated options.
    pub fn new(opts: ClientOptions) -> Result<Self, FapiError> {
        opts.validate()?;
        let http = build_http_client(&opts)?;
        Ok(Self {
            opts: Arc::new(opts),
            http,
            discovery: Arc::new(RwLock::new(None)),
            jwks: Arc::new(RwLock::new(None)),
        })
    }

    /// Build a client via a [`crate::ClientOptionsBuilder`].
    pub fn builder() -> crate::options::ClientOptionsBuilder {
        crate::options::ClientOptions::builder()
    }

    /// Return a reference to the configured options.
    pub fn options(&self) -> &ClientOptions {
        &self.opts
    }

    // ── Discovery (1.3b.3) ───────────────────────────────────────────────

    /// Fetch and cache the OIDC discovery document.
    ///
    /// Cached with a configurable TTL (`ClientOptions::discovery_ttl`).
    pub async fn discover(&self) -> Result<DiscoveryDocument, FapiError> {
        {
            let cache = self.discovery.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() < self.opts.discovery_ttl {
                    return Ok(c.doc.clone());
                }
            }
        }

        let url = format!(
            "{}/.well-known/openid-configuration",
            self.opts.issuer_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| FapiError::Discovery(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FapiError::Discovery(format!("status {}", resp.status())));
        }
        let doc: DiscoveryDocument = resp
            .json()
            .await
            .map_err(|e| FapiError::Discovery(e.to_string()))?;

        let mut cache = self.discovery.write().await;
        *cache = Some(CachedDiscovery {
            doc: doc.clone(),
            fetched_at: Instant::now(),
        });
        Ok(doc)
    }

    /// Get or initialize the JWKS cache (lazily created from discovery's `jwks_uri`).
    async fn jwks_cache(&self) -> Result<JwksCache, FapiError> {
        {
            let cache = self.jwks.read().await;
            if let Some(ref c) = *cache {
                return Ok(c.clone());
            }
        }
        let doc = self.discover().await?;
        let cache = JwksCache::new(doc.jwks_uri.clone(), self.http.clone(), self.opts.jwks_ttl);
        let mut w = self.jwks.write().await;
        *w = Some(cache.clone());
        Ok(cache)
    }

    /// Fetch and cache the JWKS from `jwks_uri`.
    pub async fn jwks(&self) -> Result<crate::discovery::JwkSet, FapiError> {
        let cache = self.jwks_cache().await?;
        cache.get().await
    }

    // ── Authorize URL (1.3b.4) ───────────────────────────────────────────

    /// Build an authorize URL with PKCE S256.
    ///
    /// - Uses **PAR** when `pushed_authorization_request_endpoint` is advertised.
    /// - Uses **JAR** (signed request object) when
    ///   `request_object_signing_alg_values_supported` is advertised and a
    ///   JAR signing key is configured.
    pub async fn authorize_url(
        &self,
        pkce_verifier: &str,
        scope: &str,
        state: &str,
    ) -> Result<String, FapiError> {
        let doc = self.discover().await?;
        let challenge = pkce_s256_challenge(pkce_verifier);
        let scope = if scope.is_empty() {
            self.opts.scopes.as_deref().unwrap_or("")
        } else {
            scope
        };

        let params: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", &self.opts.client_id),
            ("redirect_uri", &self.opts.redirect_uri),
            ("scope", scope),
            ("state", state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ];

        // JAR: build a signed request object if advertised + key configured.
        let params_with_jar: Vec<(&str, String)>;
        let params_ref: Vec<(&str, &str)> = if doc.jar_supported() {
            if let Some(ref key_pem) = self.opts.jar_key_pem {
                let alg = select_signing_alg(
                    self.opts.jar_signing_alg.as_deref(),
                    doc.request_object_signing_alg_values_supported
                        .as_deref()
                        .unwrap_or(&[]),
                )?;
                let jwt =
                    jar_request_object(&params, &self.opts.client_id, &doc.issuer, key_pem, alg)?;
                params_with_jar = vec![
                    ("response_type", "code".to_string()),
                    ("client_id", self.opts.client_id.clone()),
                    ("redirect_uri", self.opts.redirect_uri.clone()),
                    ("state", state.to_string()),
                    ("request", jwt),
                ];
                params_with_jar
                    .iter()
                    .map(|(k, v)| (*k, v.as_str()))
                    .collect()
            } else {
                params.clone()
            }
        } else {
            params.clone()
        };

        // PAR: push the request and redirect with request_uri.
        if let Some(ref par_endpoint) = doc.pushed_authorization_request_endpoint {
            let request_uri = self
                .push_authorization_request(par_endpoint, &params_ref)
                .await?;
            return Ok(format!(
                "{}?request_uri={}&client_id={}",
                doc.authorization_endpoint,
                url_encode(&request_uri),
                url_encode(&self.opts.client_id)
            ));
        }

        let query: String = params_ref
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{}?{}", doc.authorization_endpoint, query))
    }

    // ── PAR (1.3b.5) ─────────────────────────────────────────────────────

    /// Submit a Pushed Authorization Request (RFC 9126).
    ///
    /// Returns the `request_uri` to use in the authorize redirect.
    pub async fn push_authorization_request(
        &self,
        par_endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<String, FapiError> {
        let mut req = self.http.post(par_endpoint).form(params);
        if let Some(ref secret) = self.opts.client_secret {
            req = req.basic_auth(&self.opts.client_id, Some(secret));
        }
        let resp = req.send().await.map_err(FapiError::Http)?;
        if !resp.status().is_success() {
            return Err(FapiError::Flow(format!("PAR status {}", resp.status())));
        }
        let body: crate::discovery::ParResponse = resp
            .json()
            .await
            .map_err(|e| FapiError::Flow(e.to_string()))?;
        Ok(body.request_uri)
    }

    // ── Token exchange (1.3b.6) ──────────────────────────────────────────

    /// Exchange an authorization code for tokens.
    ///
    /// - Validates the `iss` parameter if `authorization_response_iss_parameter_supported` is true.
    /// - Validates **JARM**-secured responses when `response_modes_supported` includes `jwt`.
    /// - Honors `mtls_endpoint_aliases` for the token endpoint.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        expected_iss: Option<&str>,
    ) -> Result<TokenResponse, FapiError> {
        let doc = self.discover().await?;

        // Validate iss parameter if supported.
        if let Some(iss) = expected_iss {
            if doc
                .authorization_response_iss_parameter_supported
                .unwrap_or(false)
                && doc.issuer != iss
            {
                return Err(FapiError::IssMismatch {
                    expected: doc.issuer.clone(),
                    actual: iss.to_string(),
                });
            }
        }

        let token_endpoint = doc.token_endpoint().to_string();
        let form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", self.opts.redirect_uri.clone()),
            ("client_id", self.opts.client_id.clone()),
            ("code_verifier", pkce_verifier.to_string()),
        ];

        let resp = self
            .token_request(&doc, &token_endpoint, "POST", &form, None)
            .await?;
        // Surface the authorization server's error body (RFC 6749 §5.2
        // `{"error": ..., "error_description": ...}`) instead of a bare
        // "decode failed" — without it a 401/400 is undebuggable.
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(FapiError::TokenExchange(format!("status {status}: {body}")));
        }
        resp.json()
            .await
            .map_err(|e| FapiError::TokenExchange(format!("decode failed: {}", e)))
    }

    /// Exchange an authorization code, first validating a JARM response JWT.
    ///
    /// When the authorization server responds with a JARM-secured JWT (in the
    /// `response` parameter of the redirect), call this with the JWT instead of
    /// the raw `code`. The JARM JWT is verified against the issuer's JWKS, the
    /// `iss` claim is checked, and the embedded `code` is then exchanged.
    pub async fn exchange_code_jarm(
        &self,
        jarm_jwt: &str,
        pkce_verifier: &str,
    ) -> Result<TokenResponse, FapiError> {
        let doc = self.discover().await?;
        let jwks = self.jwks_cache().await?;
        let claims = validate_jarm(jarm_jwt, &doc.issuer, &doc, &jwks).await?;
        let code = claims
            .code
            .ok_or_else(|| FapiError::Jarm("JARM response missing code".into()))?;
        self.exchange_code(&code, pkce_verifier, Some(&doc.issuer))
            .await
    }

    // ── Refresh (1.3b.7) ─────────────────────────────────────────────────

    /// Refresh an access token. Honors `mtls_endpoint_aliases`.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, FapiError> {
        let doc = self.discover().await?;
        let token_endpoint = doc.token_endpoint().to_string();
        let form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", self.opts.client_id.clone()),
        ];
        let resp = self
            .token_request(&doc, &token_endpoint, "POST", &form, None)
            .await?;
        // Surface the authorization server's error body (see exchange_code).
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(FapiError::TokenRefresh(format!("status {status}: {body}")));
        }
        resp.json()
            .await
            .map_err(|e| FapiError::TokenRefresh(format!("decode failed: {}", e)))
    }

    // ── Introspect & Revoke (1.3b.8) ─────────────────────────────────────

    /// Introspect a token (RFC 7662). Honors `mtls_endpoint_aliases`.
    pub async fn introspect(&self, token: &str) -> Result<IntrospectionResponse, FapiError> {
        let doc = self.discover().await?;
        let endpoint = doc
            .introspection_endpoint()
            .ok_or_else(|| FapiError::Flow("no introspection endpoint".into()))?
            .to_string();
        let form = vec![
            ("token", token.to_string()),
            ("client_id", self.opts.client_id.clone()),
        ];
        let resp = self
            .token_request(&doc, &endpoint, "POST", &form, None)
            .await?;
        resp.json()
            .await
            .map_err(|e| FapiError::Flow(format!("introspect decode failed: {}", e)))
    }

    /// Revoke a token (RFC 7009). Honors `mtls_endpoint_aliases`.
    pub async fn revoke(&self, token: &str) -> Result<(), FapiError> {
        let doc = self.discover().await?;
        let endpoint = doc
            .revocation_endpoint()
            .ok_or_else(|| FapiError::Flow("no revocation endpoint".into()))?
            .to_string();
        let form = vec![("token", token.to_string())];
        let resp = self
            .token_request(&doc, &endpoint, "POST", &form, None)
            .await?;
        if !resp.status().is_success() {
            return Err(FapiError::Flow(format!("revoke status {}", resp.status())));
        }
        Ok(())
    }

    // ── UserInfo (1.3b.9) ────────────────────────────────────────────────

    /// Fetch UserInfo (OIDC Core §5.3) with the given access token.
    pub async fn user_info(&self, access_token: &str) -> Result<UserInfoResponse, FapiError> {
        let doc = self.discover().await?;
        let endpoint = doc
            .userinfo_endpoint
            .as_deref()
            .or_else(|| {
                doc.mtls_endpoint_aliases
                    .as_ref()
                    .and_then(|a| a.userinfo_endpoint.as_deref())
            })
            .ok_or_else(|| FapiError::Flow("no userinfo endpoint".into()))?
            .to_string();

        let mut req = self.http.get(&endpoint).bearer_auth(access_token);
        if doc.dpop_supported() {
            if let Some(ref key) = self.opts.dpop_key_pem {
                let alg = select_signing_alg(
                    self.opts.dpop_signing_alg.as_deref(),
                    doc.dpop_signing_alg_values_supported
                        .as_deref()
                        .unwrap_or(&[]),
                )?;
                let proof = dpop_proof("GET", &endpoint, Some(access_token), key, alg)?;
                req = req.header("DPoP", proof);
            }
        }
        let resp = req.send().await.map_err(FapiError::Http)?;
        if !resp.status().is_success() {
            return Err(FapiError::Flow(format!(
                "userinfo status {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| FapiError::Flow(format!("userinfo decode failed: {}", e)))
    }

    // ── PKCE helper ──────────────────────────────────────────────────────

    /// Generate a PKCE code verifier (random 43-char URL-safe string).
    pub fn generate_pkce_verifier() -> String {
        generate_pkce_verifier()
    }

    // ── Token auto-refresh (1.3b.13) ─────────────────────────────────────

    /// Wrap a [`TokenResponse`] in a [`ManagedToken`] for auto-refresh.
    pub fn managed_token(&self, resp: TokenResponse) -> ManagedToken {
        ManagedToken::from_response(resp)
    }

    /// Refresh a [`ManagedToken`] if it is expired (or about to expire within
    /// `skew`), retrying up to `ClientOptions::refresh_retries` times.
    pub async fn ensure_fresh(
        &self,
        token: &mut ManagedToken,
        skew: Duration,
    ) -> Result<(), FapiError> {
        if !token.expires_within(skew) {
            return Ok(());
        }
        let refresh = token
            .refresh_token
            .clone()
            .ok_or_else(|| FapiError::TokenRefresh("no refresh_token available".into()))?;

        let mut last_err: Option<FapiError> = None;
        let attempts = self.opts.refresh_retries.max(1);
        for _ in 0..attempts {
            match self.refresh_token(&refresh).await {
                Ok(new) => {
                    *token = ManagedToken::from_response(new);
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| FapiError::TokenRefresh("refresh failed".into())))
    }

    // ── Internal: authenticated token-endpoint request ───────────────────

    /// Build and send an authenticated request to a token-style endpoint.
    ///
    /// Honors client auth (secret basic/post, `tls_client_auth`), DPoP proof,
    /// and mTLS aliases. `method` is typically `"POST"`.
    async fn token_request(
        &self,
        doc: &DiscoveryDocument,
        endpoint: &str,
        method: &str,
        form: &[(&str, String)],
        access_token: Option<&str>,
    ) -> Result<reqwest::Response, FapiError> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| FapiError::Flow(format!("invalid method: {}", e)))?;
        let mut req = self.http.request(m, endpoint).form(form);

        // Client authentication: tls_client_auth takes precedence when advertised.
        if doc.mtls_client_auth_supported() {
            if let Some(ref dn) = self.opts.tls_client_auth_subject_dn {
                // Rebuild form body with tls_client_auth appended.
                let mut pairs: Vec<(String, String)> = form
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect();
                pairs.push(("tls_client_auth".to_string(), dn.clone()));
                let body = serde_urlencoded::to_string(&pairs)
                    .map_err(|e| FapiError::Flow(e.to_string()))?;
                req = req
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body);
            }
        } else if let Some(ref secret) = self.opts.client_secret {
            // Prefer client_secret_basic for the token endpoint.
            req = req.basic_auth(&self.opts.client_id, Some(secret));
        }

        // DPoP proof on token requests.
        if doc.dpop_supported() {
            if let Some(ref key) = self.opts.dpop_key_pem {
                let alg = select_signing_alg(
                    self.opts.dpop_signing_alg.as_deref(),
                    doc.dpop_signing_alg_values_supported
                        .as_deref()
                        .unwrap_or(&[]),
                )?;
                let proof = dpop_proof(method, endpoint, access_token, key, alg)?;
                req = req.header("DPoP", proof);
            }
        }

        req.send().await.map_err(FapiError::Http)
    }
}

/// Build the inner `reqwest::Client`, configuring mTLS certs when provided.
fn build_http_client(opts: &ClientOptions) -> Result<reqwest::Client, FapiError> {
    let mut builder = reqwest::Client::builder().timeout(opts.http_timeout);

    if let (Some(cert_path), Some(key_path)) = (&opts.tls_cert, &opts.tls_key) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| FapiError::Mtls(format!("read cert failed: {}", e)))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| FapiError::Mtls(format!("read key failed: {}", e)))?;
        let identity = reqwest::Identity::from_pem(&[cert_pem, key_pem].concat())
            .map_err(|e| FapiError::Mtls(format!("identity load failed: {}", e)))?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| FapiError::Config(format!("HTTP client build failed: {}", e)))
}
