// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic helpers: PKCE, DPoP proof generation, JAR request-object
//! signing, JARM response validation, and minimal URL encoding.
//!
//! Stories 1.3b.4 (JAR), 1.3b.6 (JARM), 1.3b.10 (DPoP).

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::discovery::{DiscoveryDocument, Jwk};
use crate::error::FapiError;

// ── URL encoding ─────────────────────────────────────────────────────────

/// Generate a fresh ES256 (P-256) keypair for DPoP proofs.
///
/// Returns the PKCS#8 PEM of the private key - hand it to
/// [`ClientOptionsBuilder::dpop_key`] (alg `"ES256"`). Sentin8:Auth verifies
/// DPoP proofs against the embedded `jwk` header (self-contained), so no key
/// registration is needed. BFF/proxy callers generate one keypair at startup
/// and reuse it for the process lifetime.
pub fn generate_dpop_key_pem() -> Result<String, FapiError> {
    use p256::ecdsa::signature::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey as _;
    let signing = p256::ecdsa::SigningKey::random(&mut OsRng);
    signing
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map(|p| p.to_string())
        .map_err(|e| FapiError::Config(format!("P-256 keygen failed: {e}")))
}

/// Minimal URL-component encoding (RFC 3986 unreserved set). Avoids a dep.
pub fn url_encode(s: &str) -> String {
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

// ── PKCE S256 ────────────────────────────────────────────────────────────

/// Generate a random PKCE code verifier (43 chars, RFC 7636 §4.1).
pub fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute the PKCE S256 code challenge from a verifier (RFC 7636 §4.2).
pub fn pkce_s256_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ── DPoP proof JWT ───────────────────────────────────────────────────────

/// Claims for a DPoP proof JWT (RFC 9449 §4.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct DpopClaims {
    /// JWT type - always `"dpop+jwt"`.
    pub htm: String,
    /// HTTP target URI (path + query).
    pub htu: String,
    /// Issued-at.
    pub iat: i64,
    /// JWT ID (unique per proof).
    pub jti: String,
    /// Access token hash (ath) - SHA-256 of the access token, base64url no-pad.
    /// Required on protected-resource requests, optional on token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

static DPOP_NONCE: AtomicU64 = AtomicU64::new(0);

/// Derive the public EC P-256 JWK from a PKCS#8 PEM private key.
///
/// DPoP proofs are self-contained: the JWT header MUST embed the public
/// `jwk` so the authorization server can verify the signature without any
/// out-of-band key registration (RFC 9449 §4.2; Sentin8:Auth requires it).
fn ec_public_jwk_from_pem(key_pem: &str) -> Result<jsonwebtoken::jwk::Jwk, FapiError> {
    use jsonwebtoken::jwk::{
        AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType,
        Jwk as JwkJwk,
    };
    use p256::pkcs8::DecodePrivateKey;
    let signing = p256::ecdsa::SigningKey::from_pkcs8_pem(key_pem)
        .map_err(|e| FapiError::Config(format!("parse DPoP key PEM: {e}")))?;
    let verifying = p256::ecdsa::VerifyingKey::from(&signing);
    let point = verifying.to_encoded_point(false); // uncompressed: 04||x||y
    let bytes = point.as_bytes();
    Ok(JwkJwk {
        common: Default::default(),
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]),
            y: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]),
        }),
    })
}

/// Public JWK (sdk discovery `Jwk` shape) for an ES256 P-256 private key PEM.
///
/// CIBA-caller use: the client DCR-registers this JWK (inline `jwks`) so the
/// AS can verify the client's signed request objects / private-key-JWT client
/// assertions against it. Mirrors the DPoP embedded-`jwk` derivation - one
/// derivation for both surfaces.
pub fn ec_public_jwk(key_pem: &str) -> Result<Jwk, FapiError> {
    let inner = ec_public_jwk_from_pem(key_pem)?;
    use jsonwebtoken::jwk::AlgorithmParameters;
    let (x, y, crv) = match &inner.algorithm {
        AlgorithmParameters::EllipticCurve(p) => (p.x.clone(), p.y.clone(), format!("{:?}", p.curve).to_lowercase()),
        _ => return Err(FapiError::Config("not an EC key".into())),
    };
    Ok(Jwk {
        kty: "EC".into(),
        kid: None,
        alg: Some("ES256".into()),
        r#use: Some("sig".into()),
        n: None,
        e: None,
        crv: Some(crv.replace("p256", "P-256")),
        x: Some(x),
        y: Some(y),
    })
}

/// Generate a DPoP proof JWT for the given HTTP method, URI, and optional access token.
///
/// `key_pem` is a PEM-encoded PKCS#8 private key. `alg` must be one of the
/// algorithms advertised in `dpop_signing_alg_values_supported` (e.g. `ES256`, `RS256`).
pub fn dpop_proof(
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    key_pem: &str,
    alg: Algorithm,
) -> Result<String, FapiError> {
    // RFC 9449: the proof header embeds the client's public JWK - the AS
    // verifies the signature against it (self-contained proof). ES256 with
    // a P-256 key is the supported shape; derive the JWK from the PEM.
    if alg != Algorithm::ES256 {
        return Err(FapiError::Config(format!(
            "DPoP proof generation supports ES256 only (got {alg:?}) - generate_dpop_key_pem produces P-256 keys"
        )));
    }
    let jwk = ec_public_jwk_from_pem(key_pem)?;
    let header = Header {
        alg,
        typ: Some("dpop+jwt".to_string()),
        jwk: Some(jwk),
        ..Default::default()
    };
    let ath = access_token.map(|t| {
        let h = Sha256::digest(t.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h)
    });
    let seq = DPOP_NONCE.fetch_add(1, Ordering::Relaxed);
    // RFC 9449 §4.2: jti MUST be unique. The counter alone restarts at 0 on
    // process restart and collides with the AS replay cache (TTL window) -
    // mix in timestamp + fresh random bytes so restarts cannot reuse a jti.
    let mut rand_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rand_bytes);
    let claims = DpopClaims {
        htm: htm.to_string(),
        htu: htu.to_string(),
        iat: Utc::now().timestamp(),
        jti: format!(
            "dpop-{}-{}-{}",
            Utc::now().timestamp_millis(),
            seq,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand_bytes)
        ),
        ath,
    };
    let key = encoding_key(key_pem, alg)?;
    jsonwebtoken::encode(&header, &claims, &key).map_err(Into::into)
}

/// Parse a signing algorithm string from discovery metadata into a `jsonwebtoken::Algorithm`.
pub fn parse_signing_alg(s: &str) -> Result<Algorithm, FapiError> {
    match s {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        _ => Err(FapiError::Dpop(format!("unsupported signing alg: {}", s))),
    }
}

/// Select a signing algorithm: prefer the configured alg, else the first advertised.
pub fn select_signing_alg(
    configured: Option<&str>,
    advertised: &[String],
) -> Result<Algorithm, FapiError> {
    if let Some(c) = configured {
        return parse_signing_alg(c);
    }
    advertised
        .first()
        .ok_or_else(|| FapiError::Config("no signing algorithms advertised".into()))
        .and_then(|s| parse_signing_alg(s))
}

fn encoding_key(pem: &str, alg: Algorithm) -> Result<EncodingKey, FapiError> {
    let result: Result<EncodingKey, String> = match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| e.to_string())
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| e.to_string())
        }
        _ => Err(format!("unsupported key alg: {:?}", alg)),
    };
    result.map_err(|e| FapiError::Dpop(format!("invalid signing key: {}", e)))
}

// ── JAR (signed request object) ──────────────────────────────────────────

/// Claims embedded in a JAR request object JWT (RFC 9101).
///
/// These are the same as the authorize request parameters, wrapped in a signed JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct JarClaims {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// Issuer of the request object - the client ID.
    pub iss: String,
    /// Audience - the authorization server issuer.
    pub aud: String,
    /// Expiry (seconds from now).
    pub exp: i64,
    /// Issued-at.
    pub iat: i64,
    /// JWT ID.
    pub jti: String,
}

/// Build and sign a JAR request object JWT.
///
/// Returns the signed JWT to be sent as `request=` (inline) or pushed via PAR.
pub fn jar_request_object(
    params: &[(&str, &str)],
    client_id: &str,
    issuer: &str,
    key_pem: &str,
    alg: Algorithm,
) -> Result<String, FapiError> {
    let now = Utc::now();
    let exp = now + ChronoDuration::minutes(10);

    let mut claims = JarClaims {
        response_type: get_param(params, "response_type").unwrap_or_else(|| "code".into()),
        client_id: client_id.to_string(),
        redirect_uri: get_param(params, "redirect_uri").unwrap_or_default(),
        scope: get_param(params, "scope").unwrap_or_default(),
        state: get_param(params, "state").unwrap_or_default(),
        code_challenge: get_param(params, "code_challenge").unwrap_or_default(),
        code_challenge_method: get_param(params, "code_challenge_method")
            .unwrap_or_else(|| "S256".into()),
        iss: client_id.to_string(),
        aud: issuer.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: format!("jar-{}", now.timestamp_millis()),
    };
    // Override with any explicit params.
    if let Some(v) = get_param(params, "iss") {
        claims.iss = v;
    }
    if let Some(v) = get_param(params, "aud") {
        claims.aud = v;
    }

    let header = Header {
        alg,
        typ: Some("oauth-authz-req+jwt".to_string()),
        ..Default::default()
    };
    let key = encoding_key(key_pem, alg)?;
    jsonwebtoken::encode(&header, &claims, &key).map_err(Into::into)
}

fn get_param(params: &[(&str, &str)], key: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
}

// ── CIBA signed request object (OpenID CIBA §7.1) ────────────────────────

/// Additional params a client may carry in a backchannel request object.
///
/// Free-form map beside the mandatory JOSE claims (`iss`/`aud`/`exp`/`iat`
/// /`nbf`/`jti`) — CIBA parameters (scope, login_hint, binding_message,
/// user_code, request_mode, client_notification_token, ...) ride here, and
/// the AS overlays them onto the request after signature verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct CibaRequestObject {
    /// Issuer of the object - the client ID (CIBA §7.1.1 required).
    pub iss: String,
    /// Audience - the authorization server issuer (required).
    pub aud: String,
    /// Expiry (seconds). The mandated window is (-5min, +1h) - 10 min is safe.
    pub exp: i64,
    /// Issued-at (seconds). Within (-1d, +5min).
    pub iat: i64,
    /// Not-before (seconds). Within (-10min, +5min) - `iat` + 30s is safe.
    pub nbf: i64,
    /// JWT ID (non-empty string).
    pub jti: String,
    /// The CIBA parameters (+ any additional claims): keys rendered as-is.
    #[serde(flatten)]
    pub params: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Build and sign a CIBA backchannel request object JWT (OpenID CIBA §7.1 /
/// RFC 9101 shape): `iss = client_id`, `aud = the AS issuer` and the CIBA
/// parameters as additional claims. Signed with the caller's registered
/// ES256 P-256 key (the registered `alg` policy excludes `none`/HS/RS256).
///
/// The `typ` header follows the request-object convention
/// (`oauth-authz-req+jwt`, the same class the JAR helper emits). Returns the
/// signed JWT to POST as the `request` form/JSON parameter of
/// `POST /oauth/bc-authorize`.
pub fn ciba_request_object(
    params: &[(String, serde_json::Value)],
    client_id: &str,
    issuer: &str,
    key_pem: &str,
) -> Result<String, FapiError> {
    let now = Utc::now();
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in params {
        map.insert(k.clone(), v.clone());
    }
    let claims = CibaRequestObject {
        iss: client_id.to_string(),
        aud: issuer.to_string(),
        exp: (now + ChronoDuration::minutes(10)).timestamp(),
        iat: now.timestamp(),
        nbf: (now - ChronoDuration::seconds(30)).timestamp(),
        jti: format!("ciba-{}", now.timestamp_millis()),
        params: map,
    };
    let header = Header {
        alg: Algorithm::ES256,
        typ: Some("oauth-authz-req+jwt".to_string()),
        ..Default::default()
    };
    let key = encoding_key(key_pem, Algorithm::ES256)?;
    jsonwebtoken::encode(&header, &claims, &key).map_err(Into::into)
}

// ── JARM response validation ─────────────────────────────────────────────

/// Claims in a JARM response JWT (JWT Secured Authorization Response Mode, RFC 9101/JARM).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields deserialized for validation even when not read by callers
pub struct JarmClaims {
    /// The authorization code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// State echoed from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Error code (if the authorization failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Error description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// Issuer - must match the discovery `issuer`.
    pub iss: String,
    /// Expiry.
    pub exp: i64,
    /// Issued-at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
}

/// Decode and validate a JARM response JWT.
///
/// `jwt` is the `response` parameter from the redirect. The JWT is verified
/// against the issuer's JWKS. The `iss` claim must match `expected_iss`.
pub async fn validate_jarm(
    jwt: &str,
    expected_iss: &str,
    _doc: &DiscoveryDocument,
    jwks: &crate::jwks::JwksCache,
) -> Result<JarmClaims, FapiError> {
    // Parse the JWT header via sentin8_jwt - jsonwebtoken::decode_header
    // fails on non-standard algorithms like MLDSA65.
    let header = sentin8_jwt::decode_header(jwt)
        .map_err(|e| FapiError::Jarm(format!("invalid header: {e}")))?;
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FapiError::Jarm("JARM JWT missing kid header".into()))?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let key = jwks.find_key(kid).await?;

    if alg == "MLDSA65" || key.kty == "MLWE" {
        // ML-DSA-65 verification (manual - jsonwebtoken doesn't support ML-DSA).
        let x = key
            .x
            .as_ref()
            .ok_or_else(|| FapiError::Jarm("MLWE JWK missing x".into()))?;
        use base64::Engine;
        let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| FapiError::Jarm(format!("invalid JWK x: {e}")))?;
        use ml_dsa::{KeyInit, MlDsa65, Verifier};
        let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(&pk_bytes)
            .map_err(|e| FapiError::Jarm(format!("invalid ML-DSA key: {e}")))?;
        let signing_input = sentin8_jwt::signing_input(jwt)
            .map_err(|e| FapiError::Jarm(format!("invalid JWT: {e}")))?;
        let sig_bytes = sentin8_jwt::decode_signature(jwt)
            .map_err(|e| FapiError::Jarm(format!("decode signature: {e}")))?;
        let signature =
            <ml_dsa::Signature<MlDsa65> as std::convert::TryFrom<&[u8]>>::try_from(&sig_bytes)
                .map_err(|e| FapiError::Jarm(format!("decode ML-DSA signature: {e}")))?;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| FapiError::Jarm(format!("ML-DSA signature verification failed: {e}")))?;
        let claims: JarmClaims = sentin8_jwt::decode_payload_typed(jwt)
            .ok_or_else(|| FapiError::Jarm("deserialize claims failed".into()))?;
        if claims.iss != expected_iss {
            return Err(FapiError::IssMismatch {
                expected: expected_iss.to_string(),
                actual: claims.iss,
            });
        }
        return Ok(claims);
    }

    // Standard algorithm path (RS256, ES256, etc.)
    let jwt_alg = parse_algorithm(alg)?;
    let decoding_key = decoding_key_from_jwk(&key, jwt_alg)?;
    let mut validation = Validation::new(jwt_alg);
    validation.set_audience::<String>(&[]); // JARM has no aud; validate iss manually.
    validation.validate_exp = true;
    validation.validate_aud = false;

    let data = jsonwebtoken::decode::<JarmClaims>(jwt, &decoding_key, &validation)
        .map_err(|e| FapiError::Jarm(format!("JWT validation failed: {}", e)))?;

    if data.claims.iss != expected_iss {
        return Err(FapiError::IssMismatch {
            expected: expected_iss.to_string(),
            actual: data.claims.iss,
        });
    }
    Ok(data.claims)
}

/// Parse a signing algorithm string into a `jsonwebtoken::Algorithm`.
fn parse_algorithm(alg: &str) -> Result<Algorithm, FapiError> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(FapiError::Jarm(format!("unsupported algorithm: {other}"))),
    }
}

/// Build a `jsonwebtoken::DecodingKey` from a JWK.
pub fn decoding_key_from_jwk(jwk: &Jwk, alg: Algorithm) -> Result<DecodingKey, FapiError> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| FapiError::Jwks("RSA key missing n".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| FapiError::Jwks("RSA key missing e".into()))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| FapiError::Jwks(format!("invalid RSA key: {}", e)))
        }
        "EC" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| FapiError::Jwks("EC key missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| FapiError::Jwks("EC key missing y".into()))?;
            let _ = alg;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| FapiError::Jwks(format!("invalid EC key: {}", e)))
        }
        _ => Err(FapiError::Jwks(format!(
            "unsupported key type: {}",
            jwk.kty
        ))),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_known_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn url_encoding() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("abc-123"), "abc-123");
        assert_eq!(url_encode("a+b=c"), "a%2Bb%3Dc");
    }

    #[test]
    fn generate_verifier_is_valid_length() {
        let v = generate_pkce_verifier();
        assert!(v.len() >= 43 && v.len() <= 128, "len = {}", v.len());
    }

    #[test]
    fn parse_signing_alg_works() {
        assert_eq!(parse_signing_alg("RS256").unwrap(), Algorithm::RS256);
        assert_eq!(parse_signing_alg("ES256").unwrap(), Algorithm::ES256);
        assert!(parse_signing_alg("HS256").is_err());
    }

    #[test]
    fn select_signing_alg_prefers_configured() {
        let advertised = vec!["RS256".to_string(), "ES256".to_string()];
        assert_eq!(
            select_signing_alg(Some("ES256"), &advertised).unwrap(),
            Algorithm::ES256
        );
    }

    #[test]
    fn select_signing_alg_falls_back_to_first() {
        let advertised = vec!["RS256".to_string()];
        assert_eq!(
            select_signing_alg(None, &advertised).unwrap(),
            Algorithm::RS256
        );
    }

    #[test]
    fn select_signing_alg_errors_when_empty() {
        let advertised: Vec<String> = vec![];
        assert!(select_signing_alg(None, &advertised).is_err());
    }
}
