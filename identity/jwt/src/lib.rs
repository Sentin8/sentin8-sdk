// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JWT decoding utilities for Sentin8.
//!
//! Provides algorithm-agnostic JWT header and payload decoding that works
//! with both standard algorithms (RS256, ES256, EdDSA, etc.) and
//! non-standard algorithms like ML-DSA-65 (`"MLDSA65"`).
//!
//! ## Why not `jsonwebtoken`?
//!
//! The `jsonwebtoken` crate's `decode_header()` and `decode()` functions
//! fail on JWTs with `alg: "MLDSA65"` because they deserialize the `alg`
//! header field into their `Algorithm` enum, which only knows
//! `HS256/384/512`, `ES256/384`, `RS256/384/512`, `PS256/384/512`, and
//! `EdDSA`. Any JWT with a different `alg` value causes a deserialization
//! error.
//!
//! These utilities parse the JWT manually (base64url decode + JSON
//! deserialize) without constraining the `alg` field, making them safe for
//! use with any JWT regardless of the signing algorithm.
//!
//! ## Security
//!
//! These functions do NOT verify JWT signatures. They are for:
//! - Reading the `kid`/`alg` to look up the signing key before verification
//! - Inspecting claims for routing/optimization decisions
//! - Token introspection (where the caller verifies the signature separately)
//!
//! For authorization decisions, always use signature-verified decoding
//! (e.g. `sentin8_auth_client::Client::verify_token()`).

use base64::Engine;
use serde::de::DeserializeOwned;

/// A decoded JWT split into its three base64url-encoded parts.
struct JwtParts<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

/// Split a JWT string into its three dot-separated parts.
fn split_jwt(token: &str) -> Result<JwtParts<'_>, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format: expected 3 parts".into());
    }
    Ok(JwtParts {
        header: parts[0],
        payload: parts[1],
        signature: parts[2],
    })
}

/// Base64url-decode a JWT segment (no padding).
fn decode_segment(segment: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("base64url decode failed: {e}"))
}

/// Decode a JWT header into a raw `serde_json::Value`.
///
/// The header typically contains:
/// - `alg` — the signing algorithm (e.g. `"MLDSA65"`, `"RS256"`)
/// - `kid` — the key ID for JWKS lookup
/// - `typ` — the JWT type (e.g. `"JWT"`, `"dpop+jwt"`)
///
/// Does NOT verify the signature.
pub fn decode_header(token: &str) -> Result<serde_json::Value, String> {
    let parts = split_jwt(token)?;
    let bytes = decode_segment(parts.header)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid header JSON: {e}"))
}

/// Decode a JWT payload (claims) into a raw `serde_json::Value`.
///
/// Does NOT verify the signature.
pub fn decode_payload(token: &str) -> Result<serde_json::Value, String> {
    let parts = split_jwt(token)?;
    let bytes = decode_segment(parts.payload)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid payload JSON: {e}"))
}

/// Decode a JWT header into a typed struct.
///
/// Convenience wrapper around `decode_header` that deserializes into `T`.
/// Does NOT verify the signature.
pub fn decode_header_typed<T: DeserializeOwned>(token: &str) -> Result<T, String> {
    let value = decode_header(token)?;
    serde_json::from_value(value).map_err(|e| format!("header type mismatch: {e}"))
}

/// Decode a JWT payload (claims) into a typed struct.
///
/// Convenience wrapper around `decode_payload` that deserializes into `T`.
/// Returns `None` if the JWT is malformed or the payload doesn't match `T`.
/// Does NOT verify the signature.
pub fn decode_payload_typed<T: DeserializeOwned>(token: &str) -> Option<T> {
    decode_payload(token)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
}

/// Decode the raw signature bytes from a JWT.
///
/// Returns the base64url-decoded signature segment. Needed by callers that
/// perform manual signature verification (e.g. ML-DSA-65).
pub fn decode_signature(token: &str) -> Result<Vec<u8>, String> {
    let parts = split_jwt(token)?;
    decode_segment(parts.signature)
}

/// Get the signing input for signature verification (header.payload).
///
/// This is the `signing_input` that gets hashed/signed — the concatenation
/// of the base64url-encoded header and payload, joined by a dot.
pub fn signing_input(token: &str) -> Result<String, String> {
    let parts = split_jwt(token)?;
    Ok(format!("{}.{}", parts.header, parts.payload))
}

/// Extract the `kid` (key ID) from a JWT header.
///
/// Returns `None` if the JWT is malformed or has no `kid` field.
/// Does NOT verify the signature.
pub fn extract_kid(token: &str) -> Option<String> {
    decode_header(token)
        .ok()
        .and_then(|h| h.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

/// Extract the `alg` (algorithm) from a JWT header.
///
/// Returns `None` if the JWT is malformed or has no `alg` field.
/// Does NOT verify the signature.
pub fn extract_alg(token: &str) -> Option<String> {
    decode_header(token)
        .ok()
        .and_then(|h| h.get("alg").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(header: &str, payload: &str, sig: &str) -> String {
        use base64::Engine;
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("{h}.{p}.{sig}")
    }

    #[test]
    fn decode_header_rs256() {
        let jwt = make_jwt(
            r#"{"alg":"RS256","kid":"key1","typ":"JWT"}"#,
            r#"{"sub":"user123"}"#,
            "signature",
        );
        let header = decode_header(&jwt).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "key1");
    }

    #[test]
    fn decode_header_mldsa65() {
        let jwt = make_jwt(
            r#"{"alg":"MLDSA65","kid":"key2","typ":"JWT"}"#,
            r#"{"sub":"user456"}"#,
            "signature",
        );
        let header = decode_header(&jwt).unwrap();
        assert_eq!(header["alg"], "MLDSA65");
        assert_eq!(header["kid"], "key2");
    }

    #[test]
    fn decode_payload_typed_works() {
        #[derive(serde::Deserialize)]
        struct Claims {
            sub: String,
            scope: String,
        }
        let jwt = make_jwt(
            r#"{"alg":"MLDSA65"}"#,
            r#"{"sub":"user1","scope":"read write"}"#,
            "sig",
        );
        let claims: Claims = decode_payload_typed(&jwt).unwrap();
        assert_eq!(claims.sub, "user1");
        assert_eq!(claims.scope, "read write");
    }

    #[test]
    fn extract_kid_and_alg() {
        let jwt = make_jwt(
            r#"{"alg":"MLDSA65","kid":"mykey"}"#,
            r#"{"sub":"x"}"#,
            "sig",
        );
        assert_eq!(extract_kid(&jwt).as_deref(), Some("mykey"));
        assert_eq!(extract_alg(&jwt).as_deref(), Some("MLDSA65"));
    }

    #[test]
    fn invalid_jwt_returns_error() {
        assert!(decode_header("not.a.jwt").is_err());
        assert!(decode_header("onlyonepart").is_err());
        assert!(decode_payload("two.parts").is_err());
    }

    #[test]
    fn signing_input_correct() {
        use base64::Engine;
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#);
        let jwt = format!("{h}.{p}.signature");
        assert_eq!(signing_input(&jwt).unwrap(), format!("{h}.{p}"));
    }
}
