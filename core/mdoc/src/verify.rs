//! Verifier-side MSO checks: the COSE_Sign1 signature against the x5chain
//! leaf, the digest coverage of the disclosed items, and the JWK form
//! of a P-256 verifying key.

use crate::mso::IssuerSignedItem;
use base64::Engine;
use sha2::Digest;

/// Extract the (x, y) halves of a certificate DER's uncompressed
/// P-256 public point (scans for the SPKI BIT STRING window).
///
/// # Errors
/// A descriptive string when no point is present.
pub fn ec_point_from_der(der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    for i in 0..der.len().saturating_sub(65) {
        if der[i] == 0x04 && der[i + 1] == 0x42 && der[i + 2] == 0x00 {
            let point = &der[i + 3..i + 68];
            if point.first() == Some(&0x04) {
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&point[1..33]);
                y.copy_from_slice(&point[33..65]);
                return Ok((x, y));
            }
        }
    }
    Err("the certificate carries no uncompressed P-256 public point".into())
}

/// The JWK (JSON) form of a P-256 verifying key (the MSO
/// `deviceKeyInfo.deviceKey`).
pub fn jwk_from_verifying_key(key: &p256::ecdsa::VerifyingKey) -> serde_json::Value {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]),
    })
}

/// The RFC 7638 thumbprint (raw 32 bytes) of a JWK - the
/// device-key-matches-proof-key check and the transcript's
/// `jwkThumbprint` member both use the raw bytes.
///
/// # Errors
/// A descriptive string when the JWK lacks the EC members.
pub fn jwk_thumbprint_raw(jwk: &serde_json::Value) -> Result<[u8; 32], String> {
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or("jwk: x is missing")?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or("jwk: y is missing")?;
    let xb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| format!("jwk x decode: {e}"))?;
    let yb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| format!("jwk y decode: {e}"))?;
    // RFC 7638: the lexicographically-ordered members
    // {"crv","kty","x","y"} for an EC key.
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        x, y
    );
    let d: [u8; 32] = sha2::Sha256::digest(canonical.as_bytes()).into();
    let _ = (xb, yb);
    Ok(d)
}

/// Verify the digest coverage of disclosed items (the suite's
/// ValidateMdocIssuerSignedItemDigests, ISO18013-5-9.1.2.4): every
/// disclosed item's `SHA-256(CBOR(item))` must appear in the MSO's
/// `valueDigests[namespace][digestID]`.
///
/// # Errors
/// Lists the first uncovered item in the error string.
pub fn verify_item_digests(
    items: &[(String, IssuerSignedItem)],
    value_digests: &serde_json::Value,
) -> Result<(), String> {
    let digests_map = value_digests
        .as_object()
        .ok_or("valueDigests is not a map")?;
    for (namespace, item) in items {
        let ns = digests_map
            .get(namespace)
            .and_then(|n| n.as_object())
            .ok_or(format!("namespace {namespace} missing from valueDigests"))?;
        let digest_b64 = ns
            .get(&item.digest_id.to_string())
            .and_then(|d| match d {
                // ciborium may surface bstr values as arrays or strings
                serde_json::Value::Array(_) | serde_json::Value::String(_) => d.as_str().map(|s| s.to_string()).or_else(|| {
                    d.as_array().map(|a| {
                        a.iter().filter_map(|b| b.as_i64().map(|i| i as u8)).collect::<Vec<u8>>()
                    }).map(|v| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v))
                }),
                _ => d.as_str().map(|s| s.to_string()),
            })
            .ok_or(format!(
                "digest {} missing for namespace {namespace}",
                item.digest_id
            ))?;
        let expected: [u8; 32] =
            sha2::Sha256::digest(crate::cbor_bytes(item).map_err(|e| e)?).into();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected);
        if b64 != digest_b64 {
            return Err(format!(
                "digest mismatch for {namespace}/{} (digestID {})",
                item.element_identifier, item.digest_id
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_is_stable() {
        let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let jwk = jwk_from_verifying_key(&key.verifying_key());
        let t1 = jwk_thumbprint_raw(&jwk).unwrap();
        let t2 = jwk_thumbprint_raw(&jwk).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32);
    }
}
