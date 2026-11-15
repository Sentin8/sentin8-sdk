//! The x5c leaf helpers - the DS (document signer) material resolution
//! shared by the issuer mint and the verifier chain check.

use base64::Engine;

/// The std-base64 DER -> PEM form of an x5c leaf entry.
///
/// # Errors
/// A descriptive string on decode failure.
pub fn x5c_leaf_pem(cert_std_b64: &str) -> Result<String, String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(cert_std_b64)
        .map_err(|e| format!("x5c leaf DER decode: {e}"))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).map_err(|e| e.to_string())?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    Ok(pem)
}

/// The P-256 signing key whose public point matches a certificate PEM's
/// subject public key, resolved from a candidate private-PEM list (the
/// caller supplies the persisted key material - the engine holds no
/// storage).
///
/// # Errors
/// A descriptive string when no candidate matches.
pub fn signing_key_matching_cert(
    cert_pem: &str,
    candidate_private_pems: &[String],
) -> Result<p256::ecdsa::SigningKey, String> {
    use p256::elliptic_curve::pkcs8::DecodePrivateKey;
    // Parse the cert's public point (scan the DER inside the PEM for
    // the 65-byte uncompressed point).
    let der = pem_to_der(cert_pem)?;
    let point = crate::verify::ec_point_from_der(&der)?;
    let (x, y) = point;
    let target = {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        let ep = p256::EncodedPoint::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        p256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|e| format!("cert public key: {e}"))?
    };
    for pem in candidate_private_pems {
        if let Ok(secret) = p256::SecretKey::from_pkcs8_pem(pem) {
            let candidate = p256::ecdsa::SigningKey::from(&secret);
            if candidate.verifying_key() == &target {
                return Ok(candidate);
            }
        }
    }
    Err("no persisted signing key matches the x5c leaf certificate".into())
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
        .ok_or("the PEM carries no CERTIFICATE block")?;
    let cleaned: String = body.replace(['\n', '\r'], "");
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.trim())
        .map_err(|e| format!("pem body decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trip() {
        use base64::Engine;
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = x5c_leaf_pem(&b64).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        let back = pem_to_der(&pem).unwrap();
        assert_eq!(back, der);
    }
}
