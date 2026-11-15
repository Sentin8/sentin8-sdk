//! The `IssuerSigned` structure (ISO 18013-5 §8.3) - the VCI credential
//! response wire form.
//!
//! `{nameSpaces, issuerAuth}` where `issuerAuth` is a COSE_Sign1 whose
//! payload is the MSO and whose protected header carries the DS
//! certificate `x5chain` (the suite's
//! `ValidateMdocIssuerSignedSignature` verifies the signature against
//! the leaf's EC public key and requires an EC curve pairing with the
//! alg).

use crate::mso::BuiltMso;
use base64::Engine;
use p256::ecdsa::signature::Signer;

/// The COSE_Sign1 protected-header label for `x5chain` (RFC 9360 §2 /
/// COSE label 33, ISO 18013-5 B.3.2 uses label 33).
pub const COSE_LABEL_X5CHAIN: u64 = 33;
/// The COSE_Sign1 protected-header label for `alg` (COSE label 1).
pub const COSE_LABEL_ALG: u64 = 1;
/// The COSE alg for ES256 (-7).
pub const COSE_ALG_ES256: i64 = -7;

/// Build the `IssuerSigned` CBOR map and encode it as unpadded base64url
/// (the OID4VCI credential response string; the suite's
/// `ValidateCredentialIsUnpaddedBase64Url` rejects padding).
///
/// Every nested structure is built as a `ciborium::Value` tree (the
/// encoder is byte-correct by construction - hand-rolled length
/// prefixes drifted on the bstr boundaries). The x5chain entry carries
/// the DS certificate as a COSE bstr (multipaz's
/// `MdocUtil.extractX5chain` reads bstr entries).
///
/// # Errors
/// Returns a descriptive string when the COSE_Sign1 mint fails (the MSO
/// payload encode or the signature).
pub fn build_issuer_signed(
    built: &BuiltMso,
    ds_key: &p256::ecdsa::SigningKey,
    ds_cert_der_std_b64: &str,
) -> Result<String, String> {
    use ciborium::value::Value;
    // nameSpaces: {namespace: [item...]} - the items re-encoded through
    // the Value tree so every member lands in the canonical form.
    let mut namespaces = Vec::new();
    for (ns, items) in &built.items {
        let arr: Vec<Value> = items
            .iter()
            .map(|it| {
                Value::Map(vec![
                    (
                        Value::Text("digestID".into()),
                        Value::Integer((it.digest_id as i64).into()),
                    ),
                    (Value::Text("salt".into()), Value::Bytes(it.salt.clone())),
                    (
                        Value::Text("elementIdentifier".into()),
                        Value::Text(it.element_identifier.clone()),
                    ),
                    (
                        Value::Text("elementValue".into()),
                        json_to_cbor(&it.element_value),
                    ),
                ])
            })
            .collect();
        namespaces.push((
            Value::Text(ns.clone()),
            Value::Array(arr),
        ));
    }

    // The MSO payload: ciborium's serde encode of the Mso struct.
    let payload = crate::cbor_bytes(&built.mso)?;

    // The protected header: {1: -7, 33: [cert-der-bstr]}.
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(ds_cert_der_std_b64)
        .map_err(|e| format!("x5chain cert decode: {e}"))?;
    let protected_map = Value::Map(vec![
        (
            Value::Integer((COSE_LABEL_ALG as i64).into()),
            Value::Integer(COSE_ALG_ES256.into()),
        ),
        (
            Value::Integer((COSE_LABEL_X5CHAIN as i64).into()),
            Value::Array(vec![Value::Bytes(cert_der)]),
        ),
    ]);
    let protected = {
        let mut buf = Vec::new();
        ciborium::into_writer(&protected_map, &mut buf)
            .map_err(|e| format!("protected encode: {e}"))?;
        buf
    };

    // Sig_structure: ["Signature1", protected(bstr), external_aad(bstr), payload(bstr)]
    // - built via the shared Value-tree helper so the builder and every
    // verifier produce byte-identical input (a hand-rolled length prefix
    // drifted at the bstr boundaries).
    let sig_structure = cose_sig_structure(&protected, &payload);
    let sig: p256::ecdsa::Signature = ds_key.sign(&sig_structure);

    // COSE_Sign1: [protected(bstr), {}, payload(bstr), signature(bstr)]
    let sign1 = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![]),
        Value::Bytes(payload),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]);

    // IssuerSigned: {nameSpaces, issuerAuth}
    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), Value::Map(namespaces)),
        (Value::Text("issuerAuth".into()), sign1),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&issuer_signed, &mut buf)
        .map_err(|e| format!("issuer signed encode: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// The COSE Sig_structure bytes: ["Signature1", protected(bstr),
/// external_aad(bstr empty), payload(bstr)] - the ONE canonical builder
/// shared by the issuer mint and every verifier (byte-identical input
/// on both sides).
pub fn cose_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    use ciborium::value::Value;
    let structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(&structure, &mut buf);
    buf
}

/// Convert a JSON value to the ciborium Value form (the elementValue
/// members preserve their JSON shapes).
fn json_to_cbor(v: &serde_json::Value) -> ciborium::value::Value {
    use ciborium::value::Value;
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                Value::Integer(u.into())
            } else {
                Value::Float(n.as_f64().unwrap_or_default())
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(json_to_cbor).collect())
        }
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, val)| (Value::Text(k.clone()), json_to_cbor(val)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_signed_round_trips() {
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let ds_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let built = crate::mso::MsoBuilder::new(
            "org.iso.18013.5.1.mDL",
            &device_key.verifying_key(),
        )
        .validity(1_768_070_400, 1_800_000_000)
        .namespace(
            "org.iso.18013.5.1",
            vec![("family_name".to_string(), serde_json::json!("Doe"))],
        )
        .build();
        // A self-signed DS cert placeholder (the verifier checks the
        // real chain; here only the round-trip shape is tested).
        let cred = build_issuer_signed(&built, &ds_key, "AAECAwQ=")
            .expect("issuer signed");
        assert!(!cred.contains('='));
        // decode: the map opens with A2 and carries the two members
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&cred)
            .unwrap();
        assert_eq!(raw[0], 0xA2);
        assert!(raw.windows(10).any(|w| w == b"nameSpaces"));
    }
}
