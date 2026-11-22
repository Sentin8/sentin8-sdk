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
    // the Value tree so every member lands in the canonical form. EACH
    // item rides the ISO Tag24 wrap (#6.24(bstr .cbor IssuerSignedItem)):
    // the suite's ValidateMdocIssuerSignedItemDigests unwraps each
    // namespaced item with DataItem.getAsTaggedEncodedCbor - a PLAIN
    // item map throws 'Failed requirement' there (9 fatal failures +
    // 6 warnings, the live mdoc canary). The digest value is unchanged:
    // getAsTaggedEncodedCbor decodes the wrapped bytes, so the covered
    // input stays the plain item's canonical encoding (what mso.rs
    // digested).
    let mut namespaces = Vec::new();
    for (ns, items) in &built.items {
        let mut arr = Vec::new();
        for it in items {
                let item_map = Value::Map(vec![
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
                ]);
                // Tag24(bstr(item bytes)).
                let item_bytes = crate::cbor_bytes(&item_map)?;
                arr.push(Value::Tag(24, Box::new(Value::Bytes(item_bytes))));
        }
        namespaces.push((
            Value::Text(ns.clone()),
            Value::Array(arr),
        ));
    }

    // The MSO payload: ciborium's serde encode of the Mso struct, then
    // the ISO 18013-5 post-processes the platform's serde bridge cannot
    // express (ciborium's serde has no tag API):
    //   1. the validityInfo dates ride tdate = Tag(0)-wrapped text
    //      (ISO 18013-5 7.1; multipaz's fromDataItem reads them with
    //      getAsDateTimeString, which REQUIRES the Tagged form - a plain
    //      text date dies 'Failed to parse the MSO').
    //   2. deviceKeyInfo.deviceKey rides the COSE_Key map - multipaz's
    //      CoseKey.fromDataItem requires the NUMBER label 1 (kty) to be
    //      present (CoseKey.kt:22's requirement); a JWK (text 'kty')
    //      throws the same 'Failed to parse the MSO'. COSE labels:
    //      1 kty=2(EC2), 3 alg=-7(ES256), -1 crv=1(P-256),
    //      -2.x + -3.y = the raw coordinate bytes.
    let payload = {
        use ciborium::value::Value as V;
        let raw = crate::cbor_bytes(&built.mso)?;
        let mut root: V = ciborium::from_reader(raw.as_slice())
            .map_err(|e| format!("mso redecode: {e}"))?;
        // The root is a Map - walk its members and wrap validityInfo's
        // datetimes in Tag(0).
        if let V::Map(entries) = &mut root {
            for (k, v) in entries.iter_mut() {
                if k.as_text() == Some("validityInfo") {
                    if let V::Map(vi) = v {
                        for (vk, vv) in vi.iter_mut() {
                            if matches!(vk.as_text(), Some("signed") | Some("validFrom") | Some("validUntil") | Some("expectedUpdate")) {
                                if let V::Text(s) = vv {
                                    let s = s.clone();
                                    *vv = V::Tag(0, Box::new(V::Text(s)));
                                }
                            }
                        }
                    }
                } else if k.as_text() == Some("deviceKeyInfo") {
                    // The JWK -> COSE_Key swap: read the coordinates from
                    // the b64url text members, replace the member with the
                    // COSE form (keep devicePrivateKey when present).
                    if let V::Map(dki) = v {
                        for (dk_key, dk_val) in dki.iter_mut() {
                            if dk_key.as_text() == Some("deviceKey") {
                                if let V::Map(jwk) = dk_val {
                                    let read = |entries: &[(V, V)], name: &str| -> Option<Vec<u8>> {
                                        entries.iter().find_map(|(jk, jv)| {
                                            (jk.as_text() == Some(name))
                                                .then(|| jv.as_text())
                                                .flatten()
                                                .and_then(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok())
                                        })
                                    };
                                    let (Some(x), Some(y)) = (read(jwk, "x"), read(jwk, "y")) else {
                                        continue;
                                    };
                                    let cose_key = V::Map(vec![
                                        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
                                        (Value::Integer(3.into()), Value::Integer((-7i64).into())), // alg: ES256
                                        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
                                        (Value::Integer((-2).into()), Value::Bytes(x)), // x
                                        (Value::Integer((-3).into()), Value::Bytes(y)), // y
                                    ]);
                                    *dk_val = cose_key;
                                }
                            }
                        }
                    }
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&root, &mut buf).map_err(|e| format!("mso reencode: {e}"))?;
        buf
    };

    // The protected header: {1: -7} - the x5chain rides the UNPROTECTED
    // headers per the MSO COSE convention (multipaz's
    // MdocUtil.extractX5chain reads CoseSign1.getUnprotectedHeaders()
    // label 33; a protected placement fails the DS-chain conditions).
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(ds_cert_der_std_b64)
        .map_err(|e| format!("x5chain cert decode: {e}"))?;
    let protected_map = Value::Map(vec![(
        Value::Integer((COSE_LABEL_ALG as i64).into()),
        Value::Integer(COSE_ALG_ES256.into()),
    )]);
    let protected = {
        let mut buf = Vec::new();
        ciborium::into_writer(&protected_map, &mut buf)
            .map_err(|e| format!("protected encode: {e}"))?;
        buf
    };
    let unprotected_map = Value::Map(vec![(
        Value::Integer((COSE_LABEL_X5CHAIN as i64).into()),
        Value::Array(vec![Value::Bytes(cert_der)]),
    )]);

    // Sig_structure: ["Signature1", protected(bstr), external_aad(bstr), payload(bstr)]
    // - built via the shared Value-tree helper so the builder and every
    // verifier produce byte-identical input (a hand-rolled length prefix
    // drifted at the bstr boundaries).
    //
    // The MSO rides the COSE payload AS THE ISO 18013-5 TAG24 WRAP
    // (#6.24(bstr .cbor MSO)): the suite's MdocUtil.parseMsoDataItem
    // decodes the payload and calls getAsTaggedEncodedCbor - a plain
    // (untagged) MSO map fails 'Failed to parse the MSO from the mdoc
    // credential' (OIDF-VCIMDOC-1, the live VCI mdoc cells). Both the
    // signature input and the wire payload are the SAME tagged bytes -
    // the Sig_structure carries the payload bstr AS ENCODED (ISO
    // 18013-5 9.1.2.4: the COSE payload element is the Tag24 bytes).
    let payload_tagged: Vec<u8> = {
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Value::Tag(24, Box::new(Value::Bytes(payload.clone()))),
            &mut buf,
        )
        .map_err(|e| format!("mso tag24 wrap: {e}"))?;
        buf
    };
    let sig_structure = cose_sig_structure(&protected, &payload_tagged);
    let sig: p256::ecdsa::Signature = ds_key.sign(&sig_structure);

    // COSE_Sign1: [protected(bstr), {}, payload(tagged-bstr), signature(bstr)]
    let sign1 = Value::Array(vec![
        Value::Bytes(protected),
        unprotected_map,
        Value::Bytes(payload_tagged),
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
pub fn json_to_cbor(v: &serde_json::Value) -> ciborium::value::Value {
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
        serde_json::Value::Object(map) => {
            // The marker forms the serde bridge cannot express as CBOR
            // tags: a single-key object with a __full_date__ / __tdate__
            // marker carries the date/INSTANT as Tag(1004) (the ISO
            // full-date - the EUDI PID Rulebook's birth_date rule) /
            // Tag(0) (tdate). Any other object maps normally.
            if map.len() == 1 {
                if let Some(serde_json::Value::String(s)) = map.get("__full_date__") {
                    return Value::Tag(1004, Box::new(Value::Text(s.clone())));
                }
                if let Some(serde_json::Value::String(s)) = map.get("__tdate__") {
                    return Value::Tag(0, Box::new(Value::Text(s.clone())));
                }
            }
            Value::Map(
                map.iter()
                    .map(|(k, val)| (Value::Text(k.clone()), json_to_cbor(val)))
                    .collect(),
            )
        }
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
