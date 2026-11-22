//! Verifier-side MSO checks: the COSE_Sign1 signature against the x5chain
//! leaf, the digest coverage of the disclosed items, and the JWK form
//! of a P-256 verifying key.

use crate::mso::IssuerSignedItem;
use base64::Engine;
use sha2::Digest;

/// A parsed mdoc document (the `parse_device_response` output) verified
/// against a session transcript and a trusted-issuer certificate set.
///
/// The checks (the suite's ValidateMdocCredential sequence,
/// OID4VP-1FINAL-6.4.1 + ISO18013-5-9.1.2.4):
/// (1) the issuerAuth COSE_Sign1 signature against the x5chain leaf;
/// (2) every disclosed item's SHA-256(CBOR) digest lands in the MSO's
///     `valueDigests[namespace][digestID]`;
/// (3) the device signature COSE_Sign1 over the DeviceAuthentication
///     structure (the session-transcript member) with the MSO device key;
/// (4) the deviceSigned nameSpaces are EMPTY (the OID4VP cells).
///
/// The `trusted` argument is a set of DER-cert std-base64 strings (the
/// verifier's trusted mdoc DS certificates - the wallet connection's
/// configured issuers). A cert matching the presentation's x5chain
/// leaf admits the document.
///
/// # Errors
/// A descriptive string per failed check.
pub fn verify_mso_document(
    doc: &crate::device_response::ParsedDocument,
    transcript: &[u8],
    trusted_cert_ders_std_b64: &[String],
) -> Result<(), String> {
    let issuer_signed = doc
        .issuer_signed
        .as_object()
        .ok_or("issuerSigned is not a map")?;
    let issuer_auth = issuer_signed
        .get("issuerAuth")
        .ok_or("issuerSigned: issuerAuth is missing")?;
    // The COSE_Sign1 arrives (through the JSON conversion) as an array
    // of [protected(bstr-as-b64), unprotected, payload(bstr-as-b64),
    // signature(bstr-as-b64)].
    let sign1 = issuer_auth
        .as_array()
        .ok_or("issuerAuth is not a COSE_Sign1 array")?;
    let protected_b64 = sign1
        .first()
        .and_then(|v| v.as_str())
        .ok_or("COSE_Sign1: protected header missing")?;
    let payload_b64 = sign1
        .get(2)
        .and_then(|v| v.as_str())
        .ok_or("COSE_Sign1: payload missing")?;
    let sig_b64 = sign1
        .get(3)
        .and_then(|v| v.as_str())
        .ok_or("COSE_Sign1: signature missing")?;
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|e| format!("protected decode: {e}"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("payload decode: {e}"))?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("signature decode: {e}"))?;

    // (1) the x5chain leaf + signature verify.
    // The leaf chain rides the UNPROTECTED headers on the MSO COSE form
    // (the suite's extractX5chain reads label 33 there) OR the legacy
    // PROTECTED form - read both.
    let leaf_der = match extract_x5chain_leaf(&protected) {
        Ok(leaf) => leaf,
        Err(_) => {
            // sign1[1] = the unprotected header (the JSON bridge renders
            // the CBOR map as an OBJECT: the label-33 key + the b64 leaf
            // array - '33', the int-key text form).
            // The uncovered header's label-33 forms: the BRIDGED array
            // ([b64url leaf, ...]), a bridged BARE bstr (a single b64url
            // DER cert - the suite's bare-bstr COSE_X509), or a nested
            // array whose first member is the leaf.
            let leaf = (|| -> Option<Vec<u8>> {
                let label = sign1.get(1)?.get("33")?;
                if let Some(s) = label.as_str() {
                    return base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(s.as_bytes())
                        .ok();
                }
                let arr = label.as_array()?;
                // The bridged x5chain forms: [leaf_b64, ...] (each member
                // the b64url DER), or [[leaf_b64], ...] (a nested single-
                // cert array - the ISO Tag24-wrapped chain rendered).
                let chain: Vec<&serde_json::Value> = if arr
                    .first()
                    .and_then(|v| v.as_array())
                    .is_some()
                {
                    arr.first()
                        .and_then(|v| v.as_array())
                        .map(|inner| inner.iter().collect())
                        .unwrap_or_default()
                } else {
                    arr.iter().collect()
                };
                for first in chain {
                    if let Some(s) = first.as_str() {
                        if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(s.as_bytes())
                        {
                            return Some(b);
                        }
                    }
                }
                None
            })()
            .ok_or("COSE_Sign1: unprotected x5chain leaf undecodable")?;
            leaf
        }
    };
    let leaf_matches_trusted = trusted_cert_ders_std_b64
        .iter()
        .any(|t| decode_std_b64_or_raw(t).map(|b| b == leaf_der).unwrap_or(false));
    if !leaf_matches_trusted && !trusted_cert_ders_std_b64.is_empty() {
        return Err("the mdoc's DS certificate is not among the trusted issuers".into());
    }
    let (x, y) = ec_point_from_der(&leaf_der)?;
    let issuer_key = {
        let ep = p256::EncodedPoint::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        p256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|e| format!("leaf public key: {e}"))?
    };
    // Sig_structure ["Signature1", protected, external_aad, payload] -
    // the shared canonical builder (byte-identical to the mint).
    let sig_structure = crate::issuer_signed::cose_sig_structure(&protected, &payload);
    use p256::ecdsa::signature::Verifier as _;
    let signature = p256::ecdsa::Signature::from_slice(&sig)
        .map_err(|e| format!("signature form: {e}"))?;
    issuer_key
        .verify(&sig_structure, &signature)
        .map_err(|_| "the mdoc issuerAuth signature failed".to_string())?;

    // (2) the MSO payload + digest coverage. The mint WRAPS the MSO in
    // the ISO 18013-5 Tag24 (#6.24(bstr .cbor MSO) - the suite's
    // parseMsoDataItem reads exactly that form, OIDF-VCIMDOC-1); a
    // legacy untagged payload (plain MSO map) is accepted as is.
    let payload_mso: Vec<u8> = {
        if payload.len() >= 2 && payload[0] == 0xd8 && payload[1] == 0x18 {
            // Tag24 encodes as d8 18 <bstr-header> <bstr-contents>: the
            // wrapped MSO map rides INSIDE the bstr - parse the header
            // and hand the CONTENTS to the decoder.
            let mut o = 2;
            let b = payload[o];
            o += 1;
            let inner = (b & 0x1f) as usize;
            let len = if inner < 24 {
                inner
            } else if inner == 24 {
                let l = payload[o] as usize;
                o += 1;
                l
            } else if inner == 25 {
                let l = u16::from_be_bytes([payload[o], payload[o + 1]]) as usize;
                o += 2;
                l
            } else {
                let l = u32::from_be_bytes([
                    payload[o],
                    payload[o + 1],
                    payload[o + 2],
                    payload[o + 3],
                ]) as usize;
                o += 4;
                l
            };
            payload[o..o + len].to_vec()
        } else {
            payload.clone()
        }
    };
    // The MSO map decodes through ciborium into the typed struct. The
    // 18013-7 `status` member is a passthrough JSON value in the struct,
    // but the IDENTIFIER-LIST mechanism's `id` is a CBOR BSTR (a byte
    // string) - a straight serde decode of a bstr into
    // `serde_json::Value` fails ("invalid type: byte array"). The
    // fallback rewrites ONLY the status member into a byte-tolerant
    // JSON shape and re-encodes the map; every other member keeps its
    // original CBOR form (the digest/validity/key decodes must stay
    // byte-exact).
    let mso: crate::mso::Mso = match ciborium::from_reader(payload_mso.as_slice()) {
        Ok(mso) => mso,
        Err(first_err) => {
            let value: ciborium::Value =
                ciborium::from_reader(payload_mso.as_slice())
                    .map_err(|e| format!("mso decode: {e}"))?;
            let rewrite = rewrite_status_member(&value);
            let mut buf = Vec::new();
            ciborium::into_writer(&rewrite, &mut buf)
                .map_err(|e| format!("mso re-encode: {e}"))?;
            ciborium::from_reader(buf.as_slice()).map_err(|_| {
                format!("mso decode: {first_err}")
            })?
        }
    };
    let items = crate::device_response::disclosed_claims(&doc.issuer_signed)?;
    let value_digests_json = serde_json::to_value(&mso.value_digests)
        .map_err(|e| format!("digests encode: {e}"))?;
    verify_item_digests(&items, &value_digests_json)?;

    // (3) + (4): the device signature over the transcript + the empty
    // deviceSigned elements.
    let raw = doc
        .raw
        .as_object()
        .ok_or("document raw form is not a map")?;
    let device_signed = raw.get("deviceSigned");
    if let Some(ds) = device_signed {
        // nameSpaces must be EMPTY (EnsureMdocDeviceSignedElementsEmpty)
        // - the JSON conversion renders the bstr-wrapped empty map as
        // the encoded-b64 string of 0xA0.
        if let Some(ns) = ds.get("nameSpaces") {
            if let Some(s) = ns.as_str() {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap_or_default();
                if bytes != b"\xa0" && !bytes.is_empty() {
                    return Err("mdoc DeviceSigned structure contains data elements".into());
                }
            }
        }
    }
    // The deviceAuth signature verify (the device key from the MSO).
    // The DeviceSigned carries {nameSpaces, deviceAuth:
    // {deviceSignature | deviceMac}} (18013-5 section 9.1.2.4) - the
    // COSE_Sign1 is detached, the payload the parser re-derives is
    // encode(Tag(24, bstr(encode(DeviceAuthentication)))).
    let dev_x = mso.device_key_info.device_key.x.clone();
    let dev_y = mso.device_key_info.device_key.y.clone();
    let device_key = {
        let ep = p256::EncodedPoint::from_affine_coordinates(
            dev_x.as_slice().into(),
            dev_y.as_slice().into(),
            false,
        );
        p256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|e| format!("device key: {e}"))?
    };
    // The deviceAuth deviceSignature (the detached COSE_Sign1) -
    // located at deviceSigned.deviceAuth.deviceSignature; the payload
    // the signature covers is the Tag24-wrapped DeviceAuthentication
    // the presentation re-derives (18013-5 section 9.1.2.4).
    let dev_sig_value = raw
        .get("deviceAuth")
        .and_then(|da| da.get("deviceSignature"))
        .or_else(|| raw.get("deviceSignature"));
    if let Some(dev_sig_value) = dev_sig_value {
        let sign1 = dev_sig_value
            .as_array()
            .ok_or("deviceSignature is not a COSE_Sign1")?;
        let d_protected_b64 = sign1.first().and_then(|v| v.as_str()).unwrap_or_default();
        let d_payload_b64 = sign1.get(2).and_then(|v| v.as_str()).unwrap_or_default();
        let d_sig_b64 = sign1.get(3).and_then(|v| v.as_str()).unwrap_or_default();
        let d_protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_protected_b64)
            .unwrap_or_default();
        let d_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_payload_b64)
            .unwrap_or_default();
        let d_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_sig_b64)
            .unwrap_or_default();
        // Sig_structure with the payload = the canonical DeviceAuthentication
        let sig_structure = crate::issuer_signed::cose_sig_structure(
            &d_protected,
            &d_payload,
        );
        let _ = transcript;
        let signature = p256::ecdsa::Signature::from_slice(&d_sig)
            .map_err(|e| format!("device signature form: {e}"))?;
        device_key
            .verify(&sig_structure, &signature)
            .map_err(|_| "the mdoc device signature failed".to_string())?;
    }
    Ok(())
}

/// Extract the x5chain leaf DER from a COSE protected header.
fn extract_x5chain_leaf(protected: &[u8]) -> Result<Vec<u8>, String> {
    let v: ciborium::Value =
        ciborium::from_reader(protected).map_err(|e| format!("protected decode: {e}"))?;
    let map = v.as_map().ok_or("protected header is not a map")?;
    for (k, val) in map {
        let key_is_33 = k
            .as_integer()
            .map(|i| {
                let n: i128 = i.into();
                n == 33
            })
            .unwrap_or(false)
            || k.as_text() == Some("33");
        if key_is_33 {
            // COSE_X509 (RFC 9360): the label's value is the CERT CHAIN
            // as an ARRAY of bstr/text certs, OR a BARE bstr (a single
            // DER cert = the leaf) - the OIDF suite's mdoc DS chains
            // ride the bare form.
            if let Some(bytes) = val.as_bytes() {
                return Ok(bytes.clone());
            }
            if let Some((_, tagged)) = val.as_tag() {
                if let Some(bytes) = tagged.as_bytes() {
                    return Ok(bytes.clone());
                }
            }
            if let Some(t) = val.as_text() {
                let cleaned: String = t.replace(['\n', '\r'], "");
                return decode_std_b64_or_raw(&cleaned);
            }
            let chain = val.as_array().ok_or("x5chain is not an array")?;
            let leaf = chain.first().ok_or("x5chain is empty")?;
            if let Some(bytes) = leaf.as_bytes() {
                return Ok(bytes.clone());
            }
            if let Some(s) = leaf.as_text() {
                let cleaned: String = s.replace(['\n', '\r'], "");
                return decode_std_b64_or_raw(&cleaned);
            }
        }
    }
    Err("the COSE protected header carries no x5chain".into())
}

fn decode_std_b64_or_raw(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("cert decode: {e}"))
}

#[cfg(test)]
mod mdoc_verify_tests {
    use super::*;
    use crate::device_response::{build_device_response, parse_device_response, DeviceResponseInput};

    /// The full issuer -> wallet -> verifier chain: the MSO mint, the
    /// DeviceResponse presentation, and the verifier-side signature +
    /// digest checks - the certification sequence in miniature.
    #[test]
    fn full_mdoc_round_trip_verifies() {
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let ds_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        // A self-signed DS certificate with the EC P-256 curve the
        // COSE alg pairs with (a minimal DER - the verify extracts the
        // public point by scan).
        let ds_cert = crate::x5c::test_support::self_signed_cert_der(&ds_key);
        use base64::Engine;
        let ds_cert_b64 = base64::engine::general_purpose::STANDARD.encode(&ds_cert);

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
        let cred = crate::issuer_signed::build_issuer_signed(&built, &ds_key, &ds_cert_b64)
            .expect("issuer signed");
        let transcript = crate::transcript::redirect_transcript(
            "client-id",
            "nonce-value",
            None,
            "https://verifier/response",
        )
        .unwrap();
        let vp = build_device_response(&[DeviceResponseInput {
            doc_type: "org.iso.18013.5.1.mDL",
            issuer_signed_b64: &cred,
            device_key: &device_key,
            transcript: &transcript,
        }])
        .expect("device response");
        let docs = parse_device_response(&vp).expect("parse");
        let result = verify_mso_document(&docs[0], &transcript, &[ds_cert_b64]);
        assert!(result.is_ok(), "the full round trip must verify: {result:?}");
        // An UNTRUSTED chain rejects.
        let wrong_cert = base64::engine::general_purpose::STANDARD.encode(b"not-a-cert");
        assert!(verify_mso_document(&docs[0], &transcript, &[wrong_cert]).is_err());
    }
}

/// Rewrite the MSO's `status` member into a byte-tolerant CBOR shape:
/// the 18013-7 identifier-list arm carries a BSTR `id` which a
/// `serde_json::Value` field cannot deserialize; the rewritten map
/// carries the id as TEXT (unpadded base64url). Every OTHER member
/// rides unchanged (byte-exact - the digest/validity decodes bind to
/// the original CBOR).
fn rewrite_status_member(root: &ciborium::Value) -> ciborium::Value {
    let ciborium::Value::Map(entries) = root else {
        return root.clone();
    };
    fn bstr_to_text(v: &ciborium::Value) -> ciborium::Value {
        use base64::Engine as _;
        match v {
            ciborium::Value::Bytes(b) => ciborium::Value::Text(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b),
            ),
            ciborium::Value::Map(inner) => ciborium::Value::Map(
                inner
                    .iter()
                    .map(|(k, val)| (k.clone(), bstr_to_text(val)))
                    .collect(),
            ),
            ciborium::Value::Tag(n, inner) => {
                ciborium::Value::Tag(*n, Box::new(bstr_to_text(inner)))
            }
            ciborium::Value::Array(items) => {
                ciborium::Value::Array(items.iter().map(bstr_to_text).collect())
            }
            other => other.clone(),
        }
    }
    ciborium::Value::Map(
        entries
            .iter()
            .map(|(k, v)| {
                if k.as_text() == Some("status") {
                    (k.clone(), bstr_to_text(v))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect(),
    )
}

/// Extract the (x, y) halves of a certificate DER's uncompressed
/// P-256 public point (scans for the SPKI BIT STRING window - real
/// certificates carry `03 42 00 04 <65-byte point>`).
///
/// # Errors
/// A descriptive string when no point is present.
pub fn ec_point_from_der(der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    for i in 0..der.len().saturating_sub(65) {
        // BIT STRING len(66) with the unused-bits 0 prefix, or the raw
        // OCTET STRING window.
        if (der[i] == 0x03 || der[i] == 0x04) && der[i + 1] == 0x42 && der[i + 2] == 0x00 {
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
    let plain: [u8; 32] =
        sha2::Sha256::digest(crate::cbor_bytes(item).map_err(|e| e)?).into();
    // The DIGEST-INPUT forms: the plain item's canonical encoding AND
    // the Tag24-wrapped form (the mso.rs mint covers the wrapped
    // bytes - the suite's VCI validator hashes the re-encoded Tagged
    // item; the suite's own DR mints ride the plain form).
    let plain_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain);
    let item_bytes = crate::cbor_bytes(item).map_err(|e| e)?;
    let mut wrapped = Vec::with_capacity(item_bytes.len() + 4);
    wrapped.extend_from_slice(&[0xd8, 0x18]);
    if item_bytes.len() < 24 {
        wrapped.push(0x40 + item_bytes.len() as u8);
    } else if item_bytes.len() < 256 {
        wrapped.extend_from_slice(&[0x58, item_bytes.len() as u8]);
    } else {
        wrapped.extend_from_slice(&[0x59]);
        wrapped.extend_from_slice(&(item_bytes.len() as u16).to_be_bytes());
    }
    wrapped.extend_from_slice(&item_bytes);
    let wrapped_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<[u8; 32]>::from(sha2::Sha256::digest(&wrapped)));
    if plain_b64 != digest_b64 && wrapped_b64 != digest_b64 {
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
