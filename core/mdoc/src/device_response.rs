//! The `DeviceResponse` (ISO/IEC 18013-7 §8) - the OID4VP vp_token wire
//! form the wallet sends and the verifier parses.
//!
//! `[version, [{status, documents: [...]}], status]` where each Document
//! is `{docType, issuerSigned, deviceSigned, deviceSignature}`:
//!
//! - `issuerSigned`: the issuer's `{nameSpaces, issuerAuth}` (the
//!   disclosed items only - selective disclosure by digestID).
//! - `deviceSigned`: `{nameSpaces: bstr(""), digestInfo: {deviceDigests,
//!   deviceKeyInfo}}` - EMPTY digests for the OID4VP cells (the suite's
//!   EnsureMdocDeviceSignedElementsEmpty).
//! - `deviceSignature`: COSE_Sign1 over
//!   `[deviceNameSpace bytes, sessionTranscript bytes]` with the
//!   device's MSO-bound key.

use crate::mso::IssuerSignedItem;

/// The DeviceResponse version member (18013-7 defines `1.0`).
pub const DEVICE_RESPONSE_VERSION: &str = "1.0";

/// The wallet's input for one document presentation.
pub struct DeviceResponseInput<'a> {
    /// The doctype.
    pub doc_type: &'a str,
    /// The disclosed `IssuerSigned` (the exact base64url string the
    /// issuance returned - the wallet re-sends it verbatim; the MSO
    /// digest coverage is verified issuer-side).
    pub issuer_signed_b64: &'a str,
    /// The device key that signs (the MSO-bound P-256 key).
    pub device_key: &'a p256::ecdsa::SigningKey,
    /// The session-transcript CBOR bytes (B.2.6.1/6.2).
    pub transcript: &'a [u8],
}

/// Build the DeviceResponse as unpadded base64url (the vp_token array
/// entry; `ValidateCredentialIsUnpaddedBase64Url`).
///
/// # Errors
/// Descriptive strings on decode/encode failures.
pub fn build_device_response(inputs: &[DeviceResponseInput<'_>]) -> Result<String, String> {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    let mut documents = Vec::new();
    for input in inputs {
        let issuer_signed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input.issuer_signed_b64)
            .map_err(|e| format!("issuer signed decode: {e}"))?;

        // deviceNameSpace: CBOR bytes of an empty map
        let device_name_space = b"\xa0".to_vec();
        // deviceDigests: empty map
        let digest_info: serde_json::Value = serde_json::json!({
            "deviceDigests": {},
            "deviceKeyInfo": {
                "deviceKey": crate::verify::jwk_from_verifying_key(&input.device_key.verifying_key()),
            },
        });
        let digest_info_bytes = crate::cbor_bytes(&digest_info)?;

        // deviceSignature input: [deviceNameSpace(bstr), sessionTranscript(bstr),
        // deviceNameSpaces(bstr), digestInfo(bstr)] per 18013-5 §8.3.2.1.1:
        // actually DeviceAuthentication = ["DeviceAuthentication", sessionTranscript,
        // deviceNameSpaces bytes, digestInfo bytes]
        let mut da = Vec::new();
        da.push(0x84); // array(4)
        da.push(0x6C); // tstr(12)
        da.extend_from_slice(b"DeviceAuthentication");
        // sessionTranscript as bstr
        da.push(0x58);
        da.push(input.transcript.len() as u8);
        da.extend_from_slice(input.transcript);
        // deviceNameSpaces
        da.push(0x58);
        da.push(device_name_space.len() as u8);
        da.extend_from_slice(&device_name_space);
        // digestInfo
        da.push(0x58);
        da.push(digest_info_bytes.len() as u8);
        da.extend_from_slice(&digest_info_bytes);
        let sig: p256::ecdsa::Signature = input.device_key.sign(&da);
        let sig_bytes = sig.to_bytes();

        // COSE_Sign1: [protected{alg:-7}, {}, payload(bstr da), sig]
        let protected = b"\xa1\x01\x26".to_vec(); // {1: -7}
        let mut sign1 = Vec::new();
        sign1.push(0x84);
        sign1.push(0x43); // bytes(3)
        sign1.extend_from_slice(&protected);
        sign1.push(0xA0);
        sign1.push(0x58);
        sign1.push(da.len() as u8);
        sign1.extend_from_slice(&da);
        sign1.push(0x58);
        sign1.push(sig_bytes.len() as u8);
        sign1.extend_from_slice(&sig_bytes);

        // Document: {docType, issuerSigned, deviceSigned, deviceSignature}
        let mut doc = Vec::new();
        doc.push(0xA4); // map(4)
        doc.push(0x67);
        doc.extend_from_slice(b"docType");
        let doctype = input.doc_type.as_bytes();
        doc.push(0x78); // tstr(1-byte len)
        doc.push(doctype.len() as u8);
        doc.extend_from_slice(doctype);
        doc.extend_from_slice(b"\x6CissuerSigned");
        // issuerSigned bytes inline
        doc.push(0x5A); // bytes(4-byte len)
        doc.extend_from_slice(&(issuer_signed.len() as u32).to_be_bytes());
        doc.extend_from_slice(&issuer_signed);
        doc.extend_from_slice(b"\x6CdeviceSigned");
        // deviceSigned: {nameSpaces: bstr(""), digestInfo: {...}}
        let device_signed = {
            let mut ds = Vec::new();
            ds.push(0xA2);
            ds.extend_from_slice(b"\x6AnameSpaces");
            ds.push(0x41); // bstr(1)
            ds.push(0xA0); // the empty map bytes
            ds.extend_from_slice(b"\x6AdigestInfo");
            ds.push(0x59);
            ds.extend_from_slice(&(digest_info_bytes.len() as u16).to_be_bytes());
            ds.extend_from_slice(&digest_info_bytes);
            ds
        };
        doc.push(0x59);
        doc.extend_from_slice(&(device_signed.len() as u16).to_be_bytes());
        doc.extend_from_slice(&device_signed);
        doc.extend_from_slice(b"\x6FdeviceSignature");
        doc.push(0x59);
        doc.extend_from_slice(&(sign1.len() as u16).to_be_bytes());
        doc.extend_from_slice(&sign1);
        documents.extend_from_slice(&doc);
    }

    // The response: [version(tstr), [{status: 0, documents: [...]}](1), status: 1]
    let mut buf = Vec::new();
    buf.push(0x83); // array(3)
    buf.push(0x63); // tstr(3)
    buf.extend_from_slice(b"1.0");
    buf.push(0x81); // array(1)
    // {status: 1, documents: array(N)}
    buf.push(0xA2);
    buf.extend_from_slice(b"\x66status"); // tstr(6)
    buf.push(0x01);
    buf.extend_from_slice(b"\x69documents"); // tstr(9)
    // documents array of N document maps - each document was appended
    // raw; wrap in array(N)
    let n = inputs.len() as u8;
    if n == 1 {
        buf.push(0x81);
    } else {
        buf.push(0x80 + n); // small-array form
    }
    buf.extend_from_slice(&documents);
    buf.push(0x01); // status: 1 (OK)

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// Parse a DeviceResponse presentation: returns the per-document
/// `docType`, the raw `issuerSigned` bytes, and the deviceSignature
/// structure for verifier-side checking.
///
/// The DeviceResponse carries CBOR byte-string members (issuerSigned,
/// signatures) that have no JSON form - the parse walks the raw
/// structure with ciborium's own `serde` bridge over a bstr-tolerant
/// value type (the parse re-encodes bstr members as base64url strings
/// inside the returned JSON tree, tagged in the parse order).
///
/// # Errors
/// Descriptive strings on decode failures.
pub fn parse_device_response(
    b64: &str,
) -> Result<Vec<ParsedDocument>, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64url decode: {e}"))?;
    // Parse with a bstr-tolerant decode: ciborium's Value (not JSON).
    let v: ciborium::Value =
        ciborium::from_reader(raw.as_slice()).map_err(|e| format!("cbor decode: {e}"))?;
    let groups = v
        .as_array()
        .and_then(|a| a.get(1))
        .and_then(|g| g.as_array())
        .ok_or("DeviceResponse: the document group array is missing")?;
    let first = groups
        .first()
        .ok_or("DeviceResponse: an empty document group")?
        .as_map()
        .ok_or("DeviceResponse: the document group is not a map")?;
    let find = |key: &str| -> Option<ciborium::Value> {
        first
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v.clone())
    };
    let docs = find("documents")
        .and_then(|d| d.as_array().cloned())
        .ok_or("DeviceResponse: documents array is missing")?;
    let mut out = Vec::new();
    for doc in docs {
        let obj = doc
            .as_map()
            .ok_or("DeviceResponse: a document is not a map")?
            .clone();
        let get = |key: &str| -> Option<ciborium::Value> {
            obj.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v.clone())
        };
        let doc_type = get("docType")
            .and_then(|d| d.as_text().map(str::to_string))
            .ok_or("DeviceResponse: docType is missing")?;
        let issuer_signed_cbor = get("issuerSigned").ok_or("issuerSigned missing")?;
        // The issuerSigned member rides as a CBOR bstr (bytes) or as the
        // inline map - accept both forms (the builder embeds the raw
        // bytes; multipaz wallets embed the map).
        let issuer_signed_json = match issuer_signed_cbor.as_bytes() {
            Some(bytes) => {
                let inner: ciborium::Value = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| format!("issuerSigned inner decode: {e}"))?;
                ciborium_value_to_json(&inner)
            }
            None => ciborium_value_to_json(&issuer_signed_cbor),
        };
        out.push(ParsedDocument {
            doc_type,
            issuer_signed: issuer_signed_json,
            raw: ciborium_value_to_json(&doc),
        });
    }
    Ok(out)
}

/// Convert a ciborium Value tree to JSON (bstr members become
/// unpadded-base64url strings).
fn ciborium_value_to_json(v: &ciborium::Value) -> serde_json::Value {
    use base64::Engine;
    match v {
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            serde_json::json!(n)
        }
        ciborium::Value::Bytes(b) => serde_json::json!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        ),
        ciborium::Value::Float(f) => serde_json::json!(f),
        ciborium::Value::Text(t) => serde_json::json!(t),
        ciborium::Value::Bool(b) => serde_json::json!(b),
        ciborium::Value::Null => serde_json::Value::Null,
        ciborium::Value::Array(items) => serde_json::Value::Array(
            items.iter().map(ciborium_value_to_json).collect(),
        ),
        ciborium::Value::Map(entries) => {
            let mut m = serde_json::Map::new();
            for (k, val) in entries {
                let key = match k {
                    ciborium::Value::Text(t) => t.clone(),
                    ciborium::Value::Integer(i) => {
                        let n: i128 = (*i).into();
                        format!("{n}")
                    }
                    ciborium::Value::Bytes(b) => {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
                    }
                    _ => continue,
                };
                m.insert(key, ciborium_value_to_json(val));
            }
            serde_json::Value::Object(m)
        }
        _ => serde_json::Value::Null,
    }
}

/// One parsed document of a DeviceResponse.
pub struct ParsedDocument {
    /// The document's doctype.
    pub doc_type: String,
    /// The issuerSigned member (the parsed CBOR value).
    pub issuer_signed: serde_json::Value,
    /// The raw parsed document value.
    pub raw: serde_json::Value,
}

/// Extract the disclosed `(namespace, elementIdentifier, value)` triples
/// from an issuerSigned member (verifier-side claim matching against the
/// DCQL query). The salt may arrive as a CBOR bstr (parsed to
/// unpadded-base64url by the value conversion) or as a raw JSON array -
/// both decode to the digestable item form.
///
/// # Errors
/// Descriptive strings on malformed items.
pub fn disclosed_claims(
    issuer_signed: &serde_json::Value,
) -> Result<Vec<(String, IssuerSignedItem)>, String> {
    let ns = issuer_signed
        .get("nameSpaces")
        .and_then(|n| n.as_object())
        .ok_or("issuerSigned: nameSpaces is missing")?;
    let mut out = Vec::new();
    for (namespace, items) in ns {
        let arr = items.as_array().ok_or("nameSpaces: a namespace is not an array")?;
        for item in arr {
            let mut item_json = item.clone();
            // The bstr salt arrives as a base64url string after the
            // ciborium->JSON conversion; IssuerSignedItem's serde wants
            // the raw bytes - decode into the `salt` member's raw form.
            if let Some(s) = item_json
                .get("salt")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&s)
                    .unwrap_or_default();
                if let Some(obj) = item_json.as_object_mut() {
                    obj.insert(
                        "salt".into(),
                        serde_json::Value::Array(
                            bytes.iter().map(|b| serde_json::json!(b)).collect(),
                        ),
                    );
                }
            }
            let parsed: IssuerSignedItem = serde_json::from_value(item_json)
                .map_err(|e| format!("issuer signed item: {e}"))?;
            out.push((namespace.clone(), parsed));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        // Build an issuer-signed doc, present it, parse it back.
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
        let cred = crate::issuer_signed::build_issuer_signed(&built, &ds_key, "AAECAwQ=")
            .unwrap();
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
        .unwrap();
        let docs = parse_device_response(&vp).unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].doc_type, "org.iso.18013.5.1.mDL");
        let claims = disclosed_claims(&docs[0].issuer_signed).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "org.iso.18013.5.1");
        assert_eq!(claims[0].1.element_identifier, "family_name");
    }
}
