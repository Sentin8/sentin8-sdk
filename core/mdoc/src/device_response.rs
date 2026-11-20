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

/// The DeviceAuthentication structure bytes (18013-5 §8.3.2.1.1) - the
/// ONE canonical builder shared by the wallet-side signature and the
/// verifier-side check.
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
pub fn build_device_response(inputs: &[DeviceResponseInput]) -> Result<String, String> {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    let mut documents = Vec::new();
    for input in inputs {
        let issuer_signed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input.issuer_signed_b64)
            .map_err(|e| format!("issuer signed decode: {e}"))?;

        // deviceNameSpace: CBOR bytes of an empty map
        let device_name_space = b"\xa0".to_vec();

        // The DeviceAuthentication (18013-5 section 9.1.2.4 as the
        // verifier's multipaz parser re-derives it):
        //   ["DeviceAuthentication", sessionTranscript(embedded RAW
        //   CBOR), docType(tstr), deviceNameSpaces(Tag #6.24(bstr))].
        // The COSE_Sign1 is DETACHED: its signature covers the
        // Sig_structure ["Signature1", protected, external_aad(empty),
        // payload = encode(Tag(24, bstr(encode(DA))))] - the detached
        // payload IS the Tag24 form the parser rebuilds. The transcript
        // rides as a RAW CBOR item (multipaz's RawCbor); the docType is
        // the canonical tstr; the nameSpaces element is the
        // DeviceNameSpaceBytes ITSELF (the #6.24 tag wrapping the empty
        // DeviceNameSpace map - DeviceResponseParser.kt appends the RAW
        // deviceSigned["nameSpaces"] DataItem, so the bytes are
        // d81841a0, not the decoded a0) (DESIGN.md 4.2).
        let mut da_inner = Vec::new();
        da_inner.push(0x84); // array(4)
        // [0] "DeviceAuthentication"
        da_inner.push(0x74);
        da_inner.extend_from_slice(b"DeviceAuthentication");
        // [1] sessionTranscript: raw CBOR item embedded verbatim
        da_inner.extend_from_slice(input.transcript);
        // [2] docType - canonical CBOR tstr: lengths 0-23 ride the
        // head byte 0x60+len; 24-255 ride the 0x78 + byte-length form
        // (a two-byte head with an extra length byte here corrupts the
        // DA and the device signature check fails).
        let dt = input.doc_type.as_bytes();
        if dt.len() <= 23 {
            da_inner.push(0x60 + dt.len() as u8);
        } else if dt.len() <= 255 {
            da_inner.push(0x78);
            da_inner.push(dt.len() as u8);
        } else {
            return Err("the docType exceeds the CBOR short-length form".into());
        }
        da_inner.extend_from_slice(dt);
        // [3] deviceNameSpaces: the DeviceNameSpaceBytes item ITSELF.
        da_inner.push(0xd8);
        da_inner.push(0x18); // Tag 24
        da_inner.push(0x41); // bytes(1)
        da_inner.extend_from_slice(&device_name_space);
        // -> Tag24(bstr(DA)) - the detached payload the parser rebuilds.
        let da_tagged = ciborium::value::Value::Tag(
            24,
            Box::new(ciborium::value::Value::Bytes(da_inner)),
        );
        let mut da_buf = Vec::new();
        ciborium::into_writer(&da_tagged, &mut da_buf)
            .map_err(|e| format!("device authentication tag encode: {e}"))?;
        let protected = b"\xa1\x01\x26".to_vec(); // {1: -7}
        let sig_input = crate::issuer_signed::cose_sig_structure(&protected, &da_buf);
        let sig: p256::ecdsa::Signature = input.device_key.sign(&sig_input);
        let sig_bytes = sig.to_bytes();
        // The DETACHED COSE_Sign1: [protected, {}, null, signature].
        let mut sign1 = Vec::new();
        sign1.push(0x84);
        sign1.push(0x43); // bytes(3)
        sign1.extend_from_slice(&protected);
        sign1.push(0xA0);
        sign1.push(0xF6); // null (detached payload)
        sign1.push(0x58);
        sign1.push(sig_bytes.len() as u8);
        sign1.extend_from_slice(&sig_bytes);
        let sign1_value: ciborium::value::Value =
            ciborium::from_reader(sign1.as_slice())
                .expect("the device COSE_Sign1 re-parse");

        // deviceSigned: {nameSpaces: Tag24(bstr(empty map)),
        // deviceAuth: {deviceSignature: COSE_Sign1}} - the parser reads
        // deviceAuth.deviceSignature (9.1.2.4).
        let device_signed_value = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("nameSpaces".into()),
                ciborium::value::Value::Tag(
                    24,
                    Box::new(ciborium::value::Value::Bytes(device_name_space.clone())),
                ),
            ),
            (
                ciborium::value::Value::Text("deviceAuth".into()),
                ciborium::value::Value::Map(vec![(
                    ciborium::value::Value::Text("deviceSignature".into()),
                    sign1_value,
                )]),
            ),
        ]);

        let issuer_signed_value: ciborium::value::Value = ciborium::from_reader(
            issuer_signed.as_slice(),
        )
        .expect("issuerSigned re-parse");
        documents.push(ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("docType".into()),
                ciborium::value::Value::Text(input.doc_type.to_string()),
            ),
            (
                ciborium::value::Value::Text("issuerSigned".into()),
                issuer_signed_value,
            ),
            (
                ciborium::value::Value::Text("deviceSigned".into()),
                device_signed_value,
            ),
        ]));
    }

    // DeviceResponse = {version: "1.0", documents: [...], status: 0}
    // (the ISO map form the parse-side multipaz DeviceResponseParser
    // reads - version then the documents/status map members).
    let response = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("version".into()),
            ciborium::value::Value::Text(DEVICE_RESPONSE_VERSION.into()),
        ),
        (
            ciborium::value::Value::Text("documents".into()),
            ciborium::value::Value::Array(documents),
        ),
        (
            ciborium::value::Value::Text("status".into()),
            ciborium::value::Value::Integer(0.into()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&response, &mut buf)
        .map_err(|e| format!("device response encode: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

pub fn parse_device_response(
    b64: &str,
) -> Result<Vec<ParsedDocument>, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64url decode: {e}"))?;
    let v: ciborium::Value =
        ciborium::from_reader(raw.as_slice()).map_err(|e| format!("cbor decode: {e}"))?;
    // DeviceResponse = {version: "1.0", documents: [...], status: 0}
    // (ISO map form) - fall back to the array form the legacy wallet
    // builders emit ([version, [{status, documents}], status]).
    let find_top = |key: &str| -> Option<ciborium::Value> {
        match &v {
            ciborium::Value::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, x)| x.clone()),
            _ => None,
        }
    };
    let (version, docs) = if let Some(d) = find_top("documents") {
        let ver = find_top("version")
            .and_then(|x| x.as_text().map(str::to_string))
            .unwrap_or_else(|| "1.0".into());
        (ver, d)
    } else {
        // Legacy array form.
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
        let ver = v
            .as_array()
            .and_then(|a| a.first())
            .and_then(|x| x.as_text().map(str::to_string))
            .unwrap_or_else(|| "1.0".into());
        let d = first
            .iter()
            .find(|(k, _)| k.as_text() == Some("documents"))
            .map(|(_, x)| x.clone())
            .ok_or("DeviceResponse: documents array is missing")?;
        (ver, d)
    };
    if version.as_str() > "1.0" {
        return Err(format!("DeviceResponse version {version} unsupported"));
    }
    let docs = docs
        .as_array()
        .cloned()
        .ok_or("DeviceResponse: documents is not an array")?;
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
        // inline map - accept both forms.
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


/// The DCQL-requested claim allowlist for one credential: the
/// (namespace, elementIdentifier) pairs the wallet is permitted to
/// disclose (OID4VP 6.4.1: wallets MUST NOT send selectively
/// disclosable claims that the DCQL query does not reach).
pub type ClaimAllowlist = Vec<(String, String)>;

/// Re-encode the stored `IssuerSigned` keeping the issuerAuth and only
/// the `nameSpaces` items whose (namespace, elementIdentifier) pair
/// passes the allowlist. Dropping an IssuerSignedItem is always legal:
/// the MSO digest coverage is per item, so the retained items still
/// verify issuer-side. An empty allowlist keeps everything (the
/// all-claims presentations of the DCQL queries without `claims`).
///
/// # Errors
/// When the stored IssuerSigned fails to decode or the re-encode fails.
pub fn filter_issuer_signed(
    issuer_signed_b64: &str,
    allow: &ClaimAllowlist,
) -> Result<String, String> {
    use base64::Engine;
    use ciborium::value::Value;
    if allow.is_empty() {
        return Ok(issuer_signed_b64.to_string());
    }
    // Filter one namespace's item array to the allowlist; items arrive
    // plain (the mock-issuer mint) or Tag24(bstr(item)) (ISO canonical)
    // - both forms read elementIdentifier the same way, and the item
    // rides unchanged (the filter DROPS items, it never rewrites them).
    fn keep_item(item: &Value, ns_name: &str, allow: &ClaimAllowlist) -> bool {
        let inner: Option<Value> = match item {
            Value::Tag(24, boxed) => match boxed.as_ref() {
                Value::Bytes(b) => ciborium::from_reader(b.as_slice()).ok(),
                _ => None,
            },
            plain @ Value::Map(_) => Some(plain.clone()),
            _ => None,
        };
        let Some(Value::Map(mp)) = inner else { return false };
        let elem = mp
            .iter()
            .find(|(k, _)| k.as_text() == Some("elementIdentifier"))
            .and_then(|(_, v)| v.as_text().map(str::to_string));
        match elem {
            Some(e) => allow.iter().any(|(an, ae)| an == ns_name && ae == &e),
            None => false,
        }
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(issuer_signed_b64)
        .map_err(|e| format!("issuer signed decode: {e}"))?;
    let mut value: Value = ciborium::from_reader(raw.as_slice())
        .map_err(|e| format!("issuer signed parse: {e}"))?;
    let Value::Map(pairs) = &mut value else {
        return Err("issuerSigned is not a map".into());
    };
    let Some((_, ns_member)) = pairs
        .iter_mut()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == "nameSpaces"))
    else {
        return Ok(issuer_signed_b64.to_string());
    };
    match ns_member {
        // Plain form: {ns -> [item...]}, kept plain.
        Value::Map(m) => {
            for (ns_key, ns_val) in m.iter_mut() {
                let Some(ns_name) = ns_key.as_text().map(str::to_string) else {
                    continue;
                };
                if let Value::Array(items) = ns_val {
                    items.retain(|it| keep_item(it, &ns_name, allow));
                }
            }
            m.retain(|(k, v)| {
                k.as_text() != Some("nameSpaces")
                    || matches!(v, Value::Array(a) if !a.is_empty())
            });
        }
        // Tag24-wrapped form: peel, filter, re-wrap.
        Value::Tag(24, boxed) => {
            let Value::Bytes(ns_bytes) = boxed.as_ref() else {
                return Err("issuerSigned nameSpaces Tag24 payload not bstr".into());
            };
            let mut ns_map: Value = ciborium::from_reader(ns_bytes.as_slice())
                .map_err(|e| format!("nameSpaces decode: {e}"))?;
            let Value::Map(m) = &mut ns_map else {
                return Err("nameSpaces is not a map".into());
            };
            for (ns_key, ns_val) in m.iter_mut() {
                let Some(ns_name) = ns_key.as_text().map(str::to_string) else {
                    continue;
                };
                if let Value::Array(items) = ns_val {
                    items.retain(|it| keep_item(it, &ns_name, allow));
                }
            }
            m.retain(|(k, v)| {
                k.as_text() != Some("nameSpaces")
                    || matches!(v, Value::Array(a) if !a.is_empty())
            });
            let mut re_ns = Vec::new();
            ciborium::into_writer(&ns_map, &mut re_ns)
                .map_err(|e| format!("nameSpaces encode: {e}"))?;
            *boxed = Box::new(Value::Bytes(re_ns));
        }
        _ => return Err("issuerSigned nameSpaces is neither a map nor Tag24".into()),
    }
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out)
        .map_err(|e| format!("issuer signed encode: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mso::NamespaceElements;

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

    /// A minimal syntactically-valid DER certificate (the mint wraps the
    /// bytes into x5chain without parsing - the tests need only a valid
    /// Standard base64 DER SEQUENCE shape).
    fn fake_ds_cert() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0x30, 0x03, 0x02, 0x01, 0x00])
    }

    /// One presented document wired end-to-end (mint -> DR build) against a
    /// fresh P-256 device key. Returns (vp_b64, transcript_bytes, ()).
    fn present(claims: Vec<(&str, NamespaceElements)>) -> (String, Vec<u8>, ()) {
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let ds_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let mut builder = crate::mso::MsoBuilder::new(
            "eu.europa.ec.eudi.pid.1",
            &device_key.verifying_key(),
        )
        .validity(1_768_070_400, 1_800_000_000);
        for (ns, items) in claims {
            builder = builder.namespace(ns, items);
        }
        let built = builder.build();
        let cred = crate::issuer_signed::build_issuer_signed(&built, &ds_key, &fake_ds_cert())
            .unwrap();
        let transcript = crate::transcript::redirect_transcript(
            "test-suite",
            "nonce-9",
            None,
            "https://verifier/responseuri",
        )
        .unwrap();
        let vp = build_device_response(&[DeviceResponseInput {
            doc_type: "eu.europa.ec.eudi.pid.1",
            issuer_signed_b64: &cred,
            device_key: &device_key,
            transcript: &transcript,
        }])
        .unwrap();
        (vp, transcript, ())
    }

    #[test]
    fn device_response_is_iso_map_form() {
        // THE regression the battery caught: the vp_token entry is the
        // ISO MAP {version, documents, status} - NOT the legacy array
        // form. Head byte 0xa3 (map, 3 members), not 0x83 (array).
        use base64::Engine;
        let (vp, _, _) = present(vec![
            ("eu.europa.ec.eudi.pid.1", vec![("given_name".to_string(), serde_json::json!("Jean"))]),
        ]);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&vp)
            .unwrap();
        assert_eq!(raw[0], 0xa3, "the DeviceResponse must be a 3-member map");
        // version: the first key is the tstr "version" (0x67).
        assert_eq!(&raw[1..9], b"\x67version");
    }

    #[test]
    fn device_signature_is_detached_and_verifies() {
        // The full chain the battery exercised: the DA the verifier
        // re-derives (RAW transcript + TAGGED DeviceNameSpaceBytes)
        // verifies under the MSO device key.
        use ciborium::value::Value;
        use p256::ecdsa::signature::Verifier;
        let (vp, transcript, _pk) = present(vec![
            ("eu.europa.ec.eudi.pid.1", vec![("given_name".to_string(), serde_json::json!("Jean"))]),
        ]);
        // Parse the DR, locate document[0].deviceSigned.deviceAuth[deviceSignature].
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&vp).unwrap();
        let dr: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let Value::Map(top) = &dr else { panic!("map form") };
        let find = |m: &Vec<(Value, Value)>, k: &str| -> Option<Value> {
            m.iter().find(|(key, _)| key.as_text() == Some(k)).map(|(_, v)| v.clone())
        };
        let docs = find(top, "documents").unwrap();
        let Value::Array(arr) = &docs else { panic!("documents array") };
        let Value::Map(doc) = &arr[0] else { panic!("document map") };
        let ds = find(doc, "deviceSigned").unwrap();
        let Value::Map(ds_map) = &ds else { panic!("deviceSigned map") };
        let auth = find(ds_map, "deviceAuth").unwrap();
        let Value::Map(auth_map) = &auth else { panic!("deviceAuth map") };
        let sig1 = find(auth_map, "deviceSignature").unwrap();
        let Value::Array(parts) = &sig1 else { panic!("COSE_Sign1 array") };
        // [protected, {}, null, signature] - the DETACHED form.
        let Value::Bytes(protected) = &parts[0] else { panic!("protected bstr") };
        assert_eq!(parts[2], Value::Null, "the payload must be null (detached)");
        let Value::Bytes(sig) = &parts[3] else { panic!("signature bstr") };
        // Rebuild the DA the verifier derives: [DA-string, RAW transcript,
        // docType, Tag24(bstr(empty map))], wrapped Tag24(bstr(DA)).
        let da_inner: Vec<u8> = {
            let mut b = Vec::new();
            b.push(0x84);
            b.push(0x74);
            b.extend_from_slice(b"DeviceAuthentication");
            b.extend_from_slice(&transcript);
            // Canonical minimal tstr head (the builder's rule): the
            // 23-char doctype rides 0x60+len, not the two-byte form.
            b.push(0x60 + "eu.europa.ec.eudi.pid.1".len() as u8);
            b.extend_from_slice(b"eu.europa.ec.eudi.pid.1");
            b.extend_from_slice(&[0xd8, 0x18, 0x41, 0xa0]);
            b
        };
        let da_tagged: Value = Value::Tag(24, Box::new(Value::Bytes(da_inner)));
        let mut da_buf = Vec::new();
        ciborium::into_writer(&da_tagged, &mut da_buf).unwrap();
        let tbs = crate::issuer_signed::cose_sig_structure(protected, &da_buf);
        // The MSO device key = the present() fixture's device key - recover
        // it from the MSO payload's deviceKeyInfo.deviceKey (x/y).
        let issuer_signed = find(doc, "issuerSigned").unwrap();
        let Value::Map(iss_map) = &issuer_signed else { panic!("issuerSigned map") };
        let auth2 = find(iss_map, "issuerAuth").unwrap();
        let Value::Array(sign1) = &auth2 else { panic!("issuerAuth Sign1") };
        let Value::Bytes(mso_payload) = &sign1[2] else { panic!("MSO payload") };
        let mso: Value = ciborium::from_reader(mso_payload.as_slice()).unwrap();
        let Value::Map(mso_map) = &mso else { panic!("MSO map") };
        let dk_info = find(mso_map, "deviceKeyInfo").unwrap();
        let Value::Map(dk_map) = &dk_info else { panic!("deviceKeyInfo map") };
        let dk = find(dk_map, "deviceKey").unwrap();
        // The mint serializes deviceKey as a JWK map (kty/crv/x/y
        // base64url members - verify.rs jwk_from_verifying_key).
        let Value::Map(dk_jwk) = &dk else { panic!("deviceKey JWK map") };
        let get_b64 = |name: &str| -> Vec<u8> {
            dk_jwk
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .and_then(|(_, v)| v.as_text())
                .map(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap())
                .unwrap()
        };
        let xb = get_b64("x");
        let yb = get_b64("y");
        let ep = p256::EncodedPoint::from_affine_coordinates(xb.as_slice().into(), yb.as_slice().into(), false);
        let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep).unwrap();
        let signature = p256::ecdsa::Signature::from_slice(sig).unwrap();
        vk.verify(&tbs, &signature)
            .expect("the device signature verifies over the re-derived DA");
    }

    /// A minted IssuerSigned carrying TWO claims in ONE namespace
    /// (family_name + given_name) via the normal mint path (plain form).
    fn minted_issuer_signed_b64(claims: Vec<(&str, Vec<(String, serde_json::Value)>)>) -> String {
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let ds_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let mut builder = crate::mso::MsoBuilder::new(
            "eu.europa.ec.eudi.pid.1",
            &device_key.verifying_key(),
        )
        .validity(1_768_070_400, 1_800_000_000);
        for (ns, items) in claims {
            builder = builder.namespace(ns, items);
        }
        let built = builder.build();
        crate::issuer_signed::build_issuer_signed(&built, &ds_key, &fake_ds_cert())
            .unwrap()
    }

    #[test]
    fn filter_keeps_only_allowlisted_claims() {
        // OID4VP 6.4.1: the wallet releases ONLY the DCQL-reached claims.
        let cred = minted_issuer_signed_b64(vec![
            (
                "eu.europa.ec.eudi.pid.1",
                vec![
                    ("family_name".to_string(), serde_json::json!("Dupont")),
                    ("given_name".to_string(), serde_json::json!("Jean")),
                    ("birth_date".to_string(), serde_json::json!("1980-05-23")),
                ],
            ),
        ]);
        let allow: ClaimAllowlist = vec![(
            "eu.europa.ec.eudi.pid.1".to_string(),
            "given_name".to_string(),
        )];
        let filtered = filter_issuer_signed(&cred, &allow).unwrap();
        let docs = parse_device_response(&{
            // Wrap the filtered IssuerSigned into a DR to reuse the parse walk.
            let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
                &mut p256::elliptic_curve::rand_core::OsRng,
            ));
            let transcript = crate::transcript::redirect_transcript(
                "t", "n", None, "https://r/u",
            )
            .unwrap();
            build_device_response(&[DeviceResponseInput {
                doc_type: "eu.europa.ec.eudi.pid.1",
                issuer_signed_b64: &filtered,
                device_key: &device_key,
                transcript: &transcript,
            }])
            .unwrap()
        })
        .unwrap();
        let claims = disclosed_claims(&docs[0].issuer_signed).unwrap();
        assert_eq!(claims.len(), 1, "only the allowlisted claim survives");
        assert_eq!(claims[0].1.element_identifier, "given_name");
    }

    #[test]
    fn filter_claims_less_releases_nothing() {
        // OID4VP 6.4.1: a claims-LESS DCQL query discloses NOTHING - the
        // no-match sentinel allowlist drops every IssuerSignedItem.
        let cred = minted_issuer_signed_b64(vec![
            (
                "eu.europa.ec.eudi.pid.1",
                vec![
                    ("family_name".to_string(), serde_json::json!("Dupont")),
                    ("given_name".to_string(), serde_json::json!("Jean")),
                ],
            ),
        ]);
        let allow: ClaimAllowlist = vec![(
            "oid4vp-6.4.1-no-claims-disclose-nothing".to_string(),
            "-".to_string(),
        )];
        let filtered = filter_issuer_signed(&cred, &allow).unwrap();
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let transcript = crate::transcript::redirect_transcript(
            "t", "n", None, "https://r/u",
        )
        .unwrap();
        let vp = build_device_response(&[DeviceResponseInput {
            doc_type: "eu.europa.ec.eudi.pid.1",
            issuer_signed_b64: &filtered,
            device_key: &device_key,
            transcript: &transcript,
        }])
        .unwrap();
        let docs = parse_device_response(&vp).unwrap();
        let claims = disclosed_claims(&docs[0].issuer_signed).unwrap();
        assert!(claims.is_empty(), "a claims-less query discloses no claim");
    }

    #[test]
    fn filter_preserves_tag24_form() {
        // The ISO-canonical holdings arrive Tag24-wrapped (both the
        // nameSpaces member and the items) - the filter preserves that
        // byte shape and still drops by elementIdentifier.
        // Build a plain IssuerSigned, then TAG-wrap it the way a multipaz
        // wallet stores it (nameSpaces -> Tag24(bstr(map)); items ->
        // Tag24(bstr(item))).
        use ciborium::value::Value;
        use base64::Engine;
        let cred = minted_issuer_signed_b64(vec![
            (
                "eu.europa.ec.eudi.pid.1",
                vec![
                    ("family_name".to_string(), serde_json::json!("Dupont")),
                    ("given_name".to_string(), serde_json::json!("Jean")),
                ],
            ),
        ]);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cred).unwrap();
        let iss: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let Value::Map(pairs) = &iss else { panic!("issuerSigned map") };
        let ns = pairs.iter().find(|(k, _)| k.as_text() == Some("nameSpaces")).map(|(_, v)| v).unwrap();
        let Value::Map(ns_map) = ns else { panic!("plain nameSpaces") };
        // Wrap each item + the whole map in Tag24(bstr(...)).
        let build_tagged_map = |inner: &Value| -> Value {
            let mut b = Vec::new();
            ciborium::into_writer(inner, &mut b).unwrap();
            Value::Tag(24, Box::new(Value::Bytes(b)))
        };
        let tagged_ns_map = Value::Map(
            ns_map
                .iter()
                .map(|(k, v)| {
                    let Value::Array(items) = v else { panic!("item array") };
                    let tagged_items: Vec<Value> = items.iter().map(build_tagged_map).collect();
                    (k.clone(), Value::Array(tagged_items))
                })
                .collect(),
        );
        let tagged_iss = Value::Map(
            pairs
                .iter()
                .map(|(k, v)| {
                    if k.as_text() == Some("nameSpaces") {
                        (k.clone(), build_tagged_map(&tagged_ns_map))
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged_iss, &mut buf).unwrap();
        let tagged_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        let allow: ClaimAllowlist = vec![(
            "eu.europa.ec.eudi.pid.1".to_string(),
            "family_name".to_string(),
        )];
        let filtered = filter_issuer_signed(&tagged_b64, &allow).unwrap();
        // The filtered form STAYS Tag24-wrapped and keeps just family_name.
        let fr = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&filtered).unwrap();
        let fv: Value = ciborium::from_reader(fr.as_slice()).unwrap();
        let Value::Map(fpairs) = &fv else { panic!("filtered map") };
        let fns = fpairs.iter().find(|(k, _)| k.as_text() == Some("nameSpaces")).map(|(_, v)| v).unwrap();
        let Value::Tag(24, inner) = fns else { panic!("the filtered nameSpaces stays Tag24-wrapped") };
        let Value::Bytes(map_b) = inner.as_ref() else { panic!("Tag24 bstr") };
        let fm: Value = ciborium::from_reader(map_b.as_slice()).unwrap();
        let Value::Map(fns_map) = &fm else { panic!("filtered inner map") };
        let (_, items) = fns_map.iter().next().unwrap();
        let Value::Array(arr) = items else { panic!("item array") };
        assert_eq!(arr.len(), 1, "only family_name survives the Tag24-form filter");
        // The surviving item is itself Tag24(bstr(item)).
        assert!(matches!(arr[0], Value::Tag(24, _)), "the item keeps its Tag24 wrap");
    }

    #[test]
    fn filtered_issuer_signed_still_parses_and_claims_reduce() {
        // The full presentation path over a FILTERED holding: the DR parse
        // + digest verification still pass (per-item digest coverage makes
        // dropping items legal).
        use base64::Engine;
        let cred = minted_issuer_signed_b64(vec![
            (
                "eu.europa.ec.eudi.pid.1",
                vec![
                    ("family_name".to_string(), serde_json::json!("Dupont")),
                    ("given_name".to_string(), serde_json::json!("Jean")),
                ],
            ),
        ]);
        let allow: ClaimAllowlist = vec![(
            "eu.europa.ec.eudi.pid.1".to_string(),
            "family_name".to_string(),
        )];
        let filtered = filter_issuer_signed(&cred, &allow).unwrap();
        let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let transcript = crate::transcript::redirect_transcript(
            "t", "n", None, "https://r/u",
        )
        .unwrap();
        let vp = build_device_response(&[DeviceResponseInput {
            doc_type: "eu.europa.ec.eudi.pid.1",
            issuer_signed_b64: &filtered,
            device_key: &device_key,
            transcript: &transcript,
        }])
        .unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&vp).unwrap();
        let vp_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let docs = parse_device_response(&vp_b64).unwrap();
        let claims = disclosed_claims(&docs[0].issuer_signed).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.element_identifier, "family_name");
    }
}
