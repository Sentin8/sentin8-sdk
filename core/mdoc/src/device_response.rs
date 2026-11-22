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
        // The MSO's revocation pointer: the issuerAuth COSE_Sign1's
        // payload (Tag24-wrapped MSO map or the bare form) decodes to
        // the `status` member; the pointer's mechanism rides the
        // member's key (status_list | identifier_list). The bridge
        // renders the pointer map with the TEXT keys (no int labels).
        let status_ref = issuer_signed_json
            .get("issuerAuth")
            .and_then(|a| a.get(2))
            .and_then(|p| p.as_str())
            .and_then(|p_b64| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(p_b64)
                    .ok()
            })
            .and_then(|payload| {
                let bytes: Vec<u8> = if payload.len() >= 2
                    && payload[0] == 0xd8
                    && payload[1] == 0x18
                {
                    // Tag24: peel d8 18 + the bstr head, hand the map.
                    let mut o = 2;
                    let h = payload[o];
                    o += 1;
                    let inner = (h & 0x1f) as usize;
                    let len = if inner < 24 {
                        inner
                    } else if inner == 24 {
                        let l = payload[o] as usize;
                        o += 1;
                        l
                    } else if inner == 25 {
                        let l = u16::from_be_bytes([payload[o], payload[o + 1]])
                            as usize;
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
                };
                let mso: ciborium::Value =
                    ciborium::from_reader(bytes.as_slice()).ok()?;
                let status = mso
                    .into_map()
                    .ok()?
                    .into_iter()
                    .find(|(k, _)| k.as_text() == Some("status"))
                    .map(|(_, v)| v)?;
                let map = status.as_tag().map(|(_, v)| v).map(|v| v.clone()).unwrap_or(status);
                let pairs = map.as_map()?;
                let get = |key: &str| -> Option<ciborium::Value> {
                    pairs
                        .iter()
                        .find(|(k, _)| k.as_text() == Some(key))
                        .map(|(_, v)| v.clone())
                };
                let read_ref = |mech: &'static str,
                                node: ciborium::Value|
                 -> Option<StatusReference> {
                    let node = node
                        .as_tag()
                        .map(|(_, v)| v.clone())
                        .unwrap_or(node);
                    let uri = node
                        .as_map()?
                        .iter()
                        .find(|(k, _)| k.as_text() == Some("uri"))
                        .and_then(|(_, v)| v.as_text())?
                        .to_string();
                    // The identifier-list arm keys on the bstr `id`
                    // (no idx); the status-list arm keys on `idx`.
                    let identifier = node
                        .as_map()?
                        .iter()
                        .find(|(k, _)| k.as_text() == Some("id"))
                        .and_then(|(_, v)| match v {
                            ciborium::Value::Bytes(b) => {
                                use base64::Engine as _;
                                Some(base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .encode(b))
                            }
                            ciborium::Value::Text(t) => Some(t.clone()),
                            _ => None,
                        });
                    let idx = node
                        .as_map()?
                        .iter()
                        .find(|(k, _)| k.as_text() == Some("idx"))
                        .and_then(|(_, v)| {
                            let i: i128 = v.as_integer()?.into();
                            u32::try_from(i).ok()
                        })
                        .unwrap_or(0);
                    if identifier.is_none() && mech == "identifier_list" {
                        return None;
                    }
                    Some(StatusReference { uri, idx, identifier, mechanism: mech })
                };
                if let Some(node) = get("status_list") {
                    return read_ref("status_list", node);
                }
                get("identifier_list")
                    .and_then(|node| read_ref("identifier_list", node))
            });
        out.push(ParsedDocument {
            doc_type,
            issuer_signed: issuer_signed_json,
            raw: ciborium_value_to_json(&doc),
            status_ref,
        });
    }
    Ok(out)
}

fn ciborium_value_to_json(v: &ciborium::Value) -> serde_json::Value {
    use base64::Engine;
    match v {
        // Tag(24) = the ISO IssuerSignedItem wrap (#6.24(bstr)): decode
        // the wrapped bytes and render the inner item - the digest
        // validator + the claim readers see the item's canonical map.
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(b) => match ciborium::from_reader(b.as_slice()) {
                Ok(item) => ciborium_value_to_json(&item),
                Err(_) => serde_json::Value::Null,
            },
            other => ciborium_value_to_json(other),
        },
        ciborium::Value::Integer(i) => {
            let n: i64 = i64::try_from(Into::<i128>::into(*i)).unwrap_or(0);
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
                        let n: i64 = i64::try_from(Into::<i128>::into(*i)).unwrap_or(0);
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
    /// The MSO's 18013-7 revocation pointer
    /// (`status.status_list {idx, uri}` or the identifier-list twin).
    pub status_ref: Option<StatusReference>,
}

/// The MSO's revocation pointer: the list URI + the credential's
/// entry index (the verifier's fetch + bit-read inputs).
#[derive(Debug, Clone)]
pub struct StatusReference {
    /// The status list's URI (the Token Status List endpoint).
    pub uri: String,
    /// The credential's index in the list (`status_list.idx`; 0 for
    /// the identifier-list mechanism, which keys on `identifier`).
    pub idx: u32,
    /// The identifier-list mechanism's opaque identifier bytes
    /// (`identifier_list.id` - a CBOR bstr; base64url in the JSON
    /// projection).
    pub identifier: Option<String>,
    /// The mechanism (`status_list` | `identifier_list`).
    pub mechanism: &'static str,
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
            // BOTH names decode: the mint's `salt` and the ISO 18013-5
            // `random` member the suite-minted items carry (the serde
            // alias accepts either name; the STRING form fails the
            // parse, so the b64url bridge form MUST be re-decoded here).
            for key in ["salt", "random"] {
                use base64::Engine as _;
                let Some(s) = item_json.get(key).and_then(|v| v.as_str()) else {
                    continue;
                };
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap_or_default();
                if !bytes.is_empty() {
                    if let Some(obj) = item_json.as_object_mut() {
                        obj.insert(
                            key.to_string(),
                            serde_json::Value::Array(
                                bytes.iter().map(|b| serde_json::json!(b)).collect(),
                            ),
                        );
                    }
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
        // The mint wraps the MSO in the ISO Tag24 (#6.24) - peel the
        // wrapper (verify.rs accepts both forms).
        // Tag24 encodes d8 18 <bstr-header> <contents>: skip the tag +
        // the bstr header to reach the MSO map bytes.
        let mso_bytes: &[u8] = {
            if mso_payload.len() >= 2 && mso_payload[0] == 0xd8 && mso_payload[1] == 0x18 {
                let mut o = 2;
                let b = mso_payload[o];
                o += 1;
                let inner = (b & 0x1f) as usize;
                let len = if inner < 24 {
                    inner
                } else if inner == 24 {
                    let l = mso_payload[o] as usize;
                    o += 1;
                    l
                } else if inner == 25 {
                    let l = u16::from_be_bytes([mso_payload[o], mso_payload[o + 1]]) as usize;
                    o += 2;
                    l
                } else {
                    let l = u32::from_be_bytes([
                        mso_payload[o],
                        mso_payload[o + 1],
                        mso_payload[o + 2],
                        mso_payload[o + 3],
                    ]) as usize;
                    o += 4;
                    l
                };
                &mso_payload[o..o + len]
            } else {
                mso_payload
            }
        };
        let mso: Value = ciborium::from_reader(mso_bytes).unwrap();
        let Value::Map(mso_map) = &mso else { panic!("MSO map") };
        let dk_info = find(mso_map, "deviceKeyInfo").unwrap();
        let Value::Map(dk_map) = &dk_info else { panic!("deviceKeyInfo map") };
        let dk = find(dk_map, "deviceKey").unwrap();
        // The mint serializes deviceKey as a COSE_Key map (int labels;
        // -2/-3 the raw coordinate bytes - the CoseDeviceKey form).
        let Value::Map(dk_items) = &dk else { panic!("deviceKey COSE map") };
        let read_label = |labels: &[i64]| -> Option<Vec<u8>> {
            for (k, v) in dk_items.iter() {
                if let Value::Integer(i) = k {
                    let n: i64 = i64::try_from(Into::<i128>::into(*i)).unwrap_or(0);
                    if labels.contains(&n) {
                        if let Value::Bytes(b) = v {
                            return Some(b.clone());
                        }
                    }
                }
            }
            None
        };
        let xb = read_label(&[-2]).unwrap();
        let yb = read_label(&[-3]).unwrap();
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
        // The ISO-canonical holdings arrive Tag24-wrapped (the
        // nameSpaces member as a whole) and the mint NOW tags each item
        // already - the test wraps only the ns map (the multipaz wallet
        // storage shape) on top; the filter preserves that byte shape
        // and still drops by elementIdentifier.
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
                    // The items are ALREADY Tag24-wrapped (the mint's native
                // form) - ride them unchanged here.
                (k.clone(), v.clone())
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
