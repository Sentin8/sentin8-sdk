//! # sentin8-cbor-mdoc - the ISO/IEC 18013-5/-7 mdoc engine
//!
//! The platform's single Mobile Security Object (MSO) engine serving all
//! three roles of the digital-credential stack (sdk DESIGN.md §8b):
//!
//! - the **issuer** role (sentin8-auth OID4VCI): builds the `IssuerSigned`
//!   structure - `nameSpaces` plus a COSE_Sign1 `issuerAuth` whose payload is
//!   the MSO and whose protected header carries the DS certificate `x5chain`.
//! - the **verifier** role (sentin8-auth OID4VP): verifies the COSE_Sign1
//!   against the `x5chain` leaf, checks the digest coverage, and parses the
//!   `DeviceResponse` presentations (ISO 18013-7).
//! - the **wallet** role (wallet8 and every vertical): builds the
//!   `DeviceResponse` - selective disclosure by digestID, the device
//!   signature over the OID4VP session transcript - and parses verifier
//!   requests.
//!
//! The engine owns codecs and crypto only - no storage, no HTTP. The wire
//! forms are exactly the two the OIDF conformance suite 5.3.3 validates:
//! the VCI credential response (`IssuerSigned`, unpadded base64url) and
//! the OID4VP vp_token (`DeviceResponse`, unpadded base64url).
//!
//! ## Wire forms
//!
//! `IssuerSigned` (ISO 18013-5 §8.3):
//!
//! ```text
//! {nameSpaces, issuerAuth}
//!   nameSpaces : {<namespace> : [IssuerSignedItem...]}
//!   issuerAuth : COSE_Sign1 = [protected, unprotected, payload(MSO), sig]
//!   MSO        : {version, digestAlgorithm, docType, validityInfo,
//!                 valueDigests, deviceKeyInfo.deviceKey}
//! ```
//!
//! `DeviceResponse` (ISO 18013-7 §8):
//!
//! ```text
//! [version, [{status, documents:[{docType, issuerSigned, deviceSigned,
//!   deviceSignature}]}], status]
//! ```
//!
//! Every digest is `SHA-256(deterministic-CBOR(IssuerSignedItem))` and the
//! device signature covers
//! `[deviceNameSpace bytes, sessionTranscript bytes]` (the empty
//! deviceNameSpace for the OID4VP cells).
//!
//! ## Session transcripts (OID4VP 1.0 Final App. B.2.6.1/6.2)
//!
//! Redirect modes:
//!
//! ```text
//! SessionTranscript = [null, null, ["OpenID4VPHandover",
//!                                   SHA-256(HandoverInfo)]]
//! HandoverInfo      = [client_id, nonce, jwkThumbprint|null, response_uri]
//! ```
//!
//! dc_api modes:
//!
//! ```text
//! SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover",
//!                                   SHA-256(DCAPIHandoverInfo)]]
//! DCAPIHandoverInfo = [origin, nonce, jwkThumbprint|null]
//! ```
//!
//! # Examples
//!
//! Build an MSO for one namespace, then verify the digest coverage:
//!
//! ```
//! use sentin8_cbor_mdoc::{MsoBuilder, namespaces};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
//!     &mut p256::elliptic_curve::rand_core::OsRng));
//! let builder = MsoBuilder::new(
//!         "org.iso.18013.5.1.mDL",
//!         &device_key.verifying_key(),
//!     )
//!     .namespace("org.iso.18013.5.1", vec![(
//!         "family_name".to_string(),
//!         serde_json::json!("Doe"),
//!     )]);
//! let built = builder.build();
//! assert_eq!(built.mso.doc_type, "org.iso.18013.5.1.mDL");
//! # Ok(())
//! # }
//! ```

// ─── MSO (Mobile Security Object, ISO 18013-5 §9.1) ─────────────────────

pub mod mso;
pub use mso::{Mso, MsoBuilder};

pub mod issuer_signed;
pub use issuer_signed::build_issuer_signed;
pub use issuer_signed::json_to_cbor;

pub mod device_response;
pub use device_response::{
    build_device_response, disclosed_claims, filter_issuer_signed, parse_device_response,
    ClaimAllowlist, DeviceResponseInput,
};

/// The claims of a base64url IssuerSigned mdoc in the DCQL claims
/// path form (OID4VP 7.2: `namespace/element` keys) - the wallet-side
/// view the 6.4.1 value matching reads.
///
/// An element whose VALUE is a map (e.g. `place_of_birth =
/// {locality, country}`) is ALSO addressable member-by-member
/// (`namespace/element/locality`): the §6.4.1 `claim_sets` preference
/// resolves against exactly that key, so the nested members are
/// flattened alongside the parent. Arrays keep the parent key only -
/// a DCQL path descends object members, never array indices.
///
/// # Errors
/// Descriptive strings on decode/parse failures (the caller degrades
/// to an empty map - unreadable values are treated as absent).
pub fn parse_issuer_signed_claims(
    issuer_signed_b64: &str,
) -> Result<Option<std::collections::BTreeMap<String, serde_json::Value>>, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(issuer_signed_b64.trim())
        .map_err(|e| format!("issuerSigned decode: {e}"))?;
    let json = crate::cbor_to_json(&raw)?;
    let claims = crate::disclosed_claims(&json)?;
    let mut map = std::collections::BTreeMap::new();
    for (namespace, item) in claims {
        let key = format!("{namespace}/{}", item.element_identifier);
        map.insert(key.clone(), item.element_value.clone());
        flatten_object_members(&mut map, &key, &item.element_value);
    }
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(map))
}

/// Flatten an object-valued element's members into
/// `prefix/member` DCQL path keys (recursively).
fn flatten_object_members(
    map: &mut std::collections::BTreeMap<String, serde_json::Value>,
    prefix: &str,
    value: &serde_json::Value,
) {
    let Some(obj) = value.as_object() else {
        return;
    };
    for (k, v) in obj {
        if k.starts_with('_') {
            continue; // the selective-disclosure markers
        }
        let path = format!("{prefix}/{k}");
        map.insert(path.clone(), v.clone());
        flatten_object_members(map, &path, v);
    }
}

pub mod transcript;
pub use transcript::{dc_api_transcript, redirect_transcript};

pub mod namespaces;
pub mod verify;
pub use verify::{jwk_thumbprint_raw, verify_mso_document};
pub mod x5c;

/// Encode any serializable value to deterministic CBOR bytes.
pub fn cbor_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

/// Decode CBOR bytes into a `serde_json::Value` tree.
///
/// Ciborium rejects tagged CBOR values when converting straight into
/// `serde_json::Value` ("invalid type: enum") - and the ISO 18013-5
/// IssuerSigned's `nameSpaces` items are CBOR Tag(24)-wrapped
/// (`#6.24(bstr .cbor IssuerSignedItem)`): the embedded item bytes are
/// themselves CBOR. The decode walks ciborium's own `Value` type and
/// unwraps tags into their wrapped form: Tag(24) decodes the wrapped
/// bytes as CBOR recursively, every other tag is dropped (the tag
/// number carries no data the claim matching reads).
///
/// # Errors
/// Descriptive strings on malformed CBOR.
pub fn cbor_to_json(bytes: &[u8]) -> Result<serde_json::Value, String> {
    use ciborium::value::Value as Cbor;
    fn walk(v: Cbor) -> Result<serde_json::Value, String> {
        match v {
            // ISO 18013-5: the namespaced items ride Tag(24) - the
            // wrapped bytes ARE the CBOR item; decode them recursively.
            // Tag(24) always wraps a byte string; a tagged value that
            // arrives as another form falls through to the generic
            // tag-drop.
            Cbor::Tag(24, inner) if matches!(&*inner, Cbor::Bytes(_)) => {
                let bytes = match *inner {
                    Cbor::Bytes(b) => b,
                    _ => unreachable!("guard above"),
                };
                let raw: Cbor = ciborium::from_reader(&bytes[..])
                    .map_err(|e| format!("cbor tag24 decode: {e}"))?;
                walk(raw)
            }
            Cbor::Tag(_, inner) => walk(*inner),
            Cbor::Null => Ok(serde_json::Value::Null),
            Cbor::Bool(b) => Ok(serde_json::Value::Bool(b)),
            Cbor::Integer(i) => Ok(serde_json::json!(i128::from(i))),
            Cbor::Float(f) => {
                Ok(serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null))
            }
            Cbor::Bytes(b) => Ok(serde_json::Value::Array(
                b.iter().map(|x| serde_json::json!(x)).collect(),
            )),
            Cbor::Text(t) => Ok(serde_json::Value::String(t)),
            Cbor::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(walk(it)?);
                }
                Ok(serde_json::Value::Array(out))
            }
            Cbor::Map(pairs) => {
                let mut m = serde_json::Map::new();
                for (k, val) in pairs {
                    let key = match k {
                        Cbor::Text(t) => t,
                        // The integer-keyed form maps over the
                        // canonical decimal form (the CBOR map keys
                        // the claim parser reads are text in
                        // practice).
                        Cbor::Integer(i) => i128::from(i).to_string(),
                        other => {
                            return Err(format!(
                                "cbor map key {other:?}: not a text/integer"
                            ))
                        }
                    };
                    m.insert(key, walk(val)?);
                }
                Ok(serde_json::Value::Object(m))
            }
            other => Err(format!("cbor value {other:?}: unmappable")),
        }
    }
    let v: Cbor = ciborium::from_reader(bytes)
        .map_err(|e| format!("cbor decode: {e}"))?;
    walk(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_round_trip() {
        let v = serde_json::json!({"a": 1, "b": [true, "x"]});
        let bytes = cbor_bytes(&v).unwrap();
        assert_eq!(cbor_to_json(&bytes).unwrap(), v);
    }
}
