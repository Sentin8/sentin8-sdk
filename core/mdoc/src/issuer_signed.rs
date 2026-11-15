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
/// The DS certificate chain is std-base64 DER entries (`x5c` form).
///
/// # Errors
/// Returns a descriptive string when the COSE_Sign1 mint fails (the MSO
/// payload encode or the signature).
pub fn build_issuer_signed(
    built: &BuiltMso,
    ds_key: &p256::ecdsa::SigningKey,
    ds_cert_der_std_b64: &str,
) -> Result<String, String> {
    // nameSpaces: {namespace: [item...]} with the IssuerSignedItems as
    // CBOR maps (each carrying its digestID/salt/element pair).
    let mut namespaces = serde_json::Map::new();
    for (ns, items) in &built.items {
        let arr: Vec<serde_json::Value> = items
            .iter()
            .map(|it| serde_json::to_value(it).expect("item json"))
            .collect();
        namespaces.insert(ns.clone(), serde_json::Value::Array(arr));
    }

    // issuerAuth: COSE_Sign1 = [protected(bstr), unprotected(map), payload(bstr), signature(bstr)]
    let payload = crate::cbor_bytes(&built.mso)?;
    let protected_map: serde_json::Value = serde_json::json!({
        COSE_LABEL_ALG.to_string(): COSE_ALG_ES256,
        COSE_LABEL_X5CHAIN.to_string(): [ds_cert_der_std_b64],
    });
    // COSE header labels are INTEGERS - ciborium serializes the map
    // with integer keys via serde_json's number keys.
    let protected_bytes = crate::cbor_bytes(&cose_header_to_cbor(&protected_map))?;
    let signing_input = {
        let mut v = Vec::with_capacity(protected_bytes.len() + payload.len());
        v.extend_from_slice(&protected_bytes);
        v.push(0xA2); // CBOR array(2) - Sig_structure ["Signature1", protected, external_aad, payload] minus the tag
        v.extend_from_slice(&payload);
        v
    };
    // Sig_structure: ["Signature1", protected(bstr), external_aad(bstr), payload(bstr)]
    let sig_structure = {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x84"); // array(4)
        buf.push(0x6A); // tstr "Signature1"
        buf.extend_from_slice(b"Signature1");
        buf.push(0x58); // bytes(1-byte length) - protected
        buf.push(protected_bytes.len() as u8);
        buf.extend_from_slice(&protected_bytes);
        buf.push(0x40); // bytes(0) - external_aad
        buf.push(0x58); // bytes(1-byte length) - payload
        buf.push(payload.len() as u8);
        buf.extend_from_slice(&payload);
        buf
    };
    let sig: p256::ecdsa::Signature = ds_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    // COSE_Sign1 array: [protected(bstr), unprotected(map{}), payload(bstr), signature(bstr)]
    let mut sign1 = Vec::new();
    sign1.extend_from_slice(b"\x84"); // array(4)
    sign1.push(0x58);
    sign1.push(protected_bytes.len() as u8);
    sign1.extend_from_slice(&protected_bytes);
    sign1.push(0xA0); // map(0) - unprotected
    sign1.push(0x59); // bytes(2-byte length) - payload
    sign1.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    sign1.extend_from_slice(&payload);
    sign1.push(0x58);
    sign1.push(sig_bytes.len() as u8);
    sign1.extend_from_slice(&sig_bytes);

    // IssuerSigned: {nameSpaces: ..., issuerAuth: [COSE_Sign1]}
    let issuer_signed = {
        let ns_cbor = crate::cbor_bytes(&serde_json::Value::Object(namespaces))?;
        let mut buf = Vec::new();
        buf.push(0xA2); // map(2)
        buf.extend_from_slice(b"\x6AnameSpaces");
        buf.extend_from_slice(&ns_cbor);
        buf.extend_from_slice(b"\x6AissuerAuth");
        buf.extend_from_slice(&sign1);
        buf
    };
    let _ = signing_input;
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(issuer_signed))
}

/// COSE header map with INTEGER keys - serde_json cannot hold integer
/// map keys, so the header builds as a raw CBOR fragment.
fn cose_header_to_cbor(_json: &serde_json::Value) -> Result<Vec<u8>, String> {
    // {1: -7, 33: [cert]} - a fixed two-entry map, integer keys.
    let cert = _json
        .get("33")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or("x5chain missing in the COSE header")?;
    use base64::Engine;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(cert)
        .map_err(|e| format!("x5chain cert decode: {e}"))?;
    // The x5chain entry in COSE is the DER bytes (a bstr), not the b64
    // text - multipaz's MdocUtil.extractX5chain reads bstr entries.
    let mut buf = Vec::new();
    buf.push(0xA2); // map(2)
    buf.push(0x01); // key 1 (alg)
    buf.push(0x26); // -7
    buf.push(0x18); // key 33 (uint8)
    buf.push(33);
    // x5chain: array(1) of bstr
    buf.push(0x81);
    buf.push(0x59);
    buf.extend_from_slice(&(cert_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&cert_bytes);
    Ok(buf)
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
