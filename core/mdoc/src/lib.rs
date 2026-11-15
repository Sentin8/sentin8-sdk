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

pub mod device_response;
pub use device_response::{
    build_device_response, parse_device_response, DeviceResponseInput,
};

pub mod transcript;
pub use transcript::{dc_api_transcript, redirect_transcript};

pub mod namespaces;
pub mod verify;
pub mod x5c;

/// Encode any serializable value to deterministic CBOR bytes.
pub fn cbor_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

/// Decode CBOR bytes into a `serde_json::Value` tree.
pub fn cbor_to_json(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let v: serde_json::Value =
        ciborium::from_reader(bytes).map_err(|e| format!("cbor decode: {e}"))?;
    Ok(v)
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
