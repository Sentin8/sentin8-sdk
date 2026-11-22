//! The Mobile Security Object (ISO/IEC 18013-5 §9.1) and its builder.
//!
//! The MSO is the issuer-signed core of every mdoc: the doctype, the
//! digest-algorithm, the validity window (tdate `Z` values - no
//! fractional seconds), the per-namespace `valueDigests` (one SHA-256
//! per IssuerSignedItem), and the `deviceKeyInfo` binding the credential
//! to the wallet's key.

use serde::{Deserialize, Serialize};

/// The MSO `version` member (18013-5 defines `1.0`).
pub const MSO_VERSION: &str = "1.0";

/// The MSO `digestAlgorithm` member (the suite warns on anything but
/// SHA-256 - `WarnIfMdocDigestAlgorithmNotSha256`, HAIP-8).
pub const DIGEST_ALGORITHM: &str = "SHA-256";

/// A tdate value (ISO 18013-5 §5.1): full-date, second precision, UTC
/// offset `Z`, no fractional seconds.
///
/// # Errors
/// Returns the original string back on a parse failure (the caller
/// decides whether to reject).
pub fn tdate(ts: i64) -> String {
    chrono_like(ts)
}

/// Minimal RFC 3339 second-precision formatter (no chrono dependency:
/// the engine is pure codec + crypto).
fn chrono_like(ts: i64) -> String {
    // Civil-date conversion from days (Howard Hinnant's algorithm).
    let days = ts.div_euclid(86_400);
    let secs_of_day = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// One namespace's elements: `(elementIdentifier, value)` pairs.
pub type NamespaceElements = Vec<(String, serde_json::Value)>;

/// The MSO validityInfo member (tdate values throughout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityInfo {
    /// The `signed` timestamp (the MSO mint instant).
    #[serde(rename = "signed")]
    pub signed: String,
    /// The `validFrom` timestamp.
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    /// The `validUntil` timestamp.
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    /// The optional `expectedUpdate` timestamp.
    #[serde(rename = "expectedUpdate", skip_serializing_if = "Option::is_none")]
    pub expected_update: Option<String>,
}

/// The MSO valueDigests member's digest BYTES: a newtype whose serde
/// `Serialize` forwards to `serialize_bytes` - ciborium's generic
/// `Vec<u8>` path routes through `serialize_seq` and lands an ARRAY of
/// UINTs, which multipaz's MSO parser rejects ('Failed to parse the
/// MSO from the mdoc credential'); ISO 18013-5 9.1.2.4 carries the
/// digest as a byte string (bstr).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct DigestBytes(
    /// The SHA-256 digest bytes.
    pub Vec<u8>,
);

impl serde::Serialize for DigestBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl std::borrow::Borrow<[u8]> for DigestBytes {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

/// The MSO valueDigests member: namespace -> {digestID: digest-bytes}.
pub type ValueDigests = std::collections::BTreeMap<String, std::collections::BTreeMap<u64, DigestBytes>>;

/// The ISO 18013-5 MSO structure (the COSE_Sign1 payload).
///
/// CBOR key-order matters for signing determinism: the map serializes
/// with the 18013-5 member order via `serde` field order (version,
/// digestAlgorithm, docType, validityInfo, valueDigests, deviceKeyInfo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mso {
    /// The MSO version member (`1.0`).
    #[serde(rename = "version")]
    pub version: String,
    /// The digest algorithm (`SHA-256`).
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,
    /// The document type (`docType`).
    #[serde(rename = "docType")]
    pub doc_type: String,
    /// The validity window.
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
    /// The per-namespace item digests.
    #[serde(rename = "valueDigests")]
    pub value_digests: ValueDigests,
    /// The device-key binding.
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,
    /// The optional 18013-7 revocation pointer
    /// (`status_list {idx, uri}` or `identifier_list {id, uri}`).
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

/// The `deviceKeyInfo` member: `{deviceKey: <COSE_Key>, devicePrivateKey: optional}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// The wallet's public key (the COSE form).
    #[serde(rename = "deviceKey")]
    pub device_key: CoseDeviceKey,
}

/// The MSO's `deviceKey` value: a COSE_Key map (ISO 18013-5 9.1.2.4 -
/// number labels 1 kty=2 EC2, 3 alg=-7 ES256, -1 crv=1 P-256, -2/-3 the
/// x/y coordinate bytes). multipaz's `CoseKey.fromDataItem` REQUIRES the
/// numeric label 1 (a JWK's text 'kty' throws 'Failed to parse the MSO').
#[derive(Debug, Clone)]
pub struct CoseDeviceKey {
    /// The uncompressed public point's x (32 bytes).
    pub x: Vec<u8>,
    /// The uncompressed public point's y (32 bytes).
    pub y: Vec<u8>,
}

use base64::Engine as _;

impl serde::Serialize for CoseDeviceKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        // The coordinate writer: forwarded through serde's
        // serialize_bytes -> ciborium writes Header::Bytes (the bstr
        // form; a plain &[u8/slice lands an ARRAY of UINTs via
        // serialize_seq - the same trap the digests hit).
        struct Bytes<'a>(&'a [u8]);
        impl serde::Serialize for Bytes<'_> {
            fn serialize<Sr: serde::Serializer>(&self, s: Sr) -> Result<Sr::Ok, Sr::Error> {
                s.serialize_bytes(self.0)
            }
        }
        let mut m = serializer.serialize_map(Some(5))?;
        m.serialize_entry(&1i64, &2i64)?; // kty: EC2
        m.serialize_entry(&3i64, &-7i64)?; // alg: ES256
        m.serialize_entry(&-1i64, &1i64)?; // crv: P-256
        m.serialize_entry(&-2i64, &Bytes(&self.x))?;
        m.serialize_entry(&-3i64, &Bytes(&self.y))?;
        m.end()
    }
}

impl<'de> serde::Deserialize<'de> for CoseDeviceKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Accept BOTH shapes: the COSE int-label map (the mint's wire
        // form) and the legacy JWK (text kty/crv/x/y) - the ciborium
        // serde bridge hands the map entries as a serde map; coordinate
        // bytes may ride bytes (numbers-rendered as arrays upstream) or
        // the b64url text the legacy JWK carries. Deserialize via a
        // serde_json::Value-free path: read through a temporary
        // ContentBuffer so either key form resolves.
        use serde::de::Error as _;
        let item = ciborium::value::Value::deserialize(deserializer)
            .map_err(|e| D::Error::custom(format!("deviceKey decode: {e}")))?;
        let entries: Vec<(ciborium::value::Value, ciborium::value::Value)> =
            match item {
                ciborium::value::Value::Map(m) => m,
                other => {
                    return Err(D::Error::custom(format!(
                        "deviceKey is not a CBOR map: {other:?}"
                    )))
                }
            };
        let read_coord = |labels: &[i64], names: &[&str]| -> Option<Vec<u8>> {
            for (k, v) in &entries {
                // Int-label form.
                if let ciborium::value::Value::Integer(i) = k {
                    let n: i128 = (*i).into();
                    let n: i64 = i64::try_from(n).unwrap_or(0);
                    if labels.contains(&n) {
                        if let ciborium::value::Value::Bytes(b) = v {
                            return Some(b.clone());
                        }
                        if let ciborium::value::Value::Text(s) = v {
                            if let Ok(b) =
                                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
                            {
                                return Some(b);
                            }
                        }
                    }
                }
                // Legacy JWK text form.
                if let Some(name) = k.as_text() {
                    if names.contains(&name) {
                        if let ciborium::value::Value::Bytes(b) = v {
                            return Some(b.clone());
                        }
                        if let ciborium::value::Value::Text(s) = v {
                            if let Ok(b) =
                                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
                            {
                                return Some(b);
                            }
                        }
                    }
                }
            }
            None
        };
        let x = read_coord(&[-2], &["x", "-2"]).ok_or_else(|| {
            D::Error::custom("deviceKey carries no x coordinate")
        })?;
        let y = read_coord(&[-3], &["y", "-3"]).ok_or_else(|| {
            D::Error::custom("deviceKey carries no y coordinate")
        })?;
        Ok(CoseDeviceKey { x, y })
    }
}

impl CoseDeviceKey {
    /// Build from the verifying key's uncompressed point halves.
    pub fn from_verifying_key(key: &p256::ecdsa::VerifyingKey) -> Self {
        let bytes = key.to_encoded_point(false);
        let b = bytes.as_bytes();
        Self {
            x: b[1..33].to_vec(),
            y: b[33..65].to_vec(),
        }
    }

    /// The legacy JWK form (the wallet-facing shape: text b64url
    /// coordinates - the proof-mint and vault surfaces use it).
    pub fn to_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.y),
        })
    }
}

/// An IssuerSignedItem (ISO 18013-5 §9.1.2.4) - the digestable unit.
///
/// Deterministic CBOR encoding of THIS structure is what the digest
/// covers (the suite's ValidateMdocIssuerSignedItemDigests re-derives
/// it from the wallet-side disclosed item - a member-order mismatch is
/// a certification failure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// The `digestID` (the disclosure selector).
    #[serde(rename = "digestID")]
    pub digest_id: u64,
    /// The per-item random `salt` (16 bytes, bstr). ISO 18013-5
    /// names the member `random` - the deserialize alias accepts it
    /// (the suite-minted items carry it); the serialize side keeps
    /// `salt`, so the minted artifacts' digests stay byte-identical
    /// to what the MsoBuilder computed.
    #[serde(with = "serde_bstr", alias = "random")]
    pub salt: Vec<u8>,
    /// The `elementIdentifier`.
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,
    /// The `elementValue`.
    #[serde(rename = "elementValue")]
    pub element_value: serde_json::Value,
}

/// CBOR bstr-transparent serde for the `salt` member (the suite parses
/// the item with multipaz, which expects a byte string; the JSON tree
/// form carries it as a number array).
mod serde_bstr {
    pub fn serialize<S>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

/// The MSO builder (sdk DESIGN.md §8b): namespaces of elements, the
/// device key, the validity window, optional status.
#[derive(Debug, Clone)]
pub struct MsoBuilder {
    doc_type: String,
    device_key: CoseDeviceKey,
    namespaces: std::collections::BTreeMap<String, NamespaceElements>,
    valid_from: i64,
    valid_until: i64,
    status: Option<serde_json::Value>,
}

impl MsoBuilder {
    /// A builder for one doctype with the wallet's P-256 verifying key.
    ///
    /// # Examples
    ///
    /// ```
    /// use sentin8_cbor_mdoc::MsoBuilder;
    /// # fn main() {
    /// let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
    ///     &mut p256::elliptic_curve::rand_core::OsRng));
    /// let b = MsoBuilder::new("eu.europa.ec.eudi.pid.1", &key.verifying_key());
    /// # }
    /// ```
    pub fn new(doc_type: &str, device_key: &p256::ecdsa::VerifyingKey) -> Self {
        Self {
            doc_type: doc_type.to_string(),
            device_key: CoseDeviceKey::from_verifying_key(device_key),
            namespaces: Default::default(),
            valid_from: 0,
            valid_until: 0,
            status: None,
        }
    }

    /// Replace the device key with one parsed from an explicit JWK
    /// (the HAIP key-attestation cells bind an attested key the proof
    /// carried).
    ///
    /// # Errors
    /// The JWK carries no valid P-256 point (x/y not base64url 32
    /// bytes).
    pub fn device_key_jwk(mut self, jwk: serde_json::Value) -> Result<Self, String> {
        let read = |name: &str| -> Option<Vec<u8>> {
            jwk.get(name)
                .and_then(|v| v.as_str())
                .and_then(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok())
                .filter(|b| b.len() == 32)
        };
        let (Some(x), Some(y)) = (read("x"), read("y")) else {
            return Err("the JWK carries no P-256 x/y".to_string());
        };
        self.device_key = CoseDeviceKey { x, y };
        Ok(self)
    }

    /// Add one namespace's elements.
    pub fn namespace(mut self, name: &str, elements: NamespaceElements) -> Self {
        self.namespaces.insert(name.to_string(), elements);
        self
    }

    /// The validity window (unix seconds).
    pub fn validity(mut self, from: i64, until: i64) -> Self {
        self.valid_from = from;
        self.valid_until = until;
        self
    }

    /// The optional 18013-7 status pointer
    /// (`{"status_list": {"idx": N, "uri": ...}}`).
    pub fn status(mut self, status: serde_json::Value) -> Self {
        self.status = Some(status);
        self
    }

    /// Build the MSO: mint per-item salts, digest every item, populate
    /// `valueDigests`. Returns the MSO plus the salted items per
    /// namespace (the caller embeds the items in `nameSpaces`).
    ///
    /// # Errors
    /// Never in practice (the digest computation is infallible); the
    /// Result shape keeps the builder forward-compatible.
    pub fn build(&self) -> BuiltMso {
        use sha2::Digest;
        let now = 0; // caller sets via validity(); mint instant = valid_from
        let mut digests: ValueDigests = Default::default();
        let mut items: std::collections::BTreeMap<String, Vec<IssuerSignedItem>> =
            Default::default();
        for (ns, elements) in &self.namespaces {
            let mut ns_items = Vec::new();
            let mut ns_digests = std::collections::BTreeMap::new();
            for (id, (element, value)) in elements.iter().enumerate() {
                let mut salt = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
                let item = IssuerSignedItem {
                    digest_id: id as u64,
                    salt: salt.to_vec(),
                    element_identifier: element.clone(),
                    element_value: value.clone(),
                };
                // The item's canonical bytes: the SAME member map the
                // wire build writes (salt = the value::Bytes bstr form,
                // elementValue = json_to_cbor - the __full_date__
                // markers render their CBOR tags) so the digest input is
                // byte-identical to what the wire carries. Hash the
                // Tag24-wrapped form (d8 18 + bstr(item) - the ISO
                // IssuerSignedItemBytes: the suite's
                // ValidateMdocIssuerSignedItemDigests re-encodes the
                // parsed Tagged item with multipaz's Cbor.encode and
                // hashes THAT form).
                use ciborium::value::Value as CborV;
                let item_value = CborV::Map(vec![
                    (CborV::Text("digestID".into()), CborV::Integer((id as i64).into())),
                    (CborV::Text("salt".into()), CborV::Bytes(salt.to_vec())),
                    (CborV::Text("elementIdentifier".into()), CborV::Text(element.clone())),
                    (CborV::Text("elementValue".into()), crate::json_to_cbor(&value)),
                ]);
                let plain = {
                    let mut buf = Vec::new();
                    ciborium::into_writer(&item_value, &mut buf)
                        .expect("item cbor: ciborium encode is infallible for these values");
                    buf
                };
                let mut wrapped = Vec::with_capacity(plain.len() + 4);
                wrapped.extend_from_slice(&[0xd8, 0x18]);
                if plain.len() < 24 {
                    wrapped.push(0x40 + plain.len() as u8);
                } else if plain.len() < 256 {
                    wrapped.extend_from_slice(&[0x58, plain.len() as u8]);
                } else {
                    wrapped.extend_from_slice(&[0x59]);
                    wrapped.extend_from_slice(&(plain.len() as u16).to_be_bytes());
                }
                wrapped.extend_from_slice(&plain);
                let d: [u8; 32] = sha2::Sha256::digest(&wrapped).into();
                ns_digests.insert(id as u64, crate::mso::DigestBytes(d.to_vec()));
                ns_items.push(item);
            }
            digests.insert(ns.clone(), ns_digests);
            items.insert(ns.clone(), ns_items);
        }
        let _ = now;
        Mso {
            version: MSO_VERSION.to_string(),
            digest_algorithm: DIGEST_ALGORITHM.to_string(),
            doc_type: self.doc_type.clone(),
            validity_info: ValidityInfo {
                signed: tdate(self.valid_from),
                valid_from: tdate(self.valid_from),
                valid_until: tdate(self.valid_until),
                expected_update: None,
            },
            value_digests: digests,
            device_key_info: DeviceKeyInfo {
                device_key: self.device_key.clone(),
            },
            status: self.status.clone(),
        }
        .with_items(items)
    }
}

/// The build output: the MSO plus the salted per-namespace items.
pub struct BuiltMso {
    /// The finished MSO.
    pub mso: Mso,
    /// The per-namespace salted IssuerSignedItems.
    pub items: std::collections::BTreeMap<String, Vec<IssuerSignedItem>>,
}

impl Mso {
    fn with_items(self, items: std::collections::BTreeMap<String, Vec<IssuerSignedItem>>) -> BuiltMso {
        BuiltMso { mso: self, items }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ))
    }

    #[test]
    fn tdate_shape() {
        // Second precision, Z suffix, no fractional seconds, fixed 20-byte
        // RFC 3339 full-date form (18013-5 tdate).
        let s = tdate(1_768_070_400);
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 20);
        assert_eq!(s, "2026-01-10T18:40:00Z");
        let epoch = tdate(0);
        assert_eq!(epoch, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn builder_digests_cover_items() {
        let built = MsoBuilder::new("org.iso.18013.5.1.mDL", &key().verifying_key())
            .validity(1_768_070_400, 1_800_000_000)
            .namespace(
                "org.iso.18013.5.1",
                vec![
                    ("family_name".to_string(), serde_json::json!("Doe")),
                    ("given_name".to_string(), serde_json::json!("Jane")),
                ],
            )
            .build();
        assert_eq!(built.mso.doc_type, "org.iso.18013.5.1.mDL");
        let digests = &built.mso.value_digests["org.iso.18013.5.1"];
        assert_eq!(digests.len(), 2);
        // every digest verifies against its item
        use sha2::Digest;
        for (id, item) in built.items["org.iso.18013.5.1"].iter().enumerate() {
            // The digests cover the Tag24-wrapped item bytes (the ISO
            // IssuerSignedItemBytes form: d8 18 + bstr(item)).
            let plain = crate::cbor_bytes(item).unwrap();
            let mut wrapped = Vec::with_capacity(plain.len() + 4);
            wrapped.extend_from_slice(&[0xd8, 0x18]);
            if plain.len() < 24 {
                wrapped.push(0x40 + plain.len() as u8);
            } else if plain.len() < 256 {
                wrapped.extend_from_slice(&[0x58, plain.len() as u8]);
            } else {
                wrapped.extend_from_slice(&[0x59]);
                wrapped.extend_from_slice(&(plain.len() as u16).to_be_bytes());
            }
            wrapped.extend_from_slice(&plain);
            let d: [u8; 32] = sha2::Sha256::digest(&wrapped).into();
            assert_eq!(&digests[&(id as u64)].0[..], &d[..]);
        }
    }
}


