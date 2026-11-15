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

/// The MSO valueDigests member: namespace -> {digestID: digest-bytes}.
pub type ValueDigests = std::collections::BTreeMap<String, std::collections::BTreeMap<u64, Vec<u8>>>;

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

/// The `deviceKeyInfo` member: `{deviceKey: <JWK>, devicePrivateKey: optional}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// The wallet's public key (a JWK map).
    #[serde(rename = "deviceKey")]
    pub device_key: serde_json::Value,
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
    /// The per-item random `salt` (16 bytes, bstr).
    #[serde(with = "serde_bstr")]
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
    device_key: serde_json::Value,
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
            device_key: crate::verify::jwk_from_verifying_key(device_key),
            namespaces: Default::default(),
            valid_from: 0,
            valid_until: 0,
            status: None,
        }
    }

    /// Replace the device key with an explicit JWK (the HAIP key-
    /// attestation cells bind an attested key the proof carried).
    pub fn device_key_jwk(mut self, jwk: serde_json::Value) -> Self {
        self.device_key = jwk;
        self
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
                let bytes = crate::cbor_bytes(&item).expect("item cbor");
                let d: [u8; 32] = sha2::Sha256::digest(bytes).into();
                ns_digests.insert(id as u64, d.to_vec());
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
            let d: [u8; 32] = sha2::Sha256::digest(crate::cbor_bytes(item).unwrap()).into();
            assert_eq!(&digests[&(id as u64)][..], &d[..]);
        }
    }
}
