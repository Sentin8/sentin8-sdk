// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-65 TLS handshake signing for the post-quantum CA families
//! (PQCA-2, acme DESIGN "CA families per mode").
//!
//! The PQ cert families (`hybrid`, `exclusive`) mint ML-DSA-65-signed
//! leaves. rustls 0.23 carries them end to end:
//!
//! - The `ML_DSA_65` `SignatureScheme` is accepted on every TLS 1.3
//!   cipher suite (`compatible_sigscheme_for_suites`: a scheme whose
//!   `algorithm()` is `None` is compatible with any TLS 1.3 suite - the
//!   `SignatureAlgorithm` enum has no PQ variant, and rustls treats that
//!   as "no constraint" rather than "unsupported").
//! - `SigningKey`/`Signer`/`KeyProvider` are implementable traits: the
//!   handshake signature is produced by the `ml-dsa` crate here, not by
//!   the crypto provider.
//!
//! The `KeyProvider` wrapper ([`PqKeyProvider`]) is the integration
//! point: the active provider is wrapped once at boot and its
//! `load_private_key` gains ML-DSA awareness (an ECDSA/RSA key falls to
//! the wrapped provider unchanged - the `classical` mode never takes
//! the PQ path).
//!
//! # Examples
//!
//! ```
//! // The PQ signer round-trips through rustls's trait objects and
//! // signs with ML-DSA-65:
//! use sentin8_tls::pq_sign::MlDsa65SigningKey;
//! use rustls::sign::SigningKey as _;
//!
//! let rustls_key = MlDsa65SigningKey::generate();
//! let schemes = [rustls::SignatureScheme::ML_DSA_65];
//! let signer = rustls_key
//!     .choose_scheme(&schemes)
//!     .expect("ML_DSA_65 offered");
//! assert_eq!(signer.scheme(), rustls::SignatureScheme::ML_DSA_65);
//! let sig = signer.sign(b"tls13 transcript").expect("sign");
//! assert!(!sig.is_empty());
//! ```

use rustls::crypto::KeyProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::SignatureScheme;

use ml_dsa::{Generate, Keypair};

/// An ML-DSA-65 private key wrapped as a rustls [`SigningKey`].
///
/// Signs TLS 1.3 handshake transcripts (CertificateVerify) with the
/// deterministic ML-DSA-65 variant via the `ml-dsa` crate. The
/// certificate bytes themselves are served verbatim by the resolver;
/// this type only produces the *handshake* signature.
pub struct MlDsa65SigningKey {
    key: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

impl MlDsa65SigningKey {
    /// Generate a fresh ML-DSA-65 key (OS entropy).
    pub fn generate() -> Self {
        Self {
            key: ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate(),
        }
    }

    /// Load from a PKCS#8 DER private key (the seed-based encoding the
    /// `ml-dsa` crate emits; matches OpenSSL 3.5's ML-DSA PKCS#8 form).
    ///
    /// # Errors
    /// Returns a string describing the parse failure on malformed DER.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, String> {
        use ml_dsa::pkcs8::DecodePrivateKey;
        let sk =
            ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_pkcs8_der(der)
                .map_err(|e| format!("parse ML-DSA-65 PKCS#8 key: {e}"))?;
        Ok(Self { key: sk })
    }

    /// The PKCS#8 DER encoding of the key (persistable form).
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, String> {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let doc = self
            .key
            .to_pkcs8_der()
            .map_err(|e| format!("encode ML-DSA-65 PKCS#8 key: {e}"))?;
        Ok(doc.as_bytes().to_vec())
    }

    /// The raw ML-DSA-65 public key (the SPKI `subjectPublicKey` bytes -
    /// a bare ML-DSA-65 public key, no DER wrapper).
    pub fn public_key_raw(&self) -> Vec<u8> {
        self.key.verifying_key().encode().to_vec()
    }
}

impl std::fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlDsa65SigningKey")
    }
}

impl SigningKey for MlDsa65SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // ML_DSA_65 only - a classical-only offer (a TLS 1.2 client, or a
        // peer that does not know the scheme) yields None and rustls
        // picks another certificate if one is available. The PQ families
        // always negotiate TLS 1.3, where the scheme is offered by the
        // rustls core (it advertises every enum value).
        if offered.contains(&SignatureScheme::ML_DSA_65) {
            Some(Box::new(MlDsa65Signer {
                key: ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&self.key.as_seed()),
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None // opt-out: the certificate bytes carry the SPKI already
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        // The enum has no PQ variant; rustls treats the handshake scheme
        // (ML_DSA_65, whose SignatureAlgorithm mapping is None) as the
        // authoritative capability, and `Anonymous` here is never
        // consulted on the TLS 1.3 path (see the module docs).
        rustls::SignatureAlgorithm::Anonymous
    }
}

struct MlDsa65Signer {
    key: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

impl std::fmt::Debug for MlDsa65Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlDsa65Signer")
    }
}

impl Signer for MlDsa65Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use ml_dsa::Signer as _;
        self.key
            .try_sign(message)
            .map(|sig| sig.encode().to_vec())
            .map_err(|e| rustls::Error::General(format!("ML-DSA-65 sign: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ML_DSA_65
    }
}

/// A [`KeyProvider`] that understands ML-DSA keys in addition to the
/// wrapped provider's classical keys (PQCA-2).
///
/// `load_private_key` probes the PKCS#8 algorithm OID: an ML-DSA-65
/// seed-encoded key resolves to [`MlDsa65SigningKey`]; anything else
/// falls through to the wrapped (graviola-backed) provider unchanged.
/// This is the single seam `sentin8-tls` config-building uses, so BOTH
/// the server (resolver) and client (mTLS) paths gain PQ key support at
/// once.
pub struct PqKeyProvider {
    inner: &'static dyn KeyProvider,
}

impl PqKeyProvider {
    /// Wrap the provider the process already installed (the graviola
    /// provider from [`crate::crypto::sentin8_pq_provider`]; its
    /// `key_provider` field is `&'static dyn KeyProvider` - the same
    /// static form this wrapper re-exposes, so the installation site
    /// stays a plain field assignment).
    pub fn wrap(inner: &'static dyn KeyProvider) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for PqKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeyProvider")
            .field("inner", &self.inner)
            .finish()
    }
}

impl KeyProvider for PqKeyProvider {
    fn load_private_key(&self, key_der: PrivateKeyDer<'static>) -> Result<std::sync::Arc<dyn SigningKey>, rustls::Error> {
        // Only the PKCS#8 form can carry an ML-DSA seed - the SEC1/PKCS#1
        // (EC/RSA) forms are classical by construction.
        if let PrivateKeyDer::Pkcs8(pkcs8) = &key_der {
            if let Some(signing_key) = probe_ml_dsa_pkcs8(pkcs8) {
                return Ok(signing_key);
            }
        }
        self.inner
            .load_private_key(key_der)
            .map_err(rustls::Error::from)
    }
}

/// Probe a PKCS#8 DER blob for the ML-DSA-65 algorithm OID
/// (`2.16.840.1.101.3.4.3.18`, FIPS 204) and load it as an
/// [`MlDsa65SigningKey`] when it matches.
fn probe_ml_dsa_pkcs8(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Option<std::sync::Arc<dyn SigningKey>> {
    // The ml-dsa crate's PKCS#8 decoder both validates the OID and
    // extracts the seed - a classical key fails here and falls through.
    MlDsa65SigningKey::from_pkcs8_der(pkcs8.secret_pkcs8_der())
        .ok()
        .map(|k| std::sync::Arc::new(k) as std::sync::Arc<dyn SigningKey>)
}