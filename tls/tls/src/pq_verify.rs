// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust PQ certificate VERIFICATION for the post-quantum cert
//! families (PQCLIENT-1, acme DESIGN "CA families per mode").
//!
//! Graviola (the platform's TLS crypto backend) provides the
//! X25519MLKEM768 key exchange and classical signing/verification, but
//! no PQ signature algorithms - its `WebPkiSupportedAlgorithms` are
//! ECDSA/Ed25519 only. The PQ cert families (`hybrid`, `exclusive`)
//! mint ML-DSA-65 leafs under an ML-DSA-65 intermediate under an
//! SLH-DSA-SHA2-128s root (acme `pq_ca.rs`), so chain validation is
//! impossible without verification algorithms for exactly those two.
//!
//! This module implements the two `SignatureVerificationAlgorithm`s -
//! over the SAME RustCrypto crates the acme mints with (`ml-dsa`,
//! `slh-dsa`: pure Rust, FIPS 204/205) - and [`merge_pq_verify_algs`]
//! grafts them onto Graviola's algorithm set. rustls's provider model
//! is fully trait-composable: `WebPkiSupportedAlgorithms.all` is a
//! list of `&dyn SignatureVerificationAlgorithm` and the
//! `SignatureScheme::ML_DSA_65` mapping is a plain vec entry, so the
//! extension needs no fork of rustls, graviola, or webpki.
//!
//! Everything built on the installed provider inherits the extension
//! at once: `WebPkiServerVerifier` (reqwest's outbound HTTPS - its
//! no-provider path calls `CryptoProvider::get_default()`), the
//! acceptor's `WebPkiClientVerifier` (inbound mTLS), and the leaf-chain
//! validation both drive. The signing side already exists
//! ([`crate::pq_sign`]: `MlDsa65SigningKey` + `PqKeyProvider`) - with
//! this module the service plane both PRESENTS and VERIFIES PQ
//! certificates end to end, with no C in the verification path
//! (SECURITY.md "Memory-Safe Cryptography" holds).
//!
//! # Examples
//!
//! ```
//! use sentin8_tls::pq_verify;
//!
//! // The provider's verification set carries the PQ algorithms -
//! // matched by the algorithm identifiers (content-addressed DER):
//! let provider = sentin8_tls::crypto::sentin8_pq_provider();
//! let has_ml_dsa = provider
//!     .signature_verification_algorithms
//!     .all
//!     .iter()
//!     .any(|alg| {
//!         alg.public_key_alg_id().as_ref()
//!             == pq_verify::ML_DSA_65.public_key_alg_id().as_ref()
//!     });
//! assert!(has_ml_dsa);
//! ```

use rustls::pki_types::alg_id;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

/// The ML-DSA-65 algorithm identifier (FIPS 204, `id-ml-dsa-65`) - the
/// predefined pki-types constant.
fn ml_dsa_65_alg_id() -> AlgorithmIdentifier {
    alg_id::ML_DSA_65
}

/// The SLH-DSA-SHA2-128s algorithm identifier (FIPS 205,
/// `id-slh-dsa-sha2-128s`, OID `2.16.840.1.101.3.4.3.20`) - DER-encoded
/// inline as the BARE OID, mirroring the form of pki-types' ML-DSA
/// reference files (`alg-ml-dsa-65.der` is `06 09 60 86 ...` with no
/// SEQUENCE wrapper - the pki-types `AlgorithmIdentifier` matches the
/// SPKI's algorithm field against exactly this). The OID's first two
/// arcs fold into one byte (2*40+16 = 0x60).
const SLH_DSA_SHA2_128S_DER: &[u8] = &[
    0x06, 0x09, // OBJECT_IDENTIFIER, length 9
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14, // 2.16.840.1.101.3.4.3.20
];

/// The SLH-DSA-SHA2-128s algorithm identifier.
fn slh_dsa_sha2_128s_alg_id() -> AlgorithmIdentifier {
    AlgorithmIdentifier::from_slice(SLH_DSA_SHA2_128S_DER)
}

/// Pure-Rust ML-DSA-65 certificate-signature verification (FIPS 204).
///
/// The public key is the raw ML-DSA-65 encoded verifying key from the
/// cert's SPKI (`subjectPublicKey` BIT STRING); the signature is the
/// encoded ML-DSA-65 signature. The `ml-dsa` crate performs the verify
/// (the context-less form - the same discipline TLS applies to
/// `CertificateVerify`).
pub static ML_DSA_65: &dyn SignatureVerificationAlgorithm = &MlDsa65Verify;

#[derive(Debug)]
struct MlDsa65Verify;

impl SignatureVerificationAlgorithm for MlDsa65Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ml_dsa_65_alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ml_dsa_65_alg_id()
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ml_dsa::signature::Verifier as _;

        let key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(
            public_key.try_into().map_err(|_| InvalidSignature)?,
        );
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(
            signature.try_into().map_err(|_| InvalidSignature)?,
        )
        .ok_or(InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }
}

/// Pure-Rust SLH-DSA-SHA2-128s certificate-signature verification
/// (FIPS 205) - the algorithm the PQ ROOT CA's self-signature uses.
/// The hash-based family: the security anchor stays sound even if
/// lattice assumptions fall (acme DESIGN PQCA-2).
pub static SLH_DSA_SHA2_128S: &dyn SignatureVerificationAlgorithm = &SlhDsaSha2_128sVerify;

#[derive(Debug)]
struct SlhDsaSha2_128sVerify;

impl SignatureVerificationAlgorithm for SlhDsaSha2_128sVerify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        slh_dsa_sha2_128s_alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        slh_dsa_sha2_128s_alg_id()
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use slh_dsa::signature::Verifier as _;

        let key = slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::try_from(public_key)
            .map_err(|_| InvalidSignature)?;
        let sig = slh_dsa::Signature::<slh_dsa::Sha2_128s>::try_from(signature)
            .map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }
}

/// The PQ verification algorithms (ML-DSA-65 + SLH-DSA-SHA2-128s) as a
/// static slice - the graft point for a provider's algorithm set.
pub const PQ_VERIFY_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[ML_DSA_65, SLH_DSA_SHA2_128S];

/// Graft the PQ verification algorithms onto a provider's
/// `WebPkiSupportedAlgorithms` (PQCLIENT-1).
///
/// Adds ML-DSA-65 + SLH-DSA-SHA2-128s to the `all` list (chain
/// validation consults it by matching the cert's signature-algorithm
/// OIDs against the entries) and maps `SignatureScheme::ML_DSA_65` to
/// the ML-DSA-65 verifier (handshake `CertificateVerify` consults the
/// mapping). SLH-DSA needs no scheme mapping: only the ROOT's
/// self-signature uses it, and roots are trust anchors - webpki
/// validates chains UP TO an anchor, never the anchor itself.
pub fn merge_pq_verify_algs(
    base: rustls::crypto::WebPkiSupportedAlgorithms,
) -> rustls::crypto::WebPkiSupportedAlgorithms {
    let mut all: Vec<&'static dyn SignatureVerificationAlgorithm> = base.all.to_vec();
    for alg in PQ_VERIFY_ALGS {
        let alg: &'static dyn SignatureVerificationAlgorithm = *alg;
        if !all.iter().any(|a| same_alg(*a, alg)) {
            all.push(alg);
        }
    }
    let mut mapping: Vec<(
        rustls::SignatureScheme,
        Vec<&'static dyn SignatureVerificationAlgorithm>,
    )> = base.mapping.iter().map(|(s, v)| (*s, v.to_vec())).collect();
    if let Some(entry) = mapping
        .iter_mut()
        .find(|(scheme, _)| *scheme == rustls::SignatureScheme::ML_DSA_65)
    {
        if !entry.1.iter().any(|a| same_alg(*a, ML_DSA_65)) {
            entry.1.push(ML_DSA_65);
        }
    } else {
        mapping.push((rustls::SignatureScheme::ML_DSA_65, vec![ML_DSA_65]));
    }
    // The merged lists are leaked to the process's static lifetime:
    // the provider is constructed once per install (the `&'static`
    // field types of `WebPkiSupportedAlgorithms` demand it) and the
    // entries themselves are already `&'static` - the leak is a
    // handful of vec headers per process, never keys or secrets.
    let mapping: Vec<(
        rustls::SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )> = mapping
        .into_iter()
        .map(|(scheme, algs)| (scheme, Box::leak(algs.into_boxed_slice()) as &[_]))
        .collect();
    rustls::crypto::WebPkiSupportedAlgorithms {
        all: Box::leak(all.into_boxed_slice()),
        mapping: Box::leak(mapping.into_boxed_slice()),
    }
}

/// Whether two `SignatureVerificationAlgorithm`s are the SAME entry
/// (the trait carries no identity method - compare by the algorithm
/// identifiers, which are content-addressed DER).
fn same_alg(
    a: &'static dyn SignatureVerificationAlgorithm,
    b: &'static dyn SignatureVerificationAlgorithm,
) -> bool {
    a.public_key_alg_id().as_ref() == b.public_key_alg_id().as_ref()
        && a.signature_alg_id().as_ref() == b.signature_alg_id().as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SLH-DSA DER must decode to the FIPS 205 OID - a wrong OID
    /// means the algorithm never matches a real cert and chain
    /// validation fails closed for the wrong reason.
    #[test]
    fn slh_dsa_der_decodes_to_fips_oid() {
        // The bare-OID DER form: 06 09 + the 9 content bytes (the two
        // arcs 2.16 fold into 0x60).
        assert_eq!(SLH_DSA_SHA2_128S_DER[0], 0x06);
        assert_eq!(
            SLH_DSA_SHA2_128S_DER[1] as usize,
            SLH_DSA_SHA2_128S_DER.len() - 2
        );
        assert_eq!(
            &SLH_DSA_SHA2_128S_DER[2..],
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14]
        );
        // Cross-check against pki-types' ML-DSA-65 reference file: the
        // sibling FIPS 204 OID differs by exactly the last arc
        // (0x12 for id-ml-dsa-65 vs 0x14 for id-slh-dsa-sha2-128s) -
        // same form, same length, one arc apart.
        let ml = rustls::pki_types::alg_id::ML_DSA_65.as_ref();
        assert_eq!(
            ml,
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]
        );
        assert_eq!(ml.len(), SLH_DSA_SHA2_128S_DER.len());
        assert_eq!(
            &ml[..ml.len() - 1],
            &SLH_DSA_SHA2_128S_DER[..SLH_DSA_SHA2_128S_DER.len() - 1]
        );
        assert_eq!(ml[ml.len() - 1], 0x12);
        assert_eq!(SLH_DSA_SHA2_128S_DER[SLH_DSA_SHA2_128S_DER.len() - 1], 0x14);
    }

    /// The merge adds both algs + the scheme mapping without dropping
    /// the classical set (hybrid mode needs BOTH families live).
    #[test]
    fn merge_keeps_classical_and_adds_pq() {
        // An empty classical base (graviola's real set lives in the
        // provider - the merge must only ADD).
        let base = rustls::crypto::WebPkiSupportedAlgorithms {
            all: &[],
            mapping: &[],
        };
        let merged = merge_pq_verify_algs(base);
        assert!(merged.all.iter().any(|a| same_alg(*a, ML_DSA_65)));
        assert!(merged.all.iter().any(|a| same_alg(*a, SLH_DSA_SHA2_128S)));
        assert!(merged
            .mapping
            .iter()
            .any(|(scheme, _)| *scheme == rustls::SignatureScheme::ML_DSA_65));
        // Idempotent: a second merge adds nothing new.
        let merged_again = merge_pq_verify_algs(merged);
        assert_eq!(merged_again.all.len(), merged.all.len());
    }

    /// A sign/verify round trip through the ML-DSA-65 algorithm: the
    /// same crates the acme mints with must verify under this impl.
    #[test]
    fn ml_dsa_round_trip() {
        use ml_dsa::signature::{Keypair, Signer};
        use ml_dsa::Generate;

        let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        // The SPKI `subjectPublicKey` bytes: the same form webpki hands
        // to `verify_signature` (acme's `spki_from_raw` uses the same
        // `encode().as_ref()`).
        let vk_bytes: Vec<u8> = key.verifying_key().encode().as_slice().to_vec();
        let msg = b"tls13 transcript";
        let sig: Vec<u8> = key.sign(msg).encode().as_slice().to_vec();
        assert!(ML_DSA_65.verify_signature(&vk_bytes, msg, &sig).is_ok());
        assert!(ML_DSA_65
            .verify_signature(&vk_bytes, b"tampered", &sig)
            .is_err());
    }

    /// A sign/verify round trip through the SLH-DSA-SHA2-128s algorithm
    /// (the root-anchor signature family).
    #[test]
    fn slh_dsa_round_trip() {
        use slh_dsa::signature::{Keypair, Signer};
        // slh-dsa generates through a rand_core 0.10 TryRng - the acme
        // adapter's `generate_slh_root_key` pattern, verbatim.
        struct OsRng;
        impl rand_core::TryRng for OsRng {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                let mut b = [0u8; 4];
                getrandom::fill(&mut b).expect("OS entropy (u32)");
                Ok(u32::from_le_bytes(b))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                let mut b = [0u8; 8];
                getrandom::fill(&mut b).expect("OS entropy (u64)");
                Ok(u64::from_le_bytes(b))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                getrandom::fill(dst).expect("OS entropy (fill)");
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for OsRng {}
        let mut rng = OsRng;
        let key = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut rng);
        let vk_bytes = key.verifying_key().to_vec();
        let msg = b"root ca tbs certificate";
        let sig = key.sign(msg).to_vec();
        assert!(SLH_DSA_SHA2_128S
            .verify_signature(&vk_bytes, msg, &sig)
            .is_ok());
        assert!(SLH_DSA_SHA2_128S
            .verify_signature(&vk_bytes, b"tampered", &sig)
            .is_err());
    }
}
