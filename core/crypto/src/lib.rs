// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-crypto
//!
//! At-rest secret encryption for Sentin8 services.
//!
//! AES-256-GCM authenticated envelope encryption for secret material stored
//! in application tables (OAuth signing keys, DCR client secrets, IdP client
//! secrets, webhook signing secrets, TOTP secrets). Secret material is never
//! stored as plaintext in application tables — it is stored by reference or
//! encrypted with this crate's envelope format.
//!
//! ## Envelope format
//!
//! Ciphertext rows are Base64 (standard) of:
//!
//! ```text
//! "v2:" || nonce (12 bytes) || ciphertext-with-tag
//! ```
//!
//! - The 12-byte nonce is random per encryption (AES-GCM standard size).
//! - AAD is not used (the table row provides the context).
//! - The master key comes from the caller (32 bytes), typically derived from
//!   `SENTIN8_AUTH_MASTER_KEY` (base64).
//!
//! ## Plaintext detection
//!
//! [`is_envelope`] returns false for anything not starting with `"v2:"` —
//! callers use this to detect un-encrypted rows and encrypt them on first
//! read (read value, seal, update row).

#![deny(missing_docs)]
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use base64::Engine as _;
use zeroize::Zeroizing;

/// Marker prefix identifying the v2 AES-GCM envelope.
pub const ENVELOPE_PREFIX: &str = "v2:";

/// AES-GCM nonce size (standard, bytes).
const NONCE_LEN: usize = 12;

/// Errors from the envelope codec.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The supplied master key is not exactly 32 bytes.
    #[error("invalid master key length: expected 32 bytes, got {0}")]
    BadKeyLen(usize),
    /// A base64-encoded envelope could not be decoded.
    #[error("base64 decode failed: {0}")]
    Base64(String),
    /// The envelope structure is invalid (missing prefix, too short).
    #[error("envelope decode failed: {0}")]
    Envelope(String),
    /// Authentication failed — wrong key or tampered ciphertext.
    #[error("decryption failed (wrong key or tampered data)")]
    DecryptFailed,
}

impl From<base64::DecodeError> for CryptoError {
    fn from(e: base64::DecodeError) -> Self {
        CryptoError::Base64(e.to_string())
    }
}

/// A 32-byte AES-256 master key. Zeroized on drop.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Build a key from exactly 32 raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::BadKeyLen(bytes.len()));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(bytes);
        Ok(MasterKey(k))
    }

    /// Build a key from a base64-encoded 32-byte value (the format of
    /// `SENTIN8_AUTH_MASTER_KEY`). Returns `None` for empty input (no key
    /// configured) so callers can apply fail-closed logic.
    pub fn from_base64(b64: &str) -> Result<Option<Self>, CryptoError> {
        if b64.trim().is_empty() {
            return Ok(None);
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64.trim())?;
        Ok(Some(Self::from_bytes(&decoded)?))
    }
}

/// Is this value a v2 envelope (vs. legacy plaintext or XOR-era ciphertext)?
pub fn is_envelope(value: &[u8]) -> bool {
    value.starts_with(ENVELOPE_PREFIX.as_bytes())
}

/// Is this *string* value a v2 envelope? Convenience for TEXT columns.
pub fn is_envelope_str(value: &str) -> bool {
    value.starts_with(ENVELOPE_PREFIX)
}

/// Encrypt `plaintext` into a `v2:` envelope, Base64 (standard) encoded.
///
/// Returns a `String` suitable for TEXT columns.
pub fn seal(key: &MasterKey, plaintext: &[u8]) -> Result<String, CryptoError> {
    use base64::Engine as _;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(&key.0[..]).map_err(|e| CryptoError::Envelope(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;

    let mut out = Vec::with_capacity(ENVELOPE_PREFIX.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(ENVELOPE_PREFIX.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&sealed);
    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

/// Decrypt a `v2:` envelope produced by [`seal`].
///
/// The envelope may be either:
/// - the **Base64 string** returned by [`seal`] (TEXT columns), or
/// - the **raw decoded envelope bytes** (`"v2:" || nonce || ct`, BYTEA
///   columns) — recognized by the literal `v2:` prefix surviving UTF-8
///   decoding without being valid Base64 of the standard alphabet prefix.
pub fn open(key: &MasterKey, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use base64::Engine as _;
    // Raw envelope (BYTEA path): starts with the literal "v2:" bytes.
    let raw: Vec<u8> = if envelope.starts_with(ENVELOPE_PREFIX.as_bytes()) {
        envelope.to_vec()
    } else if let Ok(s) = std::str::from_utf8(envelope) {
        // TEXT column: the whole "v2:..." string is Base64 of
        // prefix+nonce+ct. (A Base64-encoded "v2:" prefix always begins
        // with "djI6" — never the literal "v2:" — so the raw check above
        // is unambiguous.)
        base64::engine::general_purpose::STANDARD.decode(s.trim())?
    } else {
        return Err(CryptoError::Envelope("not a v2 envelope".into()));
    };

    if raw.len() < ENVELOPE_PREFIX.len() + NONCE_LEN || !raw.starts_with(ENVELOPE_PREFIX.as_bytes())
    {
        return Err(CryptoError::Envelope("not a v2 envelope".into()));
    }
    let nonce_bytes = raw[ENVELOPE_PREFIX.len()..ENVELOPE_PREFIX.len() + NONCE_LEN]
        .try_into()
        .unwrap_or([0u8; NONCE_LEN]);
    let ct = &raw[ENVELOPE_PREFIX.len() + NONCE_LEN..];

    let cipher =
        Aes256Gcm::new_from_slice(&key.0[..]).map_err(|e| CryptoError::Envelope(e.to_string()))?;
    let plain = cipher
        .decrypt(
            &aes_gcm::Nonce::from(nonce_bytes),
            Payload { msg: ct, aad: &[] },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(plain)
}

/// Decrypt a v2 envelope stored in a TEXT column.
pub fn open_str(key: &MasterKey, envelope: &str) -> Result<Vec<u8>, CryptoError> {
    open(key, envelope.as_bytes())
}

/// Encrypt `plaintext` into the **raw** envelope bytes (`"v2:" || nonce || ct`)
/// for BYTEA columns — the form [`open`] recognizes directly. This is the
/// byte-column counterpart of [`seal`] (TEXT form = base64 of these bytes).
pub fn seal_raw(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(&key.0[..]).map_err(|e| CryptoError::Envelope(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;

    let mut out = Vec::with_capacity(ENVELOPE_PREFIX.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(ENVELOPE_PREFIX.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Derive a 32-byte master key from arbitrary key material via SHA-256.
/// Useful when an operator provides a passphrase instead of exact 32 bytes.
pub fn derive_key(material: &[u8]) -> MasterKey {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(material);
    MasterKey::from_bytes(&digest).expect("SHA-256 output is 32 bytes")
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MasterKey {
        MasterKey::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn seal_open_round_trip() {
        use base64::Engine as _;
        let k = key();
        let secret = b"client-secret-abc123";
        let sealed = seal(&k, secret).unwrap();
        // The Base64 TEXT form starts with the encoding of "v2:" ("djI6").
        assert!(
            sealed.starts_with("djI6"),
            "expected base64-encoded v2: prefix, got {sealed}"
        );
        // ...and decodes to a raw "v2:" envelope.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        assert!(raw.starts_with(b"v2:"));
        let opened = open_str(&k, &sealed).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn seal_raw_open_round_trip_byte_form() {
        // BYTEA-column form: seal_raw emits the raw "v2:" || nonce || ct
        // bytes; open recognizes them directly. Also proves the TEXT and RAW
        // forms are the same envelope (TEXT = base64 of RAW) — the pair must
        // stay interchangeable for encrypt/decrypt consumers.
        let k = key();
        let secret = b"super-secret-client-secret";
        let raw = seal_raw(&k, secret).unwrap();
        assert!(is_envelope(&raw), "raw form must start with the v2: prefix");
        let opened = open(&k, &raw).unwrap();
        assert_eq!(opened, secret);
        // TEXT form of the same envelope decrypts to the same plaintext.
        let text = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(open_str(&k, &text).unwrap(), secret);
    }

    #[test]
    fn nonce_is_random_per_seal() {
        let k = key();
        let a = seal(&k, b"same").unwrap();
        let b = seal(&k, b"same").unwrap();
        assert_ne!(a, b, "same plaintext must produce different ciphertext");
    }

    #[test]
    fn open_rejects_wrong_key() {
        let sealed = seal(&key(), b"secret").unwrap();
        let other = MasterKey::from_bytes(&[9u8; 32]).unwrap();
        assert!(open_str(&other, &sealed).is_err());
    }

    #[test]
    fn open_rejects_plaintext() {
        let k = key();
        assert!(open_str(&k, "not-an-envelope").is_err());
        assert!(open_str(&k, "v2:short").is_err());
    }

    #[test]
    fn open_accepts_raw_envelope_bytes() {
        let k = key();
        let sealed = seal(&k, b"bytea secret").unwrap();
        // Decode to raw bytes (as a BYTEA column would hold) then open.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        assert_eq!(open(&k, &raw).unwrap(), b"bytea secret");
    }

    #[test]
    fn is_envelope_detects_prefix() {
        assert!(is_envelope_str("v2:AAAA"));
        assert!(!is_envelope_str("plaintext"));
        assert!(!is_envelope_str(""));
        assert!(is_envelope(b"v2:xyz"));
        assert!(!is_envelope(b"legacy"));
    }

    #[test]
    fn master_key_from_base64() {
        assert!(MasterKey::from_base64("").unwrap().is_none());
        let b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert!(MasterKey::from_base64(&b64).unwrap().is_some());
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(MasterKey::from_base64(&short).is_err());
    }

    #[test]
    fn derive_key_is_deterministic_32_bytes() {
        let a = derive_key(b"passphrase");
        let b = derive_key(b"passphrase");
        let plain = b"secret";
        let sealed = seal(&a, plain).unwrap();
        assert_eq!(open_str(&b, &sealed).unwrap(), plain);
    }

    #[test]
    fn bad_key_len_rejected() {
        assert!(MasterKey::from_bytes(&[1u8; 16]).is_err());
    }
}
