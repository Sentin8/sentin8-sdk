//! The OID4VP session transcripts (1.0 Final Appendix B.2.6.1/6.2).
//!
//! Redirect modes (direct_post, direct_post.jwt, url query):
//!
//! ```text
//! SessionTranscript = CBOR([null, null, ["OpenID4VPHandover",
//!                                   SHA-256(HandoverInfo)]])
//! HandoverInfo      = CBOR([client_id, nonce, jwkThumbprint|null, response_uri])
//! ```
//!
//! dc_api modes:
//!
//! ```text
//! SessionTranscript = CBOR([null, null, ["OpenID4VPDCAPIHandover",
//!                                   SHA-256(DCAPIHandoverInfo)]])
//! DCAPIHandoverInfo = CBOR([origin, nonce, jwkThumbprint|null])
//! ```
//!
//! `jwkThumbprint` is the RAW 32 bytes of the RFC 7638 SHA-256
//! thumbprint of the response-encryption JWK (null for the unencrypted
//! direct_post/dc_api forms).

use sha2::Digest;

/// CBOR-encode a nullable byte-string member (minimal definite-length
/// heads: 0x40+len for <=23 bytes, 0x58+len for 24-255, 0x59+u16 beyond).
fn opt_bstr(v: Option<&[u8]>, buf: &mut Vec<u8>) {
    match v {
        Some(bytes) => {
            let n = bytes.len();
            if n <= 23 {
                buf.push(0x40 + n as u8);
            } else if n <= 255 {
                buf.push(0x58);
                buf.push(n as u8);
            } else {
                buf.push(0x59);
                buf.extend_from_slice(&(n as u16).to_be_bytes());
            }
            buf.extend_from_slice(bytes);
        }
        None => buf.push(0xF6), // null
    }
}

/// CBOR-encode a text string with the minimal definite-length head
/// (0x60+len for lengths 0-23, 0x78+len for 24-255) - the suite's
/// multipaz Cbor.encode emits exactly this canonical shape, so any
/// non-minimal head here desynchronizes the session transcript the
/// verifier re-derives.
fn tstr(s: &str, buf: &mut Vec<u8>) {
    let b = s.as_bytes();
    let n = b.len();
    if n <= 23 {
        buf.push(0x60 + n as u8);
    } else if n <= 255 {
        buf.push(0x78);
        buf.push(n as u8);
    } else {
        buf.push(0x79);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    }
    buf.extend_from_slice(b);
}

/// The redirect-mode transcript (B.2.6.1).
///
/// # Errors
/// Never in practice; the Result keeps the signature stable.
pub fn redirect_transcript(
    client_id: &str,
    nonce: &str,
    response_encryption_jwk_thumbprint_raw: Option<&[u8]>,
    response_uri: &str,
) -> Result<Vec<u8>, String> {
    // HandoverInfo = [client_id, nonce, jwkThumbprint|null, response_uri]
    let mut hi = Vec::new();
    hi.push(0x84); // array(4)
    tstr(client_id, &mut hi);
    tstr(nonce, &mut hi);
    opt_bstr(response_encryption_jwk_thumbprint_raw, &mut hi);
    tstr(response_uri, &mut hi);

    // SessionTranscript = [null, null, ["OpenID4VPHandover", SHA-256(hi)]]
    let digest: [u8; 32] = sha2::Sha256::digest(&hi).into();
    Ok(wrap("OpenID4VPHandover", &digest))
}

/// The dc_api-mode transcript (B.2.6.2).
///
/// # Errors
/// Never in practice; the Result keeps the signature stable.
pub fn dc_api_transcript(
    origin: &str,
    nonce: &str,
    response_encryption_jwk_thumbprint_raw: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // DCAPIHandoverInfo = [origin, nonce, jwkThumbprint|null]
    let mut hi = Vec::new();
    hi.push(0x83); // array(3)
    tstr(origin, &mut hi);
    tstr(nonce, &mut hi);
    opt_bstr(response_encryption_jwk_thumbprint_raw, &mut hi);

    let digest: [u8; 32] = sha2::Sha256::digest(&hi).into();
    Ok(wrap("OpenID4VPDCAPIHandover", &digest))
}

fn wrap(handover_kind: &str, digest: &[u8; 32]) -> Vec<u8> {
    // [null, null, [handover, digest]]
    let mut buf = Vec::new();
    buf.push(0x83); // array(3)
    buf.push(0xF6); // null
    buf.push(0xF6); // null
    buf.push(0x82); // array(2)
    tstr(handover_kind, &mut buf);
    buf.push(0x58);
    buf.push(32);
    buf.extend_from_slice(digest);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_shapes() {
        let t = redirect_transcript("cid", "n0", None, "https://r/u").unwrap();
        assert_eq!(t[0], 0x83);
        let d = dc_api_transcript("https://rp.example", "n0", None).unwrap();
        assert_eq!(d[0], 0x83);
        // both carry the null-null head
        assert_eq!(&t[1..3], &[0xF6, 0xF6]);
        assert_eq!(&d[1..3], &[0xF6, 0xF6]);
    }

    #[test]
    fn minimal_cbor_heads() {
        // THE transcript desync root cause: the outer members carry MINIMAL
        // definite-length heads - the 17-char "OpenID4VPHandover" rides
        // 0x71, never the two-byte 0x78 0x11 form.
        let t = redirect_transcript("cid", "n0", None, "https://r/u").unwrap();
        assert_eq!(
            &t[0..5],
            &[0x83, 0xf6, 0xf6, 0x82, 0x71],
            "array(3) | null | null | array(2) | tstr(17, one-byte head)"
        );
        // The 32-byte digest bstr rides the 1-byte-length form (0x58 0x20)
        // directly after the 17-char string (starts at index 5+17=22).
        assert_eq!(&t[22..24], &[0x58, 0x20], "the digest bstr rides 0x58 20");
        assert_eq!(t.len(), 24 + 32, "5 + 17 + 2 head + 32 digest bytes");
    }

    #[test]
    fn transcript_digest_varies_with_inputs() {
        // The HandoverInfo (client_id/nonce/thumbprint/uri) hashes into the
        // digest: a changed member changes the digest and NOT the shape.
        let base = redirect_transcript("cid", "n0", None, "https://r/u").unwrap();
        let other = redirect_transcript("cid", "n1", None, "https://r/u").unwrap();
        assert_ne!(base, other, "the nonce rides the hashed HandoverInfo");
        assert_eq!(base[0..22].to_vec(), other[0..22].to_vec(), "the outer shape is input-independent");
        // The thumbprint rides when present: a distinct digest, a bstr member.
        let thumb = [9u8; 32];
        let with_thumb = redirect_transcript("cid", "n0", Some(&thumb), "https://r/u").unwrap();
        assert_ne!(base, with_thumb);
    }

    #[test]
    fn transcript_matches_suite_shape() {
        // The suite's logged shape (byte-exact): the digest is SHA-256 over
        // the HandoverInfo CBOR and the wrapper is 83 f6 f6 82 71 <digest>.
        use sha2::Digest;
        let client_id = "x509_hash:abc";
        let nonce = "n-._~";
        let response_uri = "https://v/responseuri";
        let t = redirect_transcript(client_id, nonce, None, response_uri).unwrap();
        // Recompute the HandoverInfo manually: [client_id, nonce, null, uri] (4 members).
        let mut hi = Vec::new();
        hi.push(0x84);
        hi.push(0x60 + client_id.len() as u8);
        hi.extend_from_slice(client_id.as_bytes());
        hi.push(0x60 + nonce.len() as u8);
        hi.extend_from_slice(nonce.as_bytes());
        hi.push(0xf6);
        hi.push(0x60 + response_uri.len() as u8);
        hi.extend_from_slice(response_uri.as_bytes());
        let digest: [u8; 32] = sha2::Sha256::digest(&hi).into();
        assert_eq!(&t[t.len() - 32..], &digest, "the digest is sha256(HandoverInfo)");
    }
}
