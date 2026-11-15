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

/// CBOR-encode a nullable byte-string member.
fn opt_bstr(v: Option<&[u8]>, buf: &mut Vec<u8>) {
    match v {
        Some(bytes) => {
            buf.push(0x58);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        None => buf.push(0xF6), // null
    }
}

/// CBOR-encode a text string.
fn tstr(s: &str, buf: &mut Vec<u8>) {
    let b = s.as_bytes();
    buf.push(0x78); // tstr, 1-byte length
    buf.push(b.len() as u8);
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
}
