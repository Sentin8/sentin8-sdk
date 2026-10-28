// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! TLS listener - wraps a `tokio::net::TcpListener` with a rustls `TlsAcceptor`.
//!
//! The listener accepts incoming TCP connections and wraps them in a TLS
//! handshake using the `WildcardCertResolver`.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::server::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::certs::WildcardCertResolver;
use crate::crypto::{sentin8_pq_provider, sentin8_tls_versions};

/// A TLS listener bound to a socket address.
///
/// Created by `Sentin8Tls::tls_listener()`. The caller accepts raw TCP
/// connections via `accept()` and runs the TLS handshake (via
/// [`Self::tls_acceptor`]) inside its per-connection task - a stalled
/// handshake delays one task, never the accept loop (tls README §6).
pub struct TlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Bind a TLS listener on `addr` using the given cert resolver.
    pub async fn bind(
        addr: &str,
        cert_resolver: Arc<WildcardCertResolver>,
    ) -> Result<Self, String> {
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind {addr}: {e}"))?;

        let server_config = ServerConfig::builder_with_provider(Arc::new(sentin8_pq_provider()))
            .with_protocol_versions(&sentin8_tls_versions())
            .map_err(|e| format!("invalid protocol versions: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    /// Bind a TLS listener that **requests** client certificates (optional
    /// mTLS - see the sentin8-tls design doc).
    ///
    /// The presented cert is verified against `client_ca_pem` (Sentin8:Acme
    /// Root CA); a handshake *without* a client cert is still accepted
    /// (`allow_unauthenticated`) so public clients keep working. The peer
    /// certificate is retrievable from the accepted stream via
    /// [`TlsStreamExt::peer_cert_der`] for `X-Sentin8-Client-Cert-*` header
    /// injection.
    pub async fn bind_with_client_auth(
        addr: &str,
        cert_resolver: Arc<WildcardCertResolver>,
        client_ca_pem: &[u8],
    ) -> Result<Self, String> {
        use rustls::server::WebPkiClientVerifier;

        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind {addr}: {e}"))?;

        let mut roots = rustls::RootCertStore::empty();
        let mut pem_reader = std::io::BufReader::new(client_ca_pem);
        for cert in rustls_pemfile::certs(&mut pem_reader) {
            let cert = cert.map_err(|e| format!("parse client CA pem: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("add client CA to root store: {e}"))?;
        }
        if roots.is_empty() {
            return Err("no usable CA certificates in client_ca_pem".to_string());
        }

        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| format!("build client cert verifier: {e}"))?;

        let server_config = ServerConfig::builder_with_provider(Arc::new(sentin8_pq_provider()))
            .with_protocol_versions(&sentin8_tls_versions())
            .map_err(|e| format!("invalid protocol versions: {e}"))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(cert_resolver);

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    /// Get the local socket address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.tcp_listener.local_addr().ok()
    }

    /// Bind a TLS listener that REQUESTS a client certificate and accepts
    /// ANY presented certificate WITHOUT CA verification (the
    /// `allow_self_signed` posture - DESIGN §9a.12).
    ///
    /// SECURITY: this posture NEVER makes a presented certificate trusted -
    /// it only carries the cert through the handshake so the application
    /// layer (Sentin8:Auth's RFC 8705 client-auth decision) can bind the
    /// thumbprint against the registration row. Unregistered certs
    /// authenticate nothing. Use it ONLY on surfaces whose client-auth
    /// decision is made by the application (the conformance rig's
    /// self_signed_tls_client_auth variants).
    ///
    /// The peer certificate is retrievable via [`TlsStreamExt::peer_cert_der`]
    /// exactly as in the CA-verified posture.
    pub async fn bind_with_client_auth_allow_self_signed(
        addr: &str,
        cert_resolver: Arc<WildcardCertResolver>,
    ) -> Result<Self, String> {
        // An accept-anything client verifier: client cert chain validation
        // is DELEGATED to the application (auth compares the RFC 8705
        // thumbprint against the registration row - a row that does not
        // carry the thumbprint never authenticates). This type exists ONLY
        // to let a self-signed client complete the handshake.
        #[derive(Debug)]
        struct AcceptAnyClientCert;

        impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
            fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
                &[]
            }

            // OPTIONAL client auth (the CA posture's
            // `allow_unauthenticated` semantics): handshakes WITHOUT a
            // client certificate keep working - only the RFC 8705
            // application decision reads a presented cert's identity.
            fn client_auth_mandatory(&self) -> bool {
                false
            }

            fn verify_client_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
                // Accept the presented cert - trust is the application's
                // decision (DESIGN §9a.12).
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                // Accept the handshake proof-of-possession without chain
                // validation - the cert itself is never trusted beyond this
                // handshake (DESIGN §9a.12).
                let _ = (message, cert, dss);
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                ]
            }
        }

        let verifier = Arc::new(AcceptAnyClientCert);

        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind {addr}: {e}"))?;

        let server_config = ServerConfig::builder_with_provider(Arc::new(sentin8_pq_provider()))
            .with_protocol_versions(&sentin8_tls_versions())
            .map_err(|e| format!("invalid protocol versions: {e}"))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(cert_resolver);

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    /// Accept the next raw TCP connection (TLS handshake is deferred -
    /// run it with [`Self::tls_acceptor`] inside the per-connection task).
    pub async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr), std::io::Error> {
        self.tcp_listener.accept().await
    }

    /// The TLS acceptor for this listener (handshake inside the
    /// per-connection task - see the type-level doc).
    pub fn tls_acceptor(&self) -> &TlsAcceptor {
        &self.tls_acceptor
    }

    /// Get the underlying TCP listener (for graceful shutdown etc.).
    pub fn tcp_listener(&self) -> &TcpListener {
        &self.tcp_listener
    }
}

/// Extensions over the accepted server TLS stream.
///
/// `ServerConnection` derefs through `ConnectionCommon` to `CommonState`,
/// which exposes `peer_certificates()` - the client's certificate chain
/// after an optional-client-auth handshake.
pub trait TlsStreamExt {
    /// The DER bytes of the client's leaf certificate, when the client
    /// presented one. `None` on anonymous connections (no client auth
    /// configured, or the client skipped the optional request).
    fn peer_cert_der(&self) -> Option<Vec<u8>>;
}

impl TlsStreamExt for tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    fn peer_cert_der(&self) -> Option<Vec<u8>> {
        let (_io, conn) = self.get_ref();
        conn.peer_certificates()
            .and_then(|chain| chain.first())
            .map(|c| c.to_vec())
    }
}

fn cert_der_to_pem_bytes(der: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for chunk in b64.as_bytes().chunks(64) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    out
}

/// Convert DER to PEM (exposed for header injection of `X-Sentin8-Client-Cert-Chain`).
pub fn cert_der_to_pem(der: &[u8]) -> String {
    String::from_utf8_lossy(&cert_der_to_pem_bytes(der)).into_owned()
}
