// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Raw-TCP TLS listener support - STARTTLS upgrade + implicit TLS for
//! non-HTTP protocols (SMTP, IMAP, POP3, ManageSieve, LMTP), plus
//! connection introspection for Received headers and DANE TLSA
//! verification.
//!
//! No protocol knowledge lives here: the caller owns the wire
//! protocol; this module only wraps `TcpStream`s in TLS on demand.
//!
//! ```text
//! // STARTTLS listener (e.g. SMTP :587):
//! let listener = tls.raw_tcp_listener("0.0.0.0:587").await?;
//! let (tcp, peer) = listener.accept_tcp().await?;
//! // ... protocol negotiation; client sends STARTTLS; reply "220 Ready" ...
//! let tls_stream = listener.upgrade_starttls(tcp).await?;
//! // Introspection for the Received header:
//! let info = TlsInfo::of(&tls_stream); // e.g. "X25519MLKEM768 with ML-DSA-65"
//! ```
//!
//! Implicit-TLS listeners (SMTPS :465, IMAPS :993, POP3S :995) use
//! [`RawTcpListener::accept_tls`], which wraps before the caller sees
//! the stream.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::server::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::certs::WildcardCertResolver;
use crate::crypto::{sentin8_pq_provider, sentin8_tls_versions};

/// A raw-TCP listener that can upgrade connections to TLS on demand
/// (STARTTLS) or accept implicit-TLS connections (TLS from the first
/// byte - SMTPS/IMAPS/POP3S).
///
/// Created via [`crate::Sentin8Tls::raw_tcp_listener`].
pub struct RawTcpListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

/// TLS session introspection for `Received` headers
/// (`with <version> cipher <suite>`) and admin/telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// Negotiated protocol version (e.g. `TLSv1.3`).
    pub version: String,
    /// Negotiated cipher suite name.
    pub cipher_suite: String,
    /// The peer certificate chain (DER, leaf first) when the client
    /// presented one - DANE TLSA verification input.
    pub peer_chain_der: Vec<Vec<u8>>,
}

impl TlsInfo {
    /// Introspect an accepted server TLS stream.
    pub fn of(stream: &TlsStream<tokio::net::TcpStream>) -> Self {
        let (_io, conn) = stream.get_ref();
        let version = conn
            .protocol_version()
            .map(format_tls_version)
            .unwrap_or_else(|| "unknown".to_string());
        let suite = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_else(|| "unknown".to_string());
        let peer_chain_der = conn
            .peer_certificates()
            .map(|chain| chain.iter().map(|c| c.to_vec()).collect())
            .unwrap_or_default();
        Self {
            version,
            cipher_suite: suite,
            peer_chain_der,
        }
    }

    /// `Received:`-header fragment: `version` + `cipher suite`
    /// (e.g. `TLSv1.3 cipher MLKEM...`).
    pub fn received_fragment(&self) -> String {
        format!("{} cipher {}", self.version, self.cipher_suite)
    }
}

/// Map the negotiated rustls version to the conventional name.
fn format_tls_version(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        other => format!("{other:?}"),
    }
}

impl RawTcpListener {
    /// Bind a raw-TCP listener whose connections can be upgraded to TLS
    /// in place (STARTTLS) or wrapped from the first byte (implicit TLS).
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

    /// The bound local address (for logs and health checks).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.tcp_listener.local_addr().ok()
    }

    /// Accept the next **plain TCP** connection (STARTTLS mode): the
    /// caller negotiates the protocol in the clear, then calls
    /// [`upgrade_starttls`](Self::upgrade_starttls) when the client
    /// requests the upgrade.
    pub async fn accept_tcp(&self) -> Result<(tokio::net::TcpStream, SocketAddr), std::io::Error> {
        self.tcp_listener.accept().await
    }

    /// Accept the next connection and wrap it in TLS immediately
    /// (implicit-TLS mode - SMTPS/IMAPS/POP3S).
    pub async fn accept_tls(
        &self,
    ) -> Result<(TlsStream<tokio::net::TcpStream>, SocketAddr), std::io::Error> {
        let (tcp_stream, peer_addr) = self.tcp_listener.accept().await?;
        let tls_stream = self
            .tls_acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
        Ok((tls_stream, peer_addr))
    }

    /// Upgrade an accepted plain connection to TLS **in place**
    /// (STARTTLS): call after the protocol-level "ready" reply.
    ///
    /// The handshake runs on the same socket; buffered plaintext must
    /// be drained by the caller first (an STARTTLS-after-data pipeliner
    /// is a protocol violation - the caller should reject).
    pub async fn upgrade_starttls(
        &self,
        tcp: tokio::net::TcpStream,
    ) -> Result<TlsStream<tokio::net::TcpStream>, String> {
        self.tls_acceptor
            .accept(tcp)
            .await
            .map_err(|e| format!("STARTTLS handshake failed: {e}"))
    }

    /// Poll for the next pending connection without blocking (for
    /// multi-listener select loops).
    pub fn listener(&self) -> &TcpListener {
        &self.tcp_listener
    }
    /// The raw acceptor (for services that own the upgrade mid-session,
    /// e.g. SMTP STARTTLS wrapping an already-accepted stream).
    pub fn tls_acceptor_handle(&self) -> TlsAcceptor {
        self.tls_acceptor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_names() {
        assert_eq!(
            format_tls_version(rustls::ProtocolVersion::TLSv1_3),
            "TLSv1.3"
        );
        assert_eq!(
            format_tls_version(rustls::ProtocolVersion::TLSv1_2),
            "TLSv1.2"
        );
        // Unknown versions render their Debug form (never empty).
        assert!(!format_tls_version(rustls::ProtocolVersion::Unknown(0x12)).is_empty());
    }

    #[test]
    fn received_fragment_shape() {
        let info = TlsInfo {
            version: "TLSv1.3".into(),
            cipher_suite: "MLKEM768_WITH_AES_256_GCM".into(),
            peer_chain_der: vec![],
        };
        assert_eq!(
            info.received_fragment(),
            "TLSv1.3 cipher MLKEM768_WITH_AES_256_GCM"
        );
    }
}
