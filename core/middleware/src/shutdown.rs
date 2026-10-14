// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Graceful shutdown — SIGTERM / SIGINT handling for all Sentin8 services.
//!
//! Provides [`shutdown_signal`] which returns a `Future` that completes when
//! the process receives SIGTERM or SIGINT (or the tokio runtime is stopped).
//! Services should pass it to `axum::serve(...).with_graceful_shutdown(...)`
//! or `select!` it against their main loop.
//!
//! On signal, the future logs a structured "shutdown signal received" event
//! and completes. The caller is responsible for any cleanup (closing DB
//! pools, flushing buffers, etc.) after the future resolves.
//!
//! ## Usage
//!
//! ```text
//! use sentin8_middleware::shutdown_signal;
//!
//! // With axum:
//! axum::serve(listener, app)
//!     .with_graceful_shutdown(shutdown_signal("auth"))
//!     .await?;
//!
//! // With a custom loop:
//! tokio::select! {
//!     _ = run_loop() => {}
//!     _ = shutdown_signal("my-worker") => {
//!         tracing::info!("shutting down");
//!     }
//! }
//! ```

use tokio::signal;

/// Returns a future that completes when SIGTERM or SIGINT is received.
///
/// Logs the signal name and service name before completing.
pub async fn shutdown_signal(service: &str) {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!(service, signal = "SIGINT", "shutdown signal received");
        }
        _ = terminate => {
            tracing::info!(service, signal = "SIGTERM", "shutdown signal received");
        }
    }
}
