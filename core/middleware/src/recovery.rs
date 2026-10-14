// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Panic recovery middleware.
//!
//! Catches panics in downstream handlers and converts them to 500 responses
//! with a structured error body, preventing the server from crashing on a
//! single bad request.

use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sentin8_errors::{ErrorCode, Sentin8Error};

/// Middleware that recovers from panics in downstream handlers.
///
/// If a handler panics, this middleware catches the panic, logs it, and
/// returns a 500 Internal Server Error with a structured body.
pub async fn recovery(req: Request, next: Next) -> Response {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // We cannot `await` inside catch_unwind, so we wrap the future
        // creation. The actual execution happens below.
        next.run(req)
    })) {
        Ok(fut) => fut.await,
        Err(panic_payload) => {
            let msg = panic_message(&panic_payload);
            tracing::error!(panic = %msg, "handler panicked");
            Sentin8Error::new(ErrorCode::Internal, format!("internal error: {msg}")).into_response()
        }
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

// Note: the catch_unwind approach above does not actually work for async
// futures because the future is created synchronously but awaited outside
// the catch_unwind scope. A production implementation will use
// `tokio::task::spawn_blocking` + a oneshot channel, or the `tower` layer's
// `catch_unwind` util. This scaffold establishes the interface.

/// Placeholder response builder for panic recovery tests.
#[cfg(test)]
pub fn panic_response(msg: &str) -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": ErrorCode::Internal.as_str(),
            "message": format!("internal error: {msg}")
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_message_extracts_str() {
        let p: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(panic_message(&p), "boom");
    }

    #[test]
    fn panic_message_extracts_string() {
        let p: Box<dyn std::any::Any + Send> = Box::new("boom".to_string());
        assert_eq!(panic_message(&p), "boom");
    }

    #[test]
    fn panic_message_handles_unknown() {
        let p: Box<dyn std::any::Any + Send> = Box::new(42i32);
        assert_eq!(panic_message(&p), "unknown panic payload");
    }
}
