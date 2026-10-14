// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Shared OpenAPI spec generation for Sentin8 services.
//!
//! Each platform service uses `utoipa` to annotate its axum handlers with
//! `#[utoipa::path]`. This crate provides:
//!
//! - The `OpenApi` derive macro (re-exported from `utoipa`)
//! - The `openapi_route()` helper — mounts `GET /openapi.json` on an axum
//!   `Router`, serving the generated OpenAPI spec
//!
//! ## Usage
//!
//! ```text
//! use sentin8_openapi::OpenApi;
//! use utoipa::path;
//!
//! #[derive(OpenApi)]
//! #[openapi(
//!     paths(create_property, list_properties),
//!     components(schemas(CreatePropertyRequest, Property)),
//!     security(),
//!     tags(name = "stat", description = "Sentin8:Stat admin API"),
//! )]
//! pub struct StatOpenApi;
//!
//! // In server.rs:
//! let openapi = StatOpenApi::openapi();
//! router = router.merge(sentin8_openapi::openapi_route(openapi));
//! ```

#![deny(missing_docs)]

pub use utoipa::OpenApi;

use axum::routing::get;
use axum::{Json, Router};

/// Mount the OpenAPI JSON endpoint on an axum `Router`.
///
/// Returns a `Router` with `GET /openapi.json` that serves the generated
/// OpenAPI spec as JSON. The spec is generated at build time from
/// `#[utoipa::path]` annotations on the service's handlers.
///
/// # Example
///
/// ```text
/// let openapi = StatOpenApi::openapi();
/// router = router.merge(sentin8_openapi::openapi_route(openapi));
/// ```
pub fn openapi_route(openapi: utoipa::openapi::OpenApi) -> Router {
    Router::new().route("/openapi.json", get(move || async move { Json(openapi) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    #[tokio::test]
    async fn openapi_route_serves_spec_at_openapi_json() {
        // Build a minimal spec by hand — the route only hosts it.
        let mut spec = utoipa::openapi::OpenApi::default();
        spec.info.title = "Sentin8:Test".into();
        spec.info.version = "1".into();

        let app = openapi_route(spec);
        let resp = app
            .oneshot(
                axum::http::Request::get("/openapi.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["info"]["title"], "Sentin8:Test");
        assert_eq!(v["openapi"], "3.1.0", "utoipa emits OpenAPI 3.1");
    }

    #[tokio::test]
    async fn openapi_route_only_mounts_openapi_json() {
        let app = openapi_route(utoipa::openapi::OpenApi::default());
        let resp = app
            .oneshot(
                axum::http::Request::get("/v1/other")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "route must not swallow other paths");
    }
}
