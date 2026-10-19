// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! RFW response types - the response envelope for admin UI endpoints.

use crate::page::AdminUiPage;
use serde::{Deserialize, Serialize};

/// The response from an admin UI endpoint.
///
/// - `GET /v1/admin/ui/{page}` → `AdminUiResponse::Page(page_def)`
/// - `POST /v1/admin/{resource}` → `AdminUiResponse::Page(updated_page_def)` or `AdminUiResponse::Redirect(route)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "response_type", rename_all = "snake_case")]
pub enum AdminUiResponse {
    /// Render this page definition.
    Page {
        /// The page definition to render.
        page: AdminUiPage,
    },
    /// Redirect to this route (e.g. after a successful form submission).
    Redirect {
        /// The route to navigate to.
        route: String,
    },
    /// An error occurred (validation error, server error, etc.).
    Error {
        /// Human-readable error message.
        message: String,
        /// Per-field validation errors, when applicable.
        #[serde(default)]
        field_errors: Vec<FieldError>,
    },
}

/// A per-field validation error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldError {
    /// The form field key the error refers to.
    pub field: String,
    /// The validation message shown under the field.
    pub message: String,
}

impl AdminUiResponse {
    /// Create a page response.
    pub fn page(page: AdminUiPage) -> Self {
        Self::Page { page }
    }

    /// Create a redirect response.
    pub fn redirect(route: impl Into<String>) -> Self {
        Self::Redirect {
            route: route.into(),
        }
    }

    /// Create an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
            field_errors: Vec::new(),
        }
    }

    /// Create an error response with field errors.
    pub fn validation_error(message: impl Into<String>, field_errors: Vec<FieldError>) -> Self {
        Self::Error {
            message: message.into(),
            field_errors,
        }
    }
}
