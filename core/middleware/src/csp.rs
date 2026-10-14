// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Content-Security-Policy headers
//!
//! Returns CSP headers suitable for Auth UI and Dash. The default policy
//! forbids `unsafe-inline` scripts (only `unsafe-inline` for styles is
//! permitted, since Flutter Web CanvasKit requires it), forbids
//! `eval`, and restricts connect-src to Sentin8 origins.

use axum::http::{HeaderName, HeaderValue};

/// The default Sentin8 Content-Security-Policy string.
///
/// - `default-src 'self'` — everything loads from the same origin by default.
/// - `script-src 'self'` — no inline scripts, no `eval`.
/// - `style-src 'self' 'unsafe-inline'` — Flutter Web needs inline styles.
/// - `img-src 'self' data: https:` — allow data URIs and any https image
///   (for user-uploaded logos served from Storage).
/// - `font-src 'self' data:` — Flutter fonts may be inlined.
/// - `connect-src 'self'` — only same-origin XHR/fetch (TLS routes cross-service).
/// - `frame-ancestors 'none'` — no framing (clickjacking).
/// - `base-uri 'self'` — no `<base>` hijack.
/// - `form-action 'self'` — forms only post to same origin.
/// - `object-src 'none'` — no Flash/Java plugins.
/// - `upgrade-insecure-requests` — force HTTPS.
pub fn default_csp_policy() -> String {
    "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: https:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     frame-ancestors 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     object-src 'none'; \
     upgrade-insecure-requests"
        .to_string()
}

/// Returns the set of security headers (including CSP) that should be
/// attached to every Auth UI / Dash response.
///
/// The returned tuple array can be iterated and inserted into an axum
/// `Response` via `headers_mut().insert()`.
pub fn csp_headers() -> Vec<(HeaderName, HeaderValue)> {
    let csp = default_csp_policy();
    vec![
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_str(&csp).expect("default CSP is valid header value"),
        ),
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        (
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ),
    ]
}

/// Build a CSP policy with an extended `connect-src` (for services that
/// need to talk to additional backends, e.g. a third-party analytics
/// endpoint). The provided origins are appended to `'self'`.
pub fn csp_with_extra_connect_src(extra_origins: &[&str]) -> String {
    let mut srcs = vec!["'self'".to_string()];
    srcs.extend(extra_origins.iter().map(|s| s.to_string()));
    format!(
        "default-src 'self'; \
         script-src 'self'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: https:; \
         font-src 'self' data:; \
         connect-src {}; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'; \
         object-src 'none'; \
         upgrade-insecure-requests",
        srcs.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_csp_forbids_unsafe_inline_script() {
        let p = default_csp_policy();
        assert!(p.contains("script-src 'self'"));
        assert!(!p.contains("script-src 'unsafe-inline'"));
    }

    #[test]
    fn default_csp_forbids_eval() {
        let p = default_csp_policy();
        assert!(!p.contains("'unsafe-eval'"));
    }

    #[test]
    fn default_csp_sets_frame_ancestors_none() {
        let p = default_csp_policy();
        assert!(p.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn default_csp_sets_upgrade_insecure_requests() {
        let p = default_csp_policy();
        assert!(p.contains("upgrade-insecure-requests"));
    }

    #[test]
    fn default_csp_sets_object_src_none() {
        let p = default_csp_policy();
        assert!(p.contains("object-src 'none'"));
    }

    #[test]
    fn csp_headers_returns_non_empty_vec() {
        let headers = csp_headers();
        assert!(!headers.is_empty());
        // Must include the CSP header itself.
        assert!(headers.iter().any(|(n, _)| n == "content-security-policy"));
    }

    #[test]
    fn csp_headers_includes_hsts() {
        let headers = csp_headers();
        assert!(headers
            .iter()
            .any(|(n, _)| n == "strict-transport-security"));
    }

    #[test]
    fn csp_headers_includes_x_frame_options() {
        let headers = csp_headers();
        assert!(headers.iter().any(|(n, _)| n == "x-frame-options"));
        assert!(headers.iter().any(|(_, v)| v == "DENY"));
    }

    #[test]
    fn csp_headers_includes_nosniff() {
        let headers = csp_headers();
        assert!(headers.iter().any(|(n, _)| n == "x-content-type-options"));
    }

    #[test]
    fn csp_with_extra_connect_src_appends_origins() {
        let p = csp_with_extra_connect_src(&["https://analytics.sentin8.local"]);
        assert!(p.contains("connect-src 'self' https://analytics.sentin8.local"));
    }

    #[test]
    fn csp_with_extra_connect_src_no_extra() {
        let p = csp_with_extra_connect_src(&[]);
        assert!(p.contains("connect-src 'self'"));
    }

    #[test]
    fn all_csp_headers_are_valid_header_values() {
        for (_, v) in csp_headers() {
            // Already constructed via from_str; just sanity check non-empty.
            assert!(!v.is_empty());
        }
    }
}
