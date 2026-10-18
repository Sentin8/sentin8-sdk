// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Router ↔ OpenAPI drift guard — the OAPEC enforcement helper.
//!
//! Every spec-owning service ships an integration test that builds its
//! production router and asserts the compiled OpenAPI spec covers every
//! route the router serves (and contains no path the router does not
//! serve). See `design/sentin8-openapi-coverage-design.md` (OAPEC) —
//! annotations decay without enforcement; this test is what keeps the
//! site API reference pages (= `docs/openapi.json`, harvested) equal to
//! the routers.
//!
//! # Route introspection
//!
//! axum 0.8's routing table is inspectable without dispatching requests
//! through the router's `Debug` representation: each `PathRouter` section
//! carries a `node: Node { paths: { RouteId(n): "/path" } }` map and, per
//! `RouteId`, a `MethodRouter` whose `allow_header: Bytes(b"GET,POST")`
//! field holds the exact registered method set (axum maintains it as the
//! `Allow` header value). `HEAD` is axum's implicit mirror of `GET` and is
//! excluded; route-level fallback endpoints (`Route(...)`) carry no method
//! set and are skipped with a warning printed to the test output.
//!
//! When anything fails to parse, the helpers FAIL LOUDLY — an axum Debug
//! format change must break the guard, never let it pass vacuously.
//!
//! # Usage
//!
//! ```no_run
//! use sentin8_shell::drift_guard::{served_routes, assert_openapi_covers_router};
//!
//! # async fn covered() {}
//! # fn spec_pairs() -> Vec<(String, String)> { Vec::new() }
//! let router: axum::Router<()> =
//!     axum::Router::new().route("/v1/things", axum::routing::get(covered));
//! let routes = served_routes(&router);
//! let spec = spec_pairs(); // (method, path) pairs from the service's OpenApi struct
//! assert_openapi_covers_router(&routes, &spec, &["/"]);
//! ```

use std::collections::{BTreeMap, BTreeSet};

/// A served (method, path) pair extracted from an axum router.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServedRoute {
    /// HTTP method (`GET`, `POST`, …).
    pub method: String,
    /// The registered route path in axum placeholder form (`{param}`,
    /// `{*wildcard}`).
    pub path: String,
}

/// Parsed view of the routing table.
#[derive(Debug, Default)]
struct RoutingTable {
    /// RouteId → path (from every `node.paths` map).
    paths: BTreeMap<String, String>,
    /// RouteId → registered methods (from each `MethodRouter`'s
    /// `allow_header`).
    methods: BTreeMap<String, BTreeSet<String>>,
    /// RouteIds whose endpoint is a bare `Route(...)` (route_service /
    /// fallback services) — no method set; skipped and reported.
    non_method_routes: BTreeSet<String>,
}

impl RoutingTable {
    /// Parse the pretty Debug output of an axum Router.
    ///
    /// Returns None when the expected structure is absent (format change)
    /// so the caller can fail loudly.
    fn parse(debug: &str) -> Option<RoutingTable> {
        // Only the traffic-carrying path_router section matters; the
        // fallback_router section (catch-alls / SPA hosts) is exempt
        // territory. Section names come straight from axum's Debug impl.
        let traffic_section = match debug.split_once("path_router: PathRouter {") {
            Some((_, rest)) => rest,
            None => return None,
        };
        // Cut at the sibling fallback_router section when present.
        let traffic = match traffic_section.split_once("fallback_router: PathRouter {") {
            Some((head, _)) => head,
            None => traffic_section,
        };

        let mut table = RoutingTable::default();
        let mut saw_paths = false;
        let mut saw_method_router = false;

        // Current RouteId whose MethodRouter block we are inside of (the
        // routes map precedes the node.paths map; the allow_header lines of
        // an entry follow its RouteId line directly).
        let mut current_id: Option<String> = None;

        let mut lines = traffic.lines().peekable();

        // Two printed shapes for map entries (both occur under `{:#?}`):
        //   expanded: `RouteId(` / `  2,` / `): "/v1/things",`
        //   compact:  `RouteId(2): "/v1/things",`
        while let Some(line) = lines.next() {
            let trimmed = line.trim();

            if trimmed == "RouteId(" {
                // EXPANDED shape: the ID number is the next line and the
                // `): value` line follows it.
                let id = lines
                    .next()
                    .map(|l| l.trim().trim_end_matches(',').to_string());
                let value_line = lines.next().map(|l| l.trim().to_string());
                if let (Some(id), Some(value_line)) = (id, value_line) {
                    if let Some(rest) = value_line.strip_prefix("): ") {
                        let value = rest.trim().trim_end_matches(',').trim();
                        match classify_value(value, &id, &mut table, &mut saw_paths, &mut saw_method_router) {
                            Classification::MethodRouter => current_id = Some(id),
                            _ => current_id = None,
                        }
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("RouteId(") {
                // COMPACT shape: `RouteId(2): "/v1/things",` (or the
                // MethodRouter variant, which still prints expanded).
                if let Some(colon_at) = rest.find("): ") {
                    let id = rest[..colon_at].trim().trim_end_matches(',').to_string();
                    let value = rest[colon_at + 3..].trim().trim_end_matches(',').trim();
                    match classify_value(value, &id, &mut table, &mut saw_paths, &mut saw_method_router) {
                        Classification::MethodRouter => current_id = Some(id),
                        _ => current_id = None,
                    }
                }
            } else if trimmed == "allow_header: Bytes(" {
                // EXPANDED Bytes shape: the b"…" literal is the next line.
                let header_line = lines.next().map(|l| l.trim().to_string());
                if let Some(header_line) = header_line {
                    if let Some(rest) = header_line.strip_prefix("b\"") {
                        if let Some(end) = rest.find('"') {
                            let header = &rest[..end];
                            let methods: BTreeSet<String> = header
                                .split(',')
                                .map(|m| m.trim().to_ascii_uppercase())
                                .filter(|m| !m.is_empty() && m != "HEAD")
                                .collect();
                            if !methods.is_empty() {
                                if let Some(id) = &current_id {
                                    table.methods.insert(id.clone(), methods);
                                }
                            }
                        }
                    }
                }
            } else if let Some(rest) =
                trimmed.strip_prefix("allow_header: Bytes(b\"")
            {
                // COMPACT Bytes shape (single line).
                if let Some(end) = rest.find('"') {
                    let header = &rest[..end];
                    let methods: BTreeSet<String> = header
                        .split(',')
                        .map(|m| m.trim().to_ascii_uppercase())
                        .filter(|m| !m.is_empty() && m != "HEAD")
                        .collect();
                    if !methods.is_empty() {
                        if let Some(id) = &current_id {
                            table.methods.insert(id.clone(), methods);
                        }
                    }
                }
            }
        }

        if !(saw_paths && saw_method_router) {
            return None;
        }
        Some(table)
    }
}

/// What a `): value` map entry resolves to.
enum Classification {
    /// `): "path",` — a registered route path (saw_paths).
    Path,
    /// `): MethodRouter(` — a method-carrying endpoint (saw_method_router).
    MethodRouter,
    /// `): Route(...)` — a route_service/fallback endpoint (no methods).
    RouteEndpoint,
}

/// Insert one classified map entry into the table.
fn classify_value(
    value: &str,
    id: &str,
    table: &mut RoutingTable,
    saw_paths: &mut bool,
    saw_method_router: &mut bool,
) -> Classification {
    if value.starts_with('"') {
        table
            .paths
            .insert(id.to_string(), value.trim_matches('"').to_string());
        *saw_paths = true;
        Classification::Path
    } else if value == "MethodRouter(" {
        *saw_method_router = true;
        Classification::MethodRouter
    } else {
        table.non_method_routes.insert(id.to_string());
        Classification::RouteEndpoint
    }
}

/// Extract the served `(method, path)` pairs from an axum router.
///
/// axum wildcard placeholders (`{*name}`) are normalized to the OpenAPI
/// path-parameter form (`{name}`) — the utoipa annotations use the same
/// `{name}` literal for catch-all segments, so both sides compare equal.
///
/// # Panics
///
/// Panics when the router's Debug output can no longer be parsed (an axum
/// upgrade changed the format) — the guard fails loudly, never vacuously.
pub fn served_routes<S>(router: &axum::Router<S>) -> Vec<ServedRoute> {
    let debug = format!("{router:#?}");
    served_routes_from_debug(&debug)
}

fn served_routes_from_debug(debug: &str) -> Vec<ServedRoute> {
    let table = RoutingTable::parse(debug).unwrap_or_else(|| {
        panic!(
            "drift guard: cannot parse the axum Router Debug output — an \
             axum upgrade changed the format; fix `parse` in \
             sentin8-shell's drift_guard.rs\n\n--- raw debug ---\n{debug}"
        )
    });

    for id in &table.non_method_routes {
        eprintln!(
            "drift guard: skipping RouteId({id}) — a route-level service \
             endpoint (route_service/fallback) carries no method set"
        );
    }

    let mut routes = Vec::new();
    for (id, path) in &table.paths {
        match table.methods.get(id) {
            Some(methods) => {
                for method in methods {
                    routes.push(ServedRoute {
                        method: method.clone(),
                        path: normalize_axum_path(path),
                    });
                }
            }
            None if table.non_method_routes.contains(id) => {}
            // A PathRouter path with neither a MethodRouter nor a known
            // Route endpoint means the parser missed something — fail.
            None => panic!(
                "drift guard: path `{path}` (RouteId {id}) has no parsed \
                 method set — the Debug parser missed its MethodRouter \
                 block; fix `parse` in sentin8-shell's drift_guard.rs"
            ),
        }
    }
    routes.sort();
    routes
}

/// axum catch-all `{*name}` → OpenAPI `{name}` (both forms denote the
/// capture; utoipa annotations in this tree write `{name}`).
fn normalize_axum_path(path: &str) -> String {
    if path.contains("{*") {
        path.replace("{*", "{")
    } else {
        path.to_string()
    }
}

/// (method, path) pairs from a utoipa-generated OpenAPI spec — the
/// per-service test passes `{Service}OpenApi::openapi()` here.
pub fn spec_pairs(spec: &utoipa::openapi::OpenApi) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, item) in &spec.paths.paths {
        let pairs = [
            ("GET", &item.get),
            ("PUT", &item.put),
            ("POST", &item.post),
            ("DELETE", &item.delete),
            ("OPTIONS", &item.options),
            ("HEAD", &item.head),
            ("PATCH", &item.patch),
            ("TRACE", &item.trace),
        ];
        for (method, op) in pairs {
            // `HEAD` is axum's implicit mirror of `GET` (drift_guard docs);
            // the guard never emits HEAD in served_routes, so a spec-level
            // HEAD pair would always read as stale — skip it here too.
            if method == "HEAD" {
                continue;
            }
            if op.is_some() {
                out.push((method.to_string(), path.clone()));
            }
        }
    }
    out.sort();
    out
}

/// The drift-guard assertion (OAPEC design §3).
///
/// Asserts BOTH directions — every served route appears in the spec and
/// every spec pair is served — panicking with a copy-pasteable list of
/// the missing/stale `(method, path)` pairs.
///
/// `exempt_path_prefixes` skips catch-all SPA hosts and pass-through
/// surfaces (`/openapi.json` is always exempt automatically). `HEAD` is
/// normalized to `GET` (axum's implicit mirror).
pub fn assert_openapi_covers_router(
    served: &[ServedRoute],
    spec_pairs: &[(String, String)],
    exempt_path_prefixes: &[&str],
) {
    let exempt = |path: &str| {
        path == "/openapi.json"
            || exempt_path_prefixes.iter().any(|p| path.starts_with(p))
    };

    let spec_set: BTreeSet<(String, String)> = spec_pairs
        .iter()
        .map(|(m, p)| (m.clone(), p.clone()))
        .collect();

    let served_set: BTreeSet<(String, String)> = served
        .iter()
        .filter(|r| !exempt(&r.path))
        .map(|r| (r.method.clone(), r.path.clone()))
        .collect();

    let missing: Vec<&ServedRoute> = served
        .iter()
        .filter(|r| !exempt(&r.path))
        .filter(|r| {
            let normalized = if r.method == "HEAD" {
                "GET"
            } else {
                r.method.as_str()
            };
            !spec_set.contains(&(normalized.to_string(), r.path.clone()))
        })
        .collect();

    let stale: Vec<&(String, String)> = spec_set
        .iter()
        .filter(|p| !served_set.contains(p))
        .collect();

    let mut msg = String::new();
    if !missing.is_empty() {
        msg.push_str(&format!(
            "\nOpenAPI drift: {} SERVED route(s) missing from the spec:\n",
            missing.len()
        ));
        for r in &missing {
            msg.push_str(&format!("    {} {}\n", r.method, r.path));
        }
    }
    if !stale.is_empty() {
        msg.push_str(&format!(
            "\nOpenAPI drift: {} SPEC pair(s) no longer served (stale):\n",
            stale.len()
        ));
        for (m, p) in &stale {
            msg.push_str(&format!("    {m} {p}\n"));
        }
    }
    assert!(
        msg.is_empty(),
        "router ↔ OpenAPI mismatch — annotate the missing handlers in the \
         service's `#[openapi(paths(...))]` list (or delete stale spec \
         pairs), then regenerate the `docs/openapi.json` dump.{}\n",
        msg
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};

    #[tokio::test]
    async fn parses_basic_router() {
        async fn a() {}
        async fn b() {}
        async fn c() {}
        let router: axum::Router<()> = axum::Router::new()
            .route("/v1/things", get(a).post(b))
            .route("/v1/things/{id}", get(c));
        let routes = served_routes(&router);
        let as_set: BTreeSet<(String, String)> =
            routes.into_iter().map(|r| (r.method, r.path)).collect();
        assert!(as_set.contains(&("GET".into(), "/v1/things".into())));
        assert!(as_set.contains(&("POST".into(), "/v1/things".into())));
        assert!(as_set.contains(&("GET".into(), "/v1/things/{id}".into())));
        assert_eq!(as_set.len(), 3);
    }

    #[tokio::test]
    async fn parse_fails_loudly_on_unrecognizable_input() {
        // An unrecognizable debug string fails the guard (never passes
        // vacuously) — both when the sections are absent...
        let result = std::panic::catch_unwind(|| {
            let _ = served_routes_from_debug("not a router debug: 42");
        });
        assert!(result.is_err(), "absent sections must fail loudly");
        // ...and when the routes/node maps are empty.
        let result = std::panic::catch_unwind(|| {
            let _ = served_routes_from_debug(
                "Router { path_router: PathRouter { routes: {} } }",
            );
        });
        assert!(result.is_err(), "empty maps must fail loudly");
    }

    #[tokio::test]
    async fn drift_guard_panics_on_missing_route() {
        async fn a() {}
        let router: axum::Router<()> = axum::Router::new().route("/v1/things", get(a));
        let routes = served_routes(&router);
        let spec = vec![("GET".to_string(), "/v1/other".to_string())];
        let result = std::panic::catch_unwind(move || {
            assert_openapi_covers_router(&routes, &spec, &[]);
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn drift_guard_passes_when_covered() {
        async fn a() {}
        async fn b() {}
        let router: axum::Router<()> = axum::Router::new()
            .route("/v1/things", get(a))
            .route("/v1/things", post(b))
            .route("/openapi.json", get(a));
        let routes = served_routes(&router);
        let spec = vec![
            ("GET".to_string(), "/v1/things".to_string()),
            ("POST".to_string(), "/v1/things".to_string()),
        ];
        // /openapi.json auto-exempt.
        assert_openapi_covers_router(&routes, &spec, &[]);
    }

    #[tokio::test]
    async fn exemption_prefixes_are_respected() {
        async fn a() {}
        let router: axum::Router<()> =
            axum::Router::new().route("/v1/proxy/everything", get(a));
        let routes = served_routes(&router);
        assert_openapi_covers_router(&routes, &[], &["/v1/proxy"]);
    }

    #[tokio::test]
    async fn head_is_normalized_to_get() {
        let spec = vec![("GET".to_string(), "/v1/things".to_string())];
        let routes = vec![
            ServedRoute { method: "GET".into(), path: "/v1/things".into() },
            ServedRoute { method: "HEAD".into(), path: "/v1/things".into() },
        ];
        assert_openapi_covers_router(&routes, &spec, &[]);
    }
}