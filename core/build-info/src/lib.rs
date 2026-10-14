// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-build-info
//!
//! Compile-time build identity for Sentin8 binaries: build hash, service
//! version, and build profile.
//!
//! The build hash is resolved in priority order:
//! 1. `SENTIN8_BUILD_HASH` env var (set by the packaging build from the package
//!    version + timestamp, or manually for reproducible builds).
//! 2. `CARGO_PKG_VERSION` as the fallback (always available).
//!
//! The full service version resolves as `{CARGO_PKG_VERSION}+{git short
//! hash}` when the build system stamped `SENTIN8_GIT_SHA`, bare
//! `{CARGO_PKG_VERSION}` otherwise. The build profile resolves as
//! `SENTIN8_BUILD_PROFILE` stamp first, `debug_assertions` cfg fallback;
//! callers render the profile via [`id()`], which appends the `.d` marker
//! on debug builds (`0.3.0+5f3a9c1.d`).
//!
//! Values are baked in at compile time via `option_env!`. This makes the
//! crate work in any environment — the build system (group Makefile,
//! packaging build) resolves and injects the stamps, and all other builds
//! fall back to the always-available cargo values. No `git` invocation.

/// The compile-time build hash.
///
/// Resolution order (see crate docs): `SENTIN8_BUILD_HASH` env →
/// `CARGO_PKG_VERSION`. This is a `const fn` so it can be used in `const`
/// contexts (e.g. static startup banners).
///
/// # Examples
///
/// ```
/// assert!(!sentin8_build_info::build_hash().is_empty());
/// ```
pub const fn build_hash() -> &'static str {
    match option_env!("SENTIN8_BUILD_HASH") {
        Some(h) => h,
        None => env!("CARGO_PKG_VERSION"),
    }
}

/// The compile-time git short hash stamp (`SENTIN8_GIT_SHA`).
///
/// `None` when the build system did not stamp a source revision
/// (ad-hoc builds; the group Makefile and the packaging build set it
/// via `git rev-parse --short HEAD` of the repo being built). An EMPTY
/// stamp value (a repo without `.git`) is treated as unstamped by the
/// rendering functions — [`version`] omits the `+hash` part rather than
/// rendering a dangling `+`.
///
/// # Examples
///
/// ```
/// match sentin8_build_info::git_sha() {
///     Some(sha) => assert!(!sha.is_empty() || true), // empty = unstamped-equivalent
///     None => {} // unstamped build
/// }
/// ```
pub const fn git_sha() -> Option<&'static str> {
    // A pure Option identity — const-legal. Content inspection (the
    // empty-stamp equivalence) happens at runtime in [`version`];
    // `const` fns cannot compare `str` contents (PartialEq is not const
    // yet).
    option_env!("SENTIN8_GIT_SHA")
}

/// The effective build profile (`"release"` or `"debug"`).
///
/// Resolution order (see crate docs): the `SENTIN8_BUILD_PROFILE` stamp
/// set by the build system first, then the `debug_assertions` cfg — the
/// signal the binary itself carries into its profile, correct for ad-hoc
/// builds too.
///
/// Not a `const fn`: matching `str` CONTENT is not const-callable yet
/// (`PartialEq` for `str` is not a const trait), so the stamp comparison
/// runs at runtime — the match is over compile-time-baked literals, the
/// result is still a fixed `&'static str` per binary.
///
/// # Examples
///
/// ```
/// let p = sentin8_build_info::build_profile();
/// assert!(p == "release" || p == "debug");
/// ```
pub fn build_profile() -> &'static str {
    match option_env!("SENTIN8_BUILD_PROFILE") {
        Some("release") => "release",
        Some("debug") => "debug",
        _ => {
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        }
    }
}

/// The full service version identity: `{version}+{git short hash}`.
///
/// Bare `{CARGO_PKG_VERSION}` when no `SENTIN8_GIT_SHA` stamp was
/// injected (no dangling `+`). Always non-empty.
///
/// Not a `const fn`: `const` contexts cannot allocate, and the joined
/// form requires an allocation. The const identity source remains
/// [`build_hash`]; callers needing a `const` string use that.
///
/// # Examples
///
/// ```
/// assert!(!sentin8_build_info::version().is_empty());
/// ```
pub fn version() -> String {
    match git_sha() {
        // An empty stamp value (a build without a resolvable git HEAD) is
        // unstamped-equivalent — no dangling `+`.
        Some(sha) if !sha.is_empty() => format!("{}+{}", env!("CARGO_PKG_VERSION"), sha),
        _ => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Render the full display identity: [`version`] with the profile marker.
///
/// Release builds return the version unchanged; debug builds append the
/// `".d"` marker (`0.3.0+5f3a9c1.d`) so a dev-fleet binary is
/// distinguishable from a release binary of the same commit at a glance
/// (banners, `/v1/health`, `sentin8-cli captain services`).
///
/// Not a `const fn` (it allocates); call sites invoke it per banner /
/// health hit.
///
/// # Examples
///
/// ```
/// let id = sentin8_build_info::id();
/// assert!(!id.is_empty());
/// if sentin8_build_info::build_profile() == "debug" {
///     assert!(id.ends_with(".d"));
/// }
/// ```
pub fn id() -> String {
    match build_profile() {
        "debug" => format!("{}.d", version()),
        _ => version(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_hash_is_never_empty() {
        assert!(!build_hash().is_empty());
    }

    #[test]
    fn build_hash_is_const_stable() {
        // const fn — same value every call, usable in const contexts.
        const H: &str = build_hash();
        assert_eq!(build_hash(), H);
    }

    #[test]
    fn version_is_never_empty() {
        assert!(!version().is_empty());
    }

    #[test]
    fn profile_is_always_release_or_debug() {
        assert!(
            build_profile() == "release" || build_profile() == "debug",
            "profile must be exactly one of release/debug, got: {}",
            build_profile()
        );
    }

    #[test]
    fn id_debug_marker_matches_profile() {
        // The marker invariant: `.d` suffix IFF the build profile is debug.
        let rendered = id();
        assert!(!rendered.is_empty());
        assert_eq!(
            rendered.ends_with(".d"),
            build_profile() == "debug",
            "id() must end with .d exactly when the profile is debug: {rendered}"
        );
        // The render always starts with the version identity.
        assert!(rendered.starts_with(&version()));
    }

    #[test]
    fn version_without_stamp_is_bare_crate_version() {
        // When no stamp was injected, version() must be the bare crate
        // version — no dangling `+`.
        if git_sha().is_none() {
            assert_eq!(version(), env!("CARGO_PKG_VERSION"));
            assert!(!version().contains('+'));
        }
    }

    #[test]
    fn version_with_stamp_is_joined() {
        // When a stamp WAS injected, version() is `{version}+{sha}`.
        if let Some(sha) = git_sha() {
            assert!(!sha.contains('+'));
            if !sha.is_empty() {
                assert_eq!(version(), format!("{}+{}", env!("CARGO_PKG_VERSION"), sha));
            } else {
                // Empty stamp = unstamped-equivalent.
                assert_eq!(version(), env!("CARGO_PKG_VERSION"));
            }
        }
    }
}
