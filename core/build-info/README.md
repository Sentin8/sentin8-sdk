# Design Doc: sentin8-build-info (Compile-Time Build Identity)

## 1. Summary

`sentin8-build-info` exposes the compile-time identity of a Sentin8
binary: the **build hash** (source revision stamp), the **service
version** (`{CARGO_PKG_VERSION}+{git short hash}`), and the **build
profile** (`"release"` / `"debug"`, rendered by callers as a `.d`
postfix on debug builds). Every Sentin8 service surfaces the identity
in its startup banner and `/v1/health` payload so operators can verify
WHICH binary runs — per instance, per profile.

## 2. Motivation

- Operators and support tooling need to know **what is running**, not just
  what is deployed: rolling upgrades mean different instances of the same
  service can run different builds simultaneously, and a dev fleet's
  debug binary must be distinguishable from a release binary of the same
  commit at a glance.
- A bare `0.1.0` tells the operator nothing about WHICH source state is
  running; the git short hash pins the version to a commit in the owning
  repository.
- The identity must exist in *every* build environment (packaged .deb,
  local debug builds, CI) without requiring a git checkout or network
  access at build time — the *build system* (group Makefile, packaging
  rules) resolves the stamp, the crate never shells out to `git`.

## 3. Architecture & High-Level Design

```mermaid
graph TD
    A[Group Makefile / packaging build] -->|"SENTIN8_GIT_SHA + SENTIN8_BUILD_HASH"| C[option_env! at compile time]
    B[Local / CI build] -->|unset| D["fallback: hash = version, profile = debug_assertions cfg"]
    C --> E["build_hash() → &'static str"]
    D --> E
    C --> V["version() → {CARGO_PKG_VERSION}+{git_sha} (or bare version when unstamped)"]
    D --> V
    C --> P["build_profile() → release | debug"]
    D --> P
    E --> F[Startup banners, /health payloads, diagnostics]
    V --> F
    P --> G["callers render id() + profile postfix (debug → suffix '.d')"]
```

Stamp resolution orders:

1. **Build hash**: `SENTIN8_BUILD_HASH` env var — set by the packaging
   build from the package version + timestamp (or manually for
   reproducible builds); fallback `CARGO_PKG_VERSION`.
2. **Git short hash**: `SENTIN8_GIT_SHA` env var — set by the group
   Makefile build targets (`git rev-parse --short HEAD` of the repo
   being built) and by the packaging build; fallback: omitted from the
   rendered version.
3. **Build profile**: `SENTIN8_BUILD_PROFILE` env var (`release` /
   `debug`) — set by the group Makefile build targets to match the
   active cargo profile; fallback: the `debug_assertions` cfg (the
   compile-time signal the binary itself carries into its profile).

## 4. Key Traits and Data Structures

- **`build_hash() -> &'static str`** — a `const fn`, so the value can be
  used in `const` contexts (static startup banners, embedded payload
  fields) as well as runtime expressions.
- **`version() -> &'static str`** — the full service identity:
  `{CARGO_PKG_VERSION}+{SENTIN8_GIT_SHA}` when the stamp is present,
  bare `{CARGO_PKG_VERSION}` otherwise. Also a `const fn`.
- **`build_profile() -> &'static str`** — `"release"` or `"debug"`; a
  `const fn`.
- **`id() -> String`** — `{version()}` plus the debug marker: an empty
  postfix on release, `".d"` on debug (`"0.3.0+5f3a9c1.d"`). The one
  call site for banners and health payloads; allocates (not a `const
  fn`) but is evaluated once per banner/health hit.

## 5. Rationale, Trade-offs, and Alternatives

- **`option_env!` over build-script git invocation.** A build script that
  shells out to `git` couples compilation to a repository checkout — it
  breaks packaged source builds, vendored builds, and reproducible builds.
  `option_env!` keeps the crate hermetic; the build system (group
  Makefile per-repo loop, packaging pipeline) resolves and injects the
  stamp — the same division of labor the build hash already uses.
- **Version fallback over error.** `env!("CARGO_PKG_VERSION")` guarantees
  a non-empty, meaningful identity in every environment without failing
  compilation; a hard error would break all ad-hoc builds.
- **`debug_assertions` cfg as the profile fallback.** An ad-hoc `cargo
  build` outside the Makefile still reports the correct profile because
  the flag is baked into the binary by the cargo profile itself — no
  coordination with the build system required. An explicitly stamped
  `SENTIN8_BUILD_PROFILE` stays the primary (a cross-profile cached
  artifact still carries its own honest signal).
- **`.d` rendered by callers, not baked into `version()`.** The version
  string stays a pure `{version}+{hash}` identity (parseable, sortable);
  the profile marker is a *display* concern of the banner/health
  renderer. Baking it in would make the CLI's `{version}.{build_hash}`
  collapse logic and any semver-ish parsing see the marker as part of
  the version.
- **`const fn` over lazy static.** The value is known at compile time by
  construction; a runtime initializer adds nothing but cost.

## 6. Internal Implementation & Invariants (Private Design)

- **Invariants:**
  - `build_hash()` and `version()` never return an empty string.
  - Both values are stable for the lifetime of the process (compile-time
    constants).
  - When `SENTIN8_BUILD_HASH` is unset at compile time, the build hash
    equals `CARGO_PKG_VERSION`.
  - When `SENTIN8_GIT_SHA` is unset at compile time, `version()` equals
    `CARGO_PKG_VERSION` exactly (no dangling `+`).
  - `build_profile()` is exactly one of `"release"` / `"debug"` in every
    build.
  - `id()` ends with `.d` **iff** the build profile is `debug`.
- **No runtime dependency** on environment, filesystem, or git — once
  compiled, the identity is fixed.

## 7. Unresolved Questions / Future Designs

- None currently. (The former open question — a source-revision stamp —
  is resolved by `SENTIN8_GIT_SHA` + `version()`.)

---

**Design attribution:** sentin8:build-info and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
