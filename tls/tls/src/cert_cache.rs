// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Persisted server-leaf cache (WARM-1, DESIGN §6.5 of the crate README).
//!
//! Minted leaves are caller-custodied artifacts exactly like the workload
//! client pairs in `.run/secrets/m2m-credentials/`: the resolver persists
//! every successfully minted server leaf to
//! `{SENTIN8_SECRETS_DIR}/tls-certs/{hostname}.crt/.key` (0700 dir / 0600
//! files) and pre-warms from that dir at boot, so a process restart or a
//! dev reset serves every previously-minted hostname with ZERO mint
//! round-trips. The on-demand Acme fetch remains the fallback for
//! genuinely new hostnames.
//!
//! Bounded-disk discipline (CR-TLS-2 applied to disk): the SNI key space
//! is client-controlled, so prewarm loads at most
//! `SENTIN8_TLS_CERT_CACHE_MAX` hostnames (newest-mtime first) and prunes
//! expired pairs on load - a public listener cannot accumulate unbounded
//! files.

use std::path::PathBuf;

/// Default cap on pre-warmed hostnames (see [`tls_cert_cache_max`]).
const DEFAULT_CACHE_MAX: usize = 256;

/// The leaf-cache dir: `{SENTIN8_SECRETS_DIR}/tls-certs/`. Mirrors the
/// m2m-credentials derivation (0700 dir holding private keys).
pub fn tls_cert_cache_dir() -> PathBuf {
    let secrets =
        std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".to_string());
    PathBuf::from(secrets).join("tls-certs")
}

/// How many hostnames prewarm may load (newest-mtime first).
pub fn tls_cert_cache_max() -> usize {
    std::env::var("SENTIN8_TLS_CERT_CACHE_MAX")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_CACHE_MAX)
}

/// Persist a minted leaf pair under the cache dir (0700/0600).
///
/// Best-effort by design: a read-only or missing cache dir NEVER fails the
/// mint - the in-memory registration already succeeded and the next boot
/// simply re-mints on demand (load-or-mint, never load-only).
pub fn persist_leaf_pair(hostname: &str, cert_pem: &[u8], key_pem: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tls_cert_cache_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return; // unwritable cache root - serving continues, next boot re-mints
    }
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let safe = cache_file_stem(hostname);
    let cert_path = dir.join(format!("{safe}.crt"));
    let key_path = dir.join(format!("{safe}.key"));
    if std::fs::write(&cert_path, cert_pem).is_err() {
        return;
    }
    let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600));
    if std::fs::write(&key_path, key_pem).is_err() {
        let _ = std::fs::remove_file(&cert_path); // never leave a keyless cert pair
        return;
    }
    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    tracing::debug!(hostname = %hostname, dir = %dir.display(), "sentin8-tls: leaf pair persisted to cache");
}

/// One cached hostname found by [`scan_cache`]: the original hostname and
/// the resolved pair paths.
#[derive(Debug)]
pub struct CachedLeaf {
    /// The served SNI hostname the pair was minted for.
    pub hostname: String,
    /// Cert PEM path (`{hostname}.crt`).
    pub cert_path: PathBuf,
    /// Key PEM path (`{hostname}.key`).
    pub key_path: PathBuf,
}

/// Scan the cache dir for candidate pairs, newest-mtime first, capped at
/// [`tls_cert_cache_max`] hostnames, pruning expired pairs.
///
/// Expiry pruning happens HERE (not at add time) so a corrupt or expired
/// pair costs one stat+delete, never a broken serve. Returns the loadable
/// pairs in mtime order; the caller parses + registers them.
pub fn scan_cache() -> Vec<CachedLeaf> {
    let dir = tls_cert_cache_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(), // no cache dir yet - cold start
    };
    let max = tls_cert_cache_max();

    // (mtime, hostname, cert_path, key_path) - collect then sort newest first.
    let mut found: Vec<(std::time::SystemTime, String, PathBuf, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if ext != "crt" {
            continue;
        }
        let Some(hostname) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(uncache_file_stem)
        else {
            continue;
        };
        if hostname.is_empty() {
            continue;
        }
        let key_path = path.with_extension("key");
        if !key_path.is_file() {
            // Keyless cert - corrupt remnant, prune it.
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok((cert_pem, _key_pem)) = read_pair(&path, &key_path) else {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&key_path);
            continue;
        };
        match pem_first_not_after(&cert_pem) {
            Some(not_after) if not_after > chrono::Utc::now() => {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                found.push((mtime, hostname, path, key_path));
            }
            // Expired (or unparsable expiry - treat as expired, fail safe to
            // re-mint): prune the pair so the dir never accumulates dead
            // leaves.
            _ => {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(&key_path);
            }
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    found
        .into_iter()
        .take(max)
        .map(|(_, hostname, cert_path, key_path)| CachedLeaf {
            hostname,
            cert_path,
            key_path,
        })
        .collect()
}

/// Read one `{hostname}.crt` + `{hostname}.key` pair from disk.
fn read_pair(cert_path: &PathBuf, key_path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let cert_pem = std::fs::read(cert_path).map_err(|_| ())?;
    let key_pem = std::fs::read(key_path).map_err(|_| ())?;
    Ok((cert_pem, key_pem))
}

/// File-stem form of a hostname (`*` wildcards and `/` are unsafe in
/// filenames): a LEADING `*.` collapses to `_` (the dot goes with it -
/// `*.foo` → `_foo`), interior `*`/`/` → `_`, `..` → `__`.
fn cache_file_stem(hostname: &str) -> String {
    let without_wildcard_dot = hostname
        .strip_prefix("*.")
        .map(|rest| format!("_{rest}"))
        .unwrap_or_else(|| hostname.to_string());
    without_wildcard_dot
        .replace('*', "_")
        .replace('/', "_")
        .replace("..", "__")
}

/// Inverse of [`cache_file_stem`] for the load path: a leading `_` label
/// denormalizes back to `*.` (wildcard parents are stored per tls README
/// §4 as `*.{parent}`). Plain hostnames round-trip unchanged (a hostname
/// whose first label starts with `_` and is stored without a wildcard is
/// indistinguishable - wildcard parents are the only writers of
/// leading-underscore stems today, and a misread plain `_foo.bar` host
/// merely registers a wildcard entry that never matches an SNI).
fn uncache_file_stem(stem: &str) -> String {
    let parts: Vec<&str> = stem.split('.').collect();
    if let Some(first) = parts.first() {
        if let Some(rest) = first.strip_prefix('_') {
            if rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                let mut out = format!("*.{rest}");
                for p in &parts[1..] {
                    out.push('.');
                    out.push_str(p);
                }
                return out;
            }
        }
    }
    stem.to_string()
}

/// First leaf-certificate block's NotAfter (DER walk, same minimal
/// discipline as the m2m crate's expiry check - no x509-parser dep).
///
/// Returns `None` when the PEM carries no parsable validity end - callers
/// treat that as expired (fail safe to re-mint).
pub fn pem_first_not_after(cert_pem: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(cert_pem);
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            if inside {
                break; // first (leaf) block complete
            }
            inside = true;
            continue;
        }
        if line.starts_with("-----END CERTIFICATE-----") && inside {
            break;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    der_not_after(&der)
}

/// Walk the DER for the validity window's NotAfter (UTCTime `17` YYMMDDHHMMSSZ
/// or GeneralizedTime `18` YYYYMMDDHHMMSSZ - the two forms RFC 5280 permits;
/// Acme's local signing uses UTCTime).
fn der_not_after(der: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // Locate the SEQUENCE { SEQUENCE { INTEGER serial, SIGALG, Name, Name,
    // Validity { notBefore, notAfter } } } - the validity end is the SECOND
    // time inside the first Certificate SEQUENCE. Minimal scan: find the
    // first `17`/`18` time tag pair at the depth where Validity lives and
    // take the second occurrence.
    let mut times: Vec<(usize, u8, usize)> = Vec::new(); // (offset, tag, content_len)
    let mut i = 0usize;
    while i + 2 < der.len() {
        let tag = der[i];
        if tag == 0x17 || tag == 0x18 {
            // short-form length only (time strings are tiny)
            let len = der[i + 1] as usize;
            if len < 32 && i + 2 + len <= der.len() {
                times.push((i, tag, len));
            }
        }
        i += 1;
    }
    // The leaf's Validity holds exactly two consecutive times (notBefore,
    // notAfter). Take the second of the first adjacent pair.
    for w in times.windows(2) {
        let (a, b) = (w[0], w[1]);
        let adjacent = a.0 + 2 + a.2 == b.0;
        if adjacent {
            let body = &der[b.0 + 2..b.0 + 2 + b.2];
            return parse_asn1_time(b.1, body);
        }
    }
    times
        .first()
        .and_then(|t| parse_asn1_time(t.1, &der[t.0 + 2..t.0 + 2 + t.2]))
}

/// Parse a UTCTime (`17`) or GeneralizedTime (`18`) body.
fn parse_asn1_time(tag: u8, body: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(body).ok()?;
    let (year, tail): (i32, &str) = if tag == 0x18 {
        (s.get(0..4)?.parse().ok()?, &s[4..])
    } else {
        let yy: i32 = s.get(0..2)?.parse().ok()?;
        // RFC 5280 UTCTime: 00-49 → 20xx, 50-99 → 19xx
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
    };
    let mo: u32 = tail.get(0..2)?.parse().ok()?;
    let d: u32 = tail.get(2..4)?.parse().ok()?;
    let h: u32 = tail.get(4..6)?.parse().ok()?;
    let mi: u32 = tail.get(6..8)?.parse().ok()?;
    let se: u32 = tail.get(8..10)?.parse().ok()?;
    Some(
        chrono::NaiveDate::from_ymd_opt(year, mo, d)?
            .and_hms_opt(h, mi, se)?
            .and_utc(),
    )
}

#[cfg(test)]
mod tests {
    //! WARM-1 (README §6.5): the persisted leaf cache's load-or-mint
    //! contract - persist → scan → prune → cap - all against a temp dir
    //! (the cache dir is env-derived, so each test pins it).

    use super::*;
    use std::sync::Mutex;

    /// Serialize env mutation across the test binary (parallel tests would
    /// race on SENTIN8_SECRETS_DIR otherwise).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sentin8-tls-certcache-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn persist_then_scan_round_trips_hostname() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("roundtrip");
        std::env::set_var("SENTIN8_SECRETS_DIR", &dir);
        persist_leaf_pair("dash.ops.sys.local.sentin8.dev", b"cert", b"key");
        assert!(tls_cert_cache_dir()
            .join("dash.ops.sys.local.sentin8.dev.crt")
            .exists());
        assert!(tls_cert_cache_dir()
            .join("dash.ops.sys.local.sentin8.dev.key")
            .exists());
        // .crt without expiry metadata → scan prunes (fail safe to re-mint),
        // so the scan result is empty but the DIR survives the prune.
        let found = scan_cache();
        assert!(
            found.is_empty(),
            "unparsable pairs must be pruned, got {found:?}"
        );
        assert!(!tls_cert_cache_dir()
            .join("dash.ops.sys.local.sentin8.dev.crt")
            .exists());
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SENTIN8_SECRETS_DIR");
    }

    #[test]
    fn stem_mapping_round_trips_wildcard_and_plain() {
        assert_eq!(cache_file_stem("*.foo.example"), "_foo.example");
        assert_eq!(uncache_file_stem("_foo.example"), "*.foo.example");
        assert_eq!(cache_file_stem("a.b.c"), "a.b.c");
        assert_eq!(uncache_file_stem("a.b.c"), "a.b.c");
        // Path-traversal safety: '..' and '/' are neutralized.
        assert_eq!(cache_file_stem("../etc/passwd"), "___etc_passwd");
        // A plain host with a leading-underscore label survives as-is.
        assert_eq!(cache_file_stem("_plain.example"), "_plain.example");
        assert_eq!(uncache_file_stem("_plain.example"), "*.plain.example");
    }

    #[test]
    fn scan_missing_dir_is_cold_start() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("missing");
        std::env::set_var("SENTIN8_SECRETS_DIR", dir.join("nope"));
        assert!(scan_cache().is_empty());
        std::env::remove_var("SENTIN8_SECRETS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_max_env_is_honored() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("maxenv");
        std::env::set_var("SENTIN8_SECRETS_DIR", &dir);
        std::env::set_var("SENTIN8_TLS_CERT_CACHE_MAX", "1");
        assert_eq!(tls_cert_cache_max(), 1);
        std::env::set_var("SENTIN8_TLS_CERT_CACHE_MAX", "0");
        assert_eq!(
            tls_cert_cache_max(),
            DEFAULT_CACHE_MAX,
            "0/invalid → default"
        );
        std::env::remove_var("SENTIN8_TLS_CERT_CACHE_MAX");
        std::env::remove_var("SENTIN8_SECRETS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn not_after_parses_real_cert_pem() {
        // Self-signed cert generated at test time via rcgen (the crate's
        // own dep) - no fixture file needed.
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["warm-test.example".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        let na = pem_first_not_after(pem.as_bytes());
        assert!(na.is_some(), "real cert PEM must yield a NotAfter");
        assert!(na.unwrap() > chrono::Utc::now());
    }

    #[test]
    fn persist_keyless_cert_never_survives() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("keyless");
        std::env::set_var("SENTIN8_SECRETS_DIR", &dir);
        // Simulate a crash between the two writes: cert present, key absent.
        let d = tls_cert_cache_dir();
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("orphan.example.crt"), b"cert").unwrap();
        let found = scan_cache();
        assert!(found.is_empty(), "keyless pair must be pruned");
        assert!(!d.join("orphan.example.crt").exists());
        std::env::remove_var("SENTIN8_SECRETS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn der_walk_finds_adjacent_validity_pair() {
        // Hand-built DER fragment: UTCTime notBefore + notAfter adjacent.
        let mut der = vec![0x17u8, 13];
        der.extend_from_slice(b"260101000000Z"); // notBefore 2026-01-01
        der.push(0x17);
        der.push(13);
        der.extend_from_slice(b"260102000000Z"); // notAfter 2026-01-02
        let na = der_not_after(&der).expect("adjacent pair must parse");
        assert_eq!(na.format("%Y-%m-%d").to_string(), "2026-01-02");
        // GeneralizedTime form.
        let mut der = vec![0x18u8, 15];
        der.extend_from_slice(b"20360101000000Z");
        der.push(0x18);
        der.push(15);
        der.extend_from_slice(b"20370101000000Z");
        let na = der_not_after(&der).expect("generalized pair must parse");
        assert_eq!(na.format("%Y-%m-%d").to_string(), "2037-01-01");
    }

    #[test]
    fn der_walk_utctime_1950_1999_window() {
        let mut der = vec![0x17u8, 13];
        der.extend_from_slice(b"510101000000Z"); // 1951-01-01
        der.push(0x17);
        der.push(13);
        der.extend_from_slice(b"990102000000Z"); // 1999-01-02
        let na = der_not_after(&der).expect("pair must parse");
        assert_eq!(na.format("%Y-%m-%d").to_string(), "1999-01-02");
    }
}
