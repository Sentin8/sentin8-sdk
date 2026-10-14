// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Input validation — same charset rules as the control-plane bus's
//! `stream_family` validator: `family`/`group` are untrusted input
//! interpolated into Valkey keys, so they are validated before any key
//! is built.

use crate::error::MemBusError;

/// `^[a-zA-Z0-9._-]{1,64}$` plus reserved-prefix rejection.
fn validate_ident(kind: &'static str, value: &str) -> Result<(), MemBusError> {
    let fail = |reason: String| Err(MemBusError::InvalidFamily(format!("{kind} {reason}")));
    if value.is_empty() {
        return fail("must not be empty".into());
    }
    if value.len() > 64 {
        return fail("must be at most 64 characters".into());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return fail("only [a-zA-Z0-9._-] allowed".into());
    }
    // Reserved control-plane prefixes must never collide with the
    // fast-plane namespaces.
    for reserved in ["dlq", "delayed", "jti"] {
        if value == reserved || value.starts_with(&format!("{reserved}.")) {
            return fail(format!("reserved prefix {reserved:?}"));
        }
    }
    Ok(())
}

/// Validate a stream/channel family before key interpolation.
pub fn validate_family(family: &str) -> Result<(), MemBusError> {
    validate_ident("family", family)
}

/// Validate a consumer group name (same charset rules).
pub fn validate_group(group: &str) -> Result<(), MemBusError> {
    validate_ident("group", group)
        .map_err(|_| MemBusError::InvalidGroup(format!("invalid consumer group {group:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MemBusError;

    #[test]
    fn accepts_valid_families() {
        for ok in [
            "me.trade",
            "me.exec",
            "md.book",
            "rfq.quote",
            "risk.exposure-1",
            "a",
            "abcDEF012._-",
        ] {
            assert!(validate_family(ok).is_ok(), "{ok} should pass");
            assert!(validate_group(ok).is_ok(), "{ok} group should pass");
        }
    }

    #[test]
    fn rejects_invalid_families() {
        for bad in [
            "",
            "me trade",
            "me:trade",      // colon is a key separator
            "me*",           // glob char
            "me?",           // glob char
            "me[1]",         // glob chars
            "me\\x",         // backslash
            "dlq",           // reserved
            "delayed",       // reserved
            "jti",           // reserved
            "dlq.sub",       // reserved prefix family
            &"x".repeat(65), // too long
            "mé",            // non-ascii
        ] {
            assert!(validate_family(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn group_error_is_group_variant() {
        let err = validate_group("bad group").unwrap_err();
        assert!(matches!(err, MemBusError::InvalidGroup(_)));
    }
}
