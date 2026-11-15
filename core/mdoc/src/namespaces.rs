//! The standard mdoc namespaces and doctypes the suite validates
//! (ISO 18013-5 §7.2/§13.4, ISO 23220-4, the EUDI PID rulebook).

/// The mDL doctype.
pub const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
/// The mDL namespace.
pub const MDL_NAMESPACE: &str = "org.iso.18013.5.1";
/// The photoID doctype.
pub const PHOTOID_DOCTYPE: &str = "org.iso.23220.photoid.1";
/// The photoID namespace.
pub const PHOTOID_NAMESPACE: &str = "org.iso.23220.1";
/// The EUDI PID doctype (and namespace - they match).
pub const EUDI_PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";

/// The mDL mandatory element set (ISO 18013-5 §7.2.1 - the suite's
/// EnsureMdocMdlMandatoryDataElementsPresent).
pub const MDL_MANDATORY_ELEMENTS: &[&str] = &[
    "family_name",
    "given_name",
    "birth_date",
    "issue_date",
    "expiry_date",
    "issuing_country",
    "issuing_authority",
    "document_number",
    "portrait",
    "driving_privileges",
    "un_distinguishing_sign",
];

/// The photoID mandatory element set (ISO 23220-4).
pub const PHOTOID_MANDATORY_ELEMENTS: &[&str] = &[
    "family_name",
    "given_name",
    "birth_date",
    "portrait",
    "issuing_country",
    "issuing_authority",
];

/// The EUDI PID mandatory element set (the PID rulebook 2.2).
pub const EUDI_PID_MANDATORY_ELEMENTS: &[&str] = &[
    "family_name",
    "given_name",
    "birth_date",
    "age_over_18",
    "issuing_country",
    "issuing_authority",
];

/// The mandatory elements for a doctype, if it is a known one.
pub fn mandatory_elements(doc_type: &str) -> Option<&'static [&'static str]> {
    match doc_type {
        MDL_DOCTYPE => Some(MDL_MANDATORY_ELEMENTS),
        PHOTOID_DOCTYPE => Some(PHOTOID_MANDATORY_ELEMENTS),
        EUDI_PID_DOCTYPE => Some(EUDI_PID_MANDATORY_ELEMENTS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_sets_resolve() {
        assert!(mandatory_elements(MDL_DOCTYPE).unwrap().contains(&"portrait"));
        assert!(mandatory_elements(EUDI_PID_DOCTYPE).is_some());
        assert!(mandatory_elements("unknown").is_none());
    }
}
