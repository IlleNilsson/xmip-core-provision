//! What a certificate was issued to authenticate, read from its extended
//! key usage: a source that cannot choose what an authority issues checks
//! it was given what its purpose needs.

use tls::certificate::Certificate;

use crate::{Purpose, Result};

/// Whether the certificate `der` serves `purpose`: it names every usage the
/// purpose's certificate carries (`Purpose::extended_key_usages`) — server
/// authentication for what a Party reaches, client authentication for an
/// operator, both between nodes. A certificate with no extended key usage
/// serves any.
///
/// # Errors
///
/// Where `der` is not a certificate.
pub fn serves(der: &[u8], purpose: Purpose) -> Result<bool> {
    serves_read(&Certificate::read(der)?, purpose)
}

/// As [`serves`], of a certificate already read.
///
/// # Errors
///
/// Where its extended key usage does not read.
pub fn serves_read(read: &Certificate, purpose: Purpose) -> Result<bool> {
    Ok(read.extended_key_usages()?.is_none_or(|usages| {
        purpose
            .extended_key_usages()
            .into_iter()
            .all(|needed| usages.iter().any(|usage| usage == needed))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Draft, KeyPair, Usage};

    fn leaf(purpose: Purpose) -> Vec<u8> {
        let key = KeyPair::generate().expect("a key");
        Draft {
            subject: "x.example",
            names: &["x.example".to_string()],
            public_key_info: &key.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_800_003_600,
            usage: Usage::Leaf(purpose),
        }
        .sign("x.example", &key)
        .expect("signed")
    }

    #[test]
    fn a_server_only_certificate_serves_what_parties_reach_and_not_a_node() {
        let server = leaf(Purpose::Receive);
        assert!(serves(&server, Purpose::Receive).expect("read"));
        assert!(!serves(&server, Purpose::Node).expect("read"));
        assert!(serves(&leaf(Purpose::Node), Purpose::Node).expect("read"));
        let operator = leaf(Purpose::Operator);
        assert!(serves(&operator, Purpose::Operator).expect("read"));
        assert!(!serves(&operator, Purpose::Receive).expect("read"));
        assert!(!serves(&operator, Purpose::Node).expect("read"));
        assert!(!serves(&server, Purpose::Operator).expect("read"));
    }
}
