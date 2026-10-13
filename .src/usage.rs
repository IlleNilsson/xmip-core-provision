//! What a certificate was issued to authenticate, read from its extended
//! key usage: a source that cannot choose what an authority issues checks
//! it was given what its purpose needs.

use asn1::SEQUENCE;

use crate::der::{CLIENT_AUTH, EXT_KEY_USAGE};
use crate::{Purpose, Result};

/// Whether the certificate `der` serves `purpose`: server authentication
/// for both, and client authentication too between nodes. A certificate
/// with no extended key usage serves any.
///
/// # Errors
///
/// Where `der` is not a certificate.
pub fn serves(der: &[u8], purpose: Purpose) -> Result<bool> {
    if !purpose.client_authentication() {
        return Ok(true);
    }
    Ok(extended_key_usages(der)?.is_none_or(|usages| usages.iter().any(|u| u == CLIENT_AUTH)))
}

/// The extended key usages `der` names, or `None` where it names none.
fn extended_key_usages(der: &[u8]) -> Result<Option<Vec<Vec<u32>>>> {
    let (certificate, _) = asn1::expect(der, SEQUENCE)?;
    let (tbs, _) = asn1::expect(certificate, SEQUENCE)?;
    for (tag, contents) in asn1::read_all(tbs)? {
        if tag != asn1::context(3, true) {
            continue;
        }
        let (extensions, _) = asn1::expect(contents, SEQUENCE)?;
        for (_, extension) in asn1::read_all(extensions)? {
            let (id, rest) = asn1::expect(extension, asn1::OBJECT_IDENTIFIER)?;
            if asn1::read_object_identifier(id)? != EXT_KEY_USAGE {
                continue;
            }
            let rest = match asn1::read(rest)? {
                (asn1::BOOLEAN, _, after) => after,
                _ => rest,
            };
            let (value, _) = asn1::expect(rest, asn1::OCTET_STRING)?;
            let (usages, _) = asn1::expect(value, SEQUENCE)?;
            return asn1::read_all(usages)?
                .into_iter()
                .map(|(_, usage)| asn1::read_object_identifier(usage).map_err(Into::into))
                .collect::<Result<Vec<_>>>()
                .map(Some);
        }
    }
    Ok(None)
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
    }
}
