//! A certificate signing request (PKCS #10, RFC 2986): written by a node
//! that asks for a certificate — an ACME order is finalized with one (RFC
//! 8555 section 7.4) — or by a person's surface asking for an operator's
//! (ADR-0034, amendment 2026-10-15), and read by the authority that answers
//! it. What a request may ask is its purpose's rule, `Purpose::admit`.

use asn1::{INTEGER, SEQUENCE, tlv};

use crate::der::{
    BIT_STRING, EXT_KEY_USAGE, EXTENSION_REQUEST, SET, SUBJECT_ALT_NAME, alternative_names,
    bit_string, ecdsa_sha256, extension, name, oid, point_of, read_alternative_names, read_name,
    sequence,
};
use crate::{KeyPair, ProvisionError, Result};

/// What a request asks for, its signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    /// The subject's attributes, each its type and value.
    pub subject: Vec<(Vec<u32>, String)>,
    /// The DNS names asked for.
    pub names: Vec<String>,
    /// The key the certificate is to be for, `SubjectPublicKeyInfo` DER.
    pub public_key_info: Vec<u8>,
    /// Every extension asked for, its identifier and its value's DER.
    pub extensions: Vec<(Vec<u32>, Vec<u8>)>,
}

/// A request for `names`, signed by `key`, DER: what an ACME order is
/// finalized with, its subject the first name.
///
/// # Errors
///
/// Where `names` is empty or signing fails.
pub fn write(key: &KeyPair, names: &[String]) -> Result<Vec<u8>> {
    let first = names
        .first()
        .ok_or_else(|| ProvisionError::new("a request names at least one DNS name"))?;
    let information = information(first, &key.public_key_info(), names, &[]);
    Ok(assemble(&information, &key.sign(&information)?))
}

/// What a request signs, `CertificationRequestInfo` DER: `subject` as one
/// common name, the key `public_key_info` holds, and an extension request
/// for `names` and `usages`, each left out where empty.
///
/// Apart from [`assemble`] so a key that never leaves its keeper — a phone's
/// keystore — signs these bytes itself.
#[must_use]
pub fn information(
    subject: &str,
    public_key_info: &[u8],
    names: &[String],
    usages: &[&[u32]],
) -> Vec<u8> {
    let mut requested = Vec::new();
    if !names.is_empty() {
        requested.extend(extension(
            SUBJECT_ALT_NAME,
            false,
            &alternative_names(names),
        ));
    }
    if !usages.is_empty() {
        let usages: Vec<u8> = usages.iter().flat_map(|usage| oid(usage)).collect();
        requested.extend(extension(EXT_KEY_USAGE, false, &tlv(SEQUENCE, &usages)));
    }
    let attribute = sequence(&[
        &oid(EXTENSION_REQUEST),
        &tlv(SET, &tlv(SEQUENCE, &requested)),
    ]);
    sequence(&[
        &tlv(INTEGER, &[0]),
        &name(subject),
        public_key_info,
        &tlv(asn1::context(0, true), &attribute),
    ])
}

/// The request, DER: `information` and its ECDSA-with-SHA-256 `signature`,
/// DER as X.509 carries one.
#[must_use]
pub fn assemble(information: &[u8], signature: &[u8]) -> Vec<u8> {
    sequence(&[information, &ecdsa_sha256(), &bit_string(signature)])
}

/// What `der` asks for, once its signature is verified under the key it
/// carries.
///
/// # Errors
///
/// Where it is not a request, its key is not P-256, or its signature does
/// not verify.
pub fn read(der: &[u8]) -> Result<Requested> {
    let (outer, _) = asn1::expect(der, SEQUENCE)?;
    let (_, info_contents, after) = asn1::read(outer)?;
    let info = &outer[..outer.len() - after.len()];
    let (algorithm, rest) = asn1::expect(after, SEQUENCE)?;
    if tlv(SEQUENCE, algorithm) != ecdsa_sha256() {
        return Err(ProvisionError::new(
            "the request is not signed with ECDSA and SHA-256",
        ));
    }
    let (bits, _) = asn1::expect(rest, BIT_STRING)?;

    let (_, rest) = asn1::expect(info_contents, INTEGER)?;
    let (_, _, after_subject) = asn1::read(rest)?;
    let subject = read_name(&rest[..rest.len() - after_subject.len()])?;
    let rest = after_subject;
    let (_, _, attributes) = asn1::read(rest)?;
    let public_key_info = rest[..rest.len() - attributes.len()].to_vec();
    let point = point_of(&public_key_info)?;
    let signed = bits
        .split_first()
        .filter(|(unused, _)| **unused == 0)
        .is_some_and(|(_, signature)| crate::verify(&point, info, signature));
    if !signed {
        return Err(ProvisionError::new(
            "the request's signature does not verify under its own key",
        ));
    }

    let extensions = requested_extensions(attributes)?;
    let names = match extensions.iter().find(|(id, _)| id == SUBJECT_ALT_NAME) {
        Some((_, value)) => read_alternative_names(value)?,
        None => Vec::new(),
    };
    Ok(Requested {
        subject,
        names,
        public_key_info,
        extensions,
    })
}

/// Every extension an extension request among `attributes` asks for.
fn requested_extensions(attributes: &[u8]) -> Result<Vec<(Vec<u32>, Vec<u8>)>> {
    let mut found = Vec::new();
    if attributes.is_empty() {
        return Ok(found);
    }
    let (attributes, _) = asn1::expect(attributes, asn1::context(0, true))?;
    for (_, attribute) in asn1::read_all(attributes)? {
        let (kind, rest) = asn1::expect(attribute, asn1::OBJECT_IDENTIFIER)?;
        if asn1::read_object_identifier(kind)? != EXTENSION_REQUEST {
            continue;
        }
        let (values, _) = asn1::expect(rest, SET)?;
        let (extensions, _) = asn1::expect(values, SEQUENCE)?;
        for (_, one) in asn1::read_all(extensions)? {
            let (id, rest) = asn1::expect(one, asn1::OBJECT_IDENTIFIER)?;
            let rest = match asn1::read(rest)? {
                (asn1::BOOLEAN, _, after) => after,
                _ => rest,
            };
            let (value, _) = asn1::expect(rest, asn1::OCTET_STRING)?;
            found.push((asn1::read_object_identifier(id)?, value.to_vec()));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{CLIENT_AUTH, COMMON_NAME};

    #[test]
    fn a_request_is_read_back_with_its_names_and_key() {
        let key = KeyPair::generate().expect("a key");
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        let der = write(&key, &names).expect("written");
        let read = read(&der).expect("read");
        assert_eq!(read.names, names);
        assert_eq!(read.public_key_info, key.public_key_info());
        assert_eq!(
            read.subject,
            [(COMMON_NAME.to_vec(), "a.example".to_string())]
        );
    }

    #[test]
    fn a_request_whose_signature_was_tampered_with_is_refused() {
        let key = KeyPair::generate().expect("a key");
        let mut der = write(&key, &["a.example".to_string()]).expect("written");
        let last = der.len() - 1;
        der[last] ^= 0x01;
        assert!(read(&der).is_err());
        assert!(write(&key, &[]).is_err());
    }

    #[test]
    fn information_signed_elsewhere_is_assembled_into_a_request_that_reads() {
        let key = KeyPair::generate().expect("a key");
        let information = information(
            "alice@example.org",
            &key.public_key_info(),
            &[],
            &[CLIENT_AUTH],
        );
        let der = assemble(&information, &key.sign(&information).expect("signed"));
        let read = read(&der).expect("read");
        assert_eq!(read.names, Vec::<String>::new());
        assert_eq!(read.extensions.len(), 1);
        assert_eq!(read.extensions[0].0, EXT_KEY_USAGE);
    }
}
