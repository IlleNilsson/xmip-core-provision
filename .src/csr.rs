//! A certificate signing request (PKCS #10, RFC 2986): written by a node
//! that asks for a certificate — an ACME order is finalized with one (RFC
//! 8555 section 7.4) — and read by the authority that answers it.

use asn1::{INTEGER, SEQUENCE, tlv};

use crate::der::{
    BIT_STRING, EXTENSION_REQUEST, SET, SUBJECT_ALT_NAME, alternative_names, bit_string,
    ecdsa_sha256, extension, name, oid, point_of, read_alternative_names, sequence,
};
use crate::{KeyPair, ProvisionError, Result};

/// What a request asks for, its signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    /// The DNS names asked for.
    pub names: Vec<String>,
    /// The key the certificate is to be for, `SubjectPublicKeyInfo` DER.
    pub public_key_info: Vec<u8>,
}

/// A request for `names`, signed by `key`, DER.
///
/// # Errors
///
/// Where `names` is empty or signing fails.
pub fn write(key: &KeyPair, names: &[String]) -> Result<Vec<u8>> {
    let first = names
        .first()
        .ok_or_else(|| ProvisionError::new("a request names at least one DNS name"))?;
    let requested = sequence(&[&extension(
        SUBJECT_ALT_NAME,
        false,
        &alternative_names(names),
    )]);
    let attribute = sequence(&[&oid(EXTENSION_REQUEST), &tlv(SET, &requested)]);
    let info = sequence(&[
        &tlv(INTEGER, &[0]),
        &name(first),
        &key.public_key_info(),
        &tlv(asn1::context(0, true), &attribute),
    ]);
    let signature = key.sign(&info)?;
    Ok(sequence(&[&info, &ecdsa_sha256(), &bit_string(&signature)]))
}

/// What `der` asks for, once its signature is verified under the key it
/// carries.
///
/// # Errors
///
/// Where it is not a request, its key is not P-256, its signature does not
/// verify, or it names no DNS name.
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
    let (_, rest) = asn1::expect(rest, SEQUENCE)?;
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

    let names = requested_names(attributes)?;
    if names.is_empty() {
        return Err(ProvisionError::new("the request names no DNS name"));
    }
    Ok(Requested {
        names,
        public_key_info,
    })
}

/// The DNS names an extension request among `attributes` asks for.
fn requested_names(attributes: &[u8]) -> Result<Vec<String>> {
    if attributes.is_empty() {
        return Ok(Vec::new());
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
            if asn1::read_object_identifier(id)? != SUBJECT_ALT_NAME {
                continue;
            }
            let rest = match asn1::read(rest)? {
                (asn1::BOOLEAN, _, after) => after,
                _ => rest,
            };
            let (value, _) = asn1::expect(rest, asn1::OCTET_STRING)?;
            return read_alternative_names(value);
        }
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_read_back_with_its_names_and_key() {
        let key = KeyPair::generate().expect("a key");
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        let der = write(&key, &names).expect("written");
        let read = read(&der).expect("read");
        assert_eq!(read.names, names);
        assert_eq!(read.public_key_info, key.public_key_info());
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
}
