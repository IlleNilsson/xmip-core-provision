//! A certificate written and signed (RFC 5280): what an authority issues
//! and what a self-signed node presents.
//!
//! Version 3, a random serial, ECDSA with SHA-256, one common name, and the
//! extensions a TLS verifier reads: an authority is a CA that signs
//! certificates; a leaf is not, signs handshakes, and names its purpose's
//! extended key usages and its DNS names. Every certificate names its own
//! key and a leaf its issuer's (key identifiers), which a verifier builds a
//! chain by and ACME Renewal Information names a certificate by (RFC 9773
//! section 4.1); a leaf of an authority that publishes says where its
//! revocation list and the authority's certificate are fetched from.

use asn1::{INTEGER, OCTET_STRING, tlv};

use crate::der::{
    AUTHORITY_INFORMATION_ACCESS, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, CA_ISSUERS,
    CRL_DISTRIBUTION_POINTS, EXT_KEY_USAGE, KEY_USAGE, SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER,
    alternative_names, ecdsa_sha256, extension, key_identifier, name, oid, sequence, time,
};
use crate::{KeyPair, ProvisionError, Purpose, Result};

/// Where, beneath the address an authority publishes at, its revocation
/// list is fetched: DER, `application/pkix-crl` (RFC 5280 section 4.2.1.13).
pub const CRL_PATH: &str = "/crl";

/// Where, beneath it, its certificate is fetched: DER,
/// `application/pkix-cert` (RFC 5280 section 4.2.2.1).
pub const AUTHORITY_PATH: &str = "/authority.cer";

/// The key usage of an authority: `keyCertSign` and `cRLSign`, seven bits,
/// one unused.
const AUTHORITY_USAGE: [u8; 4] = [0x03, 0x02, 0x01, 0x06];
/// The key usage of a leaf: `digitalSignature`, one bit, seven unused.
const LEAF_USAGE: [u8; 4] = [0x03, 0x02, 0x07, 0x80];

/// What a certificate may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// Sign certificates: a certificate authority.
    Authority,
    /// Authenticate a TLS end for `Purpose`.
    Leaf(Purpose),
}

/// A certificate before it is signed.
#[derive(Clone, Copy, Debug)]
pub struct Draft<'a> {
    /// The common name of its subject.
    pub subject: &'a str,
    /// Its DNS names, the ones a TLS verifier checks a host against.
    pub names: &'a [String],
    /// Its public key, `SubjectPublicKeyInfo` DER.
    pub public_key_info: &'a [u8],
    /// From when it is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
    /// What it may do.
    pub usage: Usage,
}

impl Draft<'_> {
    /// The certificate, DER, signed by `issuer_key` in the name of
    /// `issuer`; a self-signed certificate names its own subject.
    ///
    /// # Errors
    ///
    /// Where it ends before it starts, a time is before 1970, or signing
    /// fails.
    pub fn sign(&self, issuer: &str, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        self.sign_under(&name(issuer), issuer_key)
    }

    /// The certificate, DER, signed by `issuer_key` in the name `issuer`
    /// holds, a `Name` whole: as an authority's own certificate names it.
    ///
    /// # Errors
    ///
    /// As [`Draft::sign`].
    pub fn sign_under(&self, issuer: &[u8], issuer_key: &KeyPair) -> Result<Vec<u8>> {
        self.sign_published(issuer, issuer_key, None)
    }

    /// As [`Draft::sign_under`], by an authority that publishes at
    /// `published` — `http://host:port`, plain HTTP, since a verifier
    /// fetches a revocation list before it trusts any TLS — where it is
    /// given: a leaf then names `<published>/crl` its distribution point
    /// and `<published>/authority.cer` its issuer's certificate.
    ///
    /// # Errors
    ///
    /// As [`Draft::sign`].
    pub fn sign_published(
        &self,
        issuer: &[u8],
        issuer_key: &KeyPair,
        published: Option<&str>,
    ) -> Result<Vec<u8>> {
        if self.not_after <= self.not_before {
            return Err(ProvisionError::new(
                "a certificate must end after it starts",
            ));
        }
        let validity = sequence(&[&time(self.not_before)?, &time(self.not_after)?]);
        let written = self.extensions(&issuer_key.public_key_info(), published)?;
        let extensions = tlv(asn1::context(3, true), &sequence(&[&written]));
        let tbs = sequence(&[
            &tlv(asn1::context(0, true), &tlv(INTEGER, &[2])),
            &tlv(INTEGER, &serial()),
            &ecdsa_sha256(),
            issuer,
            &validity,
            &name(self.subject),
            self.public_key_info,
            &extensions,
        ]);
        let signature = issuer_key.sign(&tbs)?;
        Ok(sequence(&[
            &tbs,
            &ecdsa_sha256(),
            &crate::der::bit_string(&signature),
        ]))
    }

    /// The extensions, in one piece.
    fn extensions(&self, issuer_key: &[u8], published: Option<&str>) -> Result<Vec<u8>> {
        let own = tlv(OCTET_STRING, &key_identifier(self.public_key_info)?);
        let mut written = extension(SUBJECT_KEY_IDENTIFIER, false, &own);
        match self.usage {
            Usage::Authority => {
                let constraints = sequence(&[&tlv(asn1::BOOLEAN, &[0xff])]);
                written.extend(extension(BASIC_CONSTRAINTS, true, &constraints));
                written.extend(extension(KEY_USAGE, true, &AUTHORITY_USAGE));
            }
            Usage::Leaf(purpose) => {
                let usages: Vec<u8> = purpose
                    .extended_key_usages()
                    .into_iter()
                    .flat_map(oid)
                    .collect();
                let issuer = tlv(asn1::context(0, false), &key_identifier(issuer_key)?);
                written.extend(extension(
                    AUTHORITY_KEY_IDENTIFIER,
                    false,
                    &sequence(&[&issuer]),
                ));
                written.extend(extension(BASIC_CONSTRAINTS, true, &sequence(&[])));
                written.extend(extension(KEY_USAGE, true, &LEAF_USAGE));
                written.extend(extension(EXT_KEY_USAGE, false, &sequence(&[&usages])));
                // A person's certificate names no host.
                if !self.names.is_empty() {
                    written.extend(extension(
                        SUBJECT_ALT_NAME,
                        false,
                        &alternative_names(self.names),
                    ));
                }
                if let Some(base) = published {
                    written.extend(publication(base.trim_end_matches('/')));
                }
            }
        }
        Ok(written)
    }
}

/// Where a leaf's authority publishes: its revocation list as the one
/// distribution point (RFC 5280 section 4.2.1.13) and its certificate as
/// the issuer's (section 4.2.2.1), each a URI.
fn publication(base: &str) -> Vec<u8> {
    let uri = |path: &str| tlv(asn1::context(6, false), format!("{base}{path}").as_bytes());
    let full_name = tlv(asn1::context(0, true), &uri(CRL_PATH));
    let point = sequence(&[&tlv(asn1::context(0, true), &full_name)]);
    let issuers = sequence(&[&oid(CA_ISSUERS), &uri(AUTHORITY_PATH)]);
    [
        extension(CRL_DISTRIBUTION_POINTS, false, &sequence(&[&point])),
        extension(AUTHORITY_INFORMATION_ACCESS, false, &sequence(&[&issuers])),
    ]
    .concat()
}

/// Sixteen random bytes, positive and with no leading zero, as RFC 5280
/// section 4.1.2.2 asks: unique to its issuer by chance alone.
fn serial() -> [u8; 16] {
    let mut bytes = codec::random::array::<16>();
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_certificate_carries_its_validity_and_verifies_under_its_issuer() {
        let authority = KeyPair::generate().expect("a key");
        let leaf = KeyPair::generate().expect("a key");
        let names = vec!["one.example".to_string()];
        let draft = Draft {
            subject: "one.example",
            names: &names,
            public_key_info: &leaf.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_800_086_400,
            usage: Usage::Leaf(Purpose::Node),
        };
        let der = draft.sign("authority", &authority).expect("signed");

        assert_eq!(
            crate::validity(&der).expect("validity"),
            (1_800_000_000, 1_800_086_400)
        );
        let (outer, _) = asn1::expect(&der, asn1::SEQUENCE).expect("certificate");
        let (_, tbs_contents, after) = asn1::read(outer).expect("tbs");
        let tbs = &outer[..outer.len() - after.len()];
        assert_ne!(tbs_contents, []);
        let (_, signature) = {
            let (algorithm, rest) = asn1::expect(after, asn1::SEQUENCE).expect("algorithm");
            (
                algorithm,
                asn1::expect(rest, crate::der::BIT_STRING).expect("bits").0,
            )
        };
        assert!(crate::verify(authority.point(), tbs, &signature[1..]));
    }

    #[test]
    fn a_certificate_that_ends_before_it_starts_is_refused() {
        let key = KeyPair::generate().expect("a key");
        let draft = Draft {
            subject: "x",
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: 10,
            not_after: 10,
            usage: Usage::Authority,
        };
        assert!(draft.sign("x", &key).is_err());
    }
}
