//! A certificate revocation list (RFC 5280 section 5): what the cluster's
//! authority says it no longer stands behind, signed by it, written whole
//! and read back. Revocation is published as a list alone — no OCSP
//! responder — as Let's Encrypt has published it since it ended OCSP on
//! 2025-08-06 (<https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life/>).

use asn1::{ENUMERATED, INTEGER, OCTET_STRING, SEQUENCE, tlv};

use crate::der::{
    AUTHORITY_KEY_IDENTIFIER, BIT_STRING, CRL_NUMBER, CRL_REASON, ecdsa_sha256, extension,
    key_identifier, read_time, sequence, time,
};
use crate::parsed::Parsed;
use crate::{KeyPair, ProvisionError, Result};

/// Why a certificate was revoked: the reasons RFC 5280 section 5.3.1 gives
/// that a leaf of the cluster's authority can have, each by its word there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No reason given; the list carries none.
    Unspecified,
    /// Its key is known or suspected to be in other hands.
    KeyCompromise,
    /// The subject's name or relation changed.
    AffiliationChanged,
    /// Another certificate took its place.
    Superseded,
    /// What it was issued for is no longer run.
    CessationOfOperation,
    /// What it was allowed is withdrawn.
    PrivilegeWithdrawn,
}

impl Reason {
    /// Every reason, in code order.
    pub const ALL: [Self; 6] = [
        Self::Unspecified,
        Self::KeyCompromise,
        Self::AffiliationChanged,
        Self::Superseded,
        Self::CessationOfOperation,
        Self::PrivilegeWithdrawn,
    ];

    /// Its code, `CRLReason`, as a list and an ACME `revokeCert` carry it.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::PrivilegeWithdrawn => 9,
        }
    }

    /// Its word, as RFC 5280 names it and an operator types it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
        }
    }

    /// The reason `word` names, its case ignored.
    ///
    /// # Errors
    ///
    /// Where it names none, listing the words.
    pub fn named(word: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.word().eq_ignore_ascii_case(word.trim()))
            .ok_or_else(|| {
                let words: Vec<&str> = Self::ALL.iter().map(|reason| reason.word()).collect();
                ProvisionError::new(format!(
                    "{word:?} is no reason a certificate is revoked for; one of {}",
                    words.join(", ")
                ))
            })
    }

    /// The reason `code` is.
    ///
    /// # Errors
    ///
    /// Where it is none this authority revokes for.
    pub fn of_code(code: u64) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|reason| u64::from(reason.code()) == code)
            .ok_or_else(|| ProvisionError::new(format!("{code} is no reason this authority takes")))
    }
}

/// One certificate the list names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    /// Its serial number's contents, as its certificate writes them.
    pub serial: Vec<u8>,
    /// When it was revoked, seconds since the epoch.
    pub at: i64,
    /// Why.
    pub reason: Reason,
}

/// A list read back, its signature not yet checked ([`Listed::signed_by`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Who signed it, `Name` DER whole.
    pub issuer: Vec<u8>,
    /// When it was made.
    pub this_update: i64,
    /// When the next one is made at the latest.
    pub next_update: i64,
    /// Its number, rising with every list (RFC 5280 section 5.2.3).
    pub number: u64,
    /// Every certificate it names.
    pub revoked: Vec<Revoked>,
    signed: Vec<u8>,
    signature: Vec<u8>,
}

impl Listed {
    /// Whether `authority`'s certificate signed it.
    ///
    /// # Errors
    ///
    /// Where the authority's key is not P-256.
    pub fn signed_by(&self, authority: &Parsed) -> Result<bool> {
        let point = crate::der::point_of(&authority.public_key_info)?;
        Ok(
            self.issuer == authority.subject
                && crate::verify(&point, &self.signed, &self.signature),
        )
    }

    /// Whether it names the certificate whose serial is `serial`.
    #[must_use]
    pub fn names(&self, serial: &[u8]) -> Option<&Revoked> {
        self.revoked.iter().find(|one| one.serial == serial)
    }
}

/// The list, DER, signed by `key` in the name `issuer` holds, numbered
/// `number`, made `this_update` and next made by `next_update`.
///
/// # Errors
///
/// Where a time is before 1970 or signing fails.
pub fn write(
    issuer: &[u8],
    key: &KeyPair,
    revoked: &[Revoked],
    number: u64,
    (this_update, next_update): (i64, i64),
) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    for one in revoked {
        let mut entry = vec![tlv(INTEGER, &one.serial), time(one.at)?];
        if one.reason != Reason::Unspecified {
            let code = tlv(ENUMERATED, &[one.reason.code()]);
            entry.push(sequence(&[&extension(CRL_REASON, false, &code)]));
        }
        let parts: Vec<&[u8]> = entry.iter().map(Vec::as_slice).collect();
        entries.extend(sequence(&parts));
    }
    let authority = tlv(
        asn1::context(0, false),
        &key_identifier(&key.public_key_info())?,
    );
    let extensions = [
        extension(AUTHORITY_KEY_IDENTIFIER, false, &sequence(&[&authority])),
        extension(CRL_NUMBER, false, &tlv(INTEGER, &asn1::unsigned(number))),
    ]
    .concat();
    let mut parts = vec![
        tlv(INTEGER, &[1]),
        ecdsa_sha256(),
        issuer.to_vec(),
        time(this_update)?,
        time(next_update)?,
    ];
    if !entries.is_empty() {
        parts.push(tlv(SEQUENCE, &entries));
    }
    parts.push(tlv(asn1::context(0, true), &sequence(&[&extensions])));
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let tbs = sequence(&parts);
    let signature = key.sign(&tbs)?;
    Ok(sequence(&[
        &tbs,
        &ecdsa_sha256(),
        &crate::der::bit_string(&signature),
    ]))
}

/// The list `der` is.
///
/// # Errors
///
/// Where it is not a revocation list, in words.
pub fn read(der: &[u8]) -> Result<Listed> {
    let (list, _) = asn1::expect(der, SEQUENCE)?;
    let (_, contents, after) = asn1::read(list)?;
    let signed = list[..list.len() - after.len()].to_vec();
    let (_, rest) = asn1::expect(after, SEQUENCE)?;
    let (bits, _) = asn1::expect(rest, BIT_STRING)?;
    let signature = bits.get(1..).unwrap_or_default().to_vec();

    let (_, rest) = asn1::expect(contents, INTEGER)?;
    let rest = asn1::read(rest)?.2;
    let (_, _, after_issuer) = asn1::read(rest)?;
    let issuer = rest[..rest.len() - after_issuer.len()].to_vec();
    let (this_tag, this, rest) = asn1::read(after_issuer)?;
    let (next_tag, next, mut rest) = asn1::read(rest)?;
    let mut listed = Listed {
        issuer,
        this_update: read_time(this_tag, this)?,
        next_update: read_time(next_tag, next)?,
        number: 0,
        revoked: Vec::new(),
        signed,
        signature,
    };
    while !rest.is_empty() {
        let (tag, inner, after) = asn1::read(rest)?;
        if tag == SEQUENCE {
            for (_, entry) in asn1::read_all(inner)? {
                listed.revoked.push(read_entry(entry)?);
            }
        } else if tag == asn1::context(0, true) {
            listed.number = read_number(inner)?;
        }
        rest = after;
    }
    Ok(listed)
}

/// One entry: its serial, its date and its reason where it gives one.
fn read_entry(entry: &[u8]) -> Result<Revoked> {
    let (serial, rest) = asn1::expect(entry, INTEGER)?;
    let (tag, at, rest) = asn1::read(rest)?;
    let mut reason = Reason::Unspecified;
    if !rest.is_empty() {
        let (extensions, _) = asn1::expect(rest, SEQUENCE)?;
        for (_, one) in asn1::read_all(extensions)? {
            let (id, value) = asn1::expect(one, asn1::OBJECT_IDENTIFIER)?;
            if asn1::read_object_identifier(id)? == CRL_REASON {
                let (value, _) = asn1::expect(value, OCTET_STRING)?;
                let (code, _) = asn1::expect(value, ENUMERATED)?;
                reason = Reason::of_code(asn1::read_unsigned(code)?)?;
            }
        }
    }
    Ok(Revoked {
        serial: serial.to_vec(),
        at: read_time(tag, at)?,
        reason,
    })
}

/// The list's number, from its extensions.
fn read_number(explicit: &[u8]) -> Result<u64> {
    let (extensions, _) = asn1::expect(explicit, SEQUENCE)?;
    for (_, one) in asn1::read_all(extensions)? {
        let (id, value) = asn1::expect(one, asn1::OBJECT_IDENTIFIER)?;
        if asn1::read_object_identifier(id)? == CRL_NUMBER {
            let (value, _) = asn1::expect(value, OCTET_STRING)?;
            let (number, _) = asn1::expect(value, INTEGER)?;
            return Ok(asn1::read_unsigned(number)?);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::name;
    use crate::{Draft, Usage};

    #[test]
    fn a_list_is_read_back_whole_and_verifies_under_its_authority_alone() {
        let key = KeyPair::generate().expect("a key");
        let authority = Draft {
            subject: "list authority",
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_900_000_000,
            usage: Usage::Authority,
        }
        .sign("list authority", &key)
        .expect("signed");
        let revoked = [
            Revoked {
                serial: vec![0x41, 0x02],
                at: 1_800_000_100,
                reason: Reason::KeyCompromise,
            },
            Revoked {
                serial: vec![0x43],
                at: 1_800_000_200,
                reason: Reason::Unspecified,
            },
        ];
        let window = (1_800_000_300, 1_800_604_800);
        let der = write(&name("list authority"), &key, &revoked, 7, window).expect("written");
        let listed = read(&der).expect("read");
        assert_eq!(listed.revoked, revoked);
        assert_eq!((listed.number, listed.this_update), (7, 1_800_000_300));
        assert_eq!(listed.next_update, 1_800_604_800);
        let parsed = Parsed::read(&authority).expect("the authority");
        assert!(listed.signed_by(&parsed).expect("checked"));
        assert!(listed.names(&[0x43]).is_some());
        assert!(listed.names(&[0x44]).is_none());

        let other = KeyPair::generate().expect("a key");
        let forged = write(&name("list authority"), &other, &revoked, 8, window).expect("forged");
        assert!(
            !read(&forged)
                .expect("read")
                .signed_by(&parsed)
                .expect("checked")
        );
        let empty = write(&name("list authority"), &key, &[], 9, window).expect("empty");
        assert_eq!(read(&empty).expect("read").revoked, []);
    }

    #[test]
    fn a_reason_is_named_by_its_word_and_its_code() {
        for reason in Reason::ALL {
            assert_eq!(Reason::named(reason.word()).expect("named"), reason);
            assert_eq!(
                Reason::of_code(reason.code().into()).expect("coded"),
                reason
            );
        }
        assert!(
            Reason::named("whim")
                .expect_err("none")
                .message
                .contains("keyCompromise")
        );
        assert!(Reason::of_code(2).is_err());
    }
}
