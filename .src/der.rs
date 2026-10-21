//! The pieces of X.509 (RFC 5280) and PKCS #10 (RFC 2986) a certificate and
//! a request are both made of, written once: object identifiers, a name, a
//! time, a public key, an extension.

use asn1::{BOOLEAN, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, object_identifier, tlv};
use codec::civil::CivilTime;

use crate::{ProvisionError, Result};

/// `SET` and `SET OF`, constructed.
pub const SET: u8 = 0x31;
/// `BIT STRING`.
pub const BIT_STRING: u8 = 0x03;
/// `UTF8String`.
const UTF8_STRING: u8 = 0x0c;
/// `UTCTime`.
const UTC_TIME: u8 = 0x17;

/// id-ecPublicKey (RFC 5480).
pub const EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10_045, 2, 1];
/// secp256r1, P-256 (RFC 5480).
pub const P256: &[u32] = &[1, 2, 840, 10_045, 3, 1, 7];
/// ecdsa-with-SHA256 (RFC 5758).
pub const ECDSA_SHA256: &[u32] = &[1, 2, 840, 10_045, 4, 3, 2];
/// id-at-commonName.
pub const COMMON_NAME: &[u32] = &[2, 5, 4, 3];
/// id-ce-subjectAltName.
pub const SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];
/// id-ce-basicConstraints.
pub const BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
/// id-ce-keyUsage.
pub const KEY_USAGE: &[u32] = &[2, 5, 29, 15];
/// id-ce-extKeyUsage.
pub const EXT_KEY_USAGE: &[u32] = &[2, 5, 29, 37];
/// id-kp-serverAuth.
pub const SERVER_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
/// id-kp-clientAuth.
pub const CLIENT_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
/// pkcs-9-at-extensionRequest (RFC 2985).
pub const EXTENSION_REQUEST: &[u32] = &[1, 2, 840, 113_549, 1, 9, 14];

/// An `OBJECT IDENTIFIER`, whole.
#[must_use]
pub fn oid(arcs: &[u32]) -> Vec<u8> {
    tlv(OBJECT_IDENTIFIER, &object_identifier(arcs))
}

/// A `SEQUENCE` of `parts`, each already whole.
#[must_use]
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A `BIT STRING` of whole bytes.
#[must_use]
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(bytes.len() + 1);
    contents.push(0);
    contents.extend_from_slice(bytes);
    tlv(BIT_STRING, &contents)
}

/// The signature algorithm every signature here is: ECDSA with SHA-256,
/// which takes no parameters.
#[must_use]
pub fn ecdsa_sha256() -> Vec<u8> {
    sequence(&[&oid(ECDSA_SHA256)])
}

/// A name of one common name, which is all a node's certificate needs: the
/// names it is checked by are its alternative names.
#[must_use]
pub fn name(common_name: &str) -> Vec<u8> {
    let attribute = sequence(&[&oid(COMMON_NAME), &tlv(UTF8_STRING, common_name.as_bytes())]);
    sequence(&[&tlv(SET, &attribute)])
}

/// A P-256 public point as `SubjectPublicKeyInfo`.
#[must_use]
pub fn public_key_info(point: &[u8]) -> Vec<u8> {
    let algorithm = sequence(&[&oid(EC_PUBLIC_KEY), &oid(P256)]);
    sequence(&[&algorithm, &bit_string(point)])
}

/// The P-256 point a `SubjectPublicKeyInfo` holds.
///
/// # Errors
///
/// Where it is not one, or its key is not P-256.
pub fn point_of(info: &[u8]) -> Result<Vec<u8>> {
    let (contents, _) = asn1::expect(info, SEQUENCE)?;
    let (algorithm, rest) = asn1::expect(contents, SEQUENCE)?;
    if algorithm != [oid(EC_PUBLIC_KEY), oid(P256)].concat() {
        return Err(ProvisionError::new("the public key is not a P-256 key"));
    }
    let (bits, _) = asn1::expect(rest, BIT_STRING)?;
    match bits.split_first() {
        Some((0, point)) if point.len() == 65 => Ok(point.to_vec()),
        _ => Err(ProvisionError::new(
            "the P-256 public key is not an uncompressed point",
        )),
    }
}

/// The alternative names `names` are: an IP address an `iPAddress`, its
/// four or sixteen octets (RFC 5280 section 4.2.1.6) — what a browser
/// checks a host reached at `127.0.0.1` against, and never a `dNSName` —
/// and every other name a `dNSName`.
#[must_use]
pub fn alternative_names(names: &[String]) -> Vec<u8> {
    let entries: Vec<u8> = names
        .iter()
        .flat_map(|name| match name.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(address)) => tlv(asn1::context(7, false), &address.octets()),
            Ok(std::net::IpAddr::V6(address)) => tlv(asn1::context(7, false), &address.octets()),
            Err(_) => tlv(asn1::context(2, false), name.as_bytes()),
        })
        .collect();
    tlv(SEQUENCE, &entries)
}

/// The `dNSName`s an alternative-names value holds; other kinds of name are
/// passed over.
///
/// # Errors
///
/// Where the value is not a `SEQUENCE` of names.
pub fn read_alternative_names(value: &[u8]) -> Result<Vec<String>> {
    let (contents, _) = asn1::expect(value, SEQUENCE)?;
    Ok(asn1::read_all(contents)?
        .into_iter()
        .filter(|(tag, _)| *tag == asn1::context(2, false))
        .map(|(_, name)| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// The attributes a `Name` holds, each its type and its value as text, in
/// the order written.
///
/// # Errors
///
/// Where it is not a `Name`, or a value is not text.
pub fn read_name(name: &[u8]) -> Result<Vec<(Vec<u32>, String)>> {
    let (sets, _) = asn1::expect(name, SEQUENCE)?;
    let mut attributes = Vec::new();
    for (_, set) in asn1::read_all(sets)? {
        for (_, attribute) in asn1::read_all(set)? {
            let (kind, rest) = asn1::expect(attribute, OBJECT_IDENTIFIER)?;
            let (_, value, _) = asn1::read(rest)?;
            let text = core::str::from_utf8(value)
                .map_err(|_| ProvisionError::new("a name's value is not text"))?;
            attributes.push((asn1::read_object_identifier(kind)?, text.to_string()));
        }
    }
    Ok(attributes)
}

/// The subject of the certificate `der`, its `Name` whole, as an issuer
/// names itself in what it signs.
///
/// # Errors
///
/// Where `der` is not a certificate.
pub fn subject_of(der: &[u8]) -> Result<Vec<u8>> {
    let (certificate, _) = asn1::expect(der, SEQUENCE)?;
    let (tbs, _) = asn1::expect(certificate, SEQUENCE)?;
    let mut rest = tbs;
    if let (tag, _, after) = asn1::read(rest)?
        && tag == asn1::context(0, true)
    {
        rest = after;
    }
    // The serial, the signature algorithm, the issuer and the validity come
    // before the subject.
    for _ in 0..4 {
        rest = asn1::read(rest)?.2;
    }
    let (_, _, after) = asn1::read(rest)?;
    Ok(rest[..rest.len() - after.len()].to_vec())
}

/// One extension: its identifier, critical or not, and its value's DER.
#[must_use]
pub fn extension(arcs: &[u32], critical: bool, value: &[u8]) -> Vec<u8> {
    let flag = if critical {
        tlv(BOOLEAN, &[0xff])
    } else {
        Vec::new()
    };
    sequence(&[&oid(arcs), &flag, &tlv(OCTET_STRING, value)])
}

/// `unix` as X.509 writes a time: `UTCTime` through 2049, `GeneralizedTime`
/// from 2050 (RFC 5280 section 4.1.2.5).
///
/// # Errors
///
/// Where `unix` is before the epoch.
pub fn time(unix: i64) -> Result<Vec<u8>> {
    let seconds =
        u64::try_from(unix).map_err(|_| ProvisionError::new("a certificate time before 1970"))?;
    let at = CivilTime::from_system_time(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
    );
    let clock = format!(
        "{:02}{:02}{:02}{:02}{:02}Z",
        at.month, at.day, at.hour, at.minute, at.second
    );
    Ok(if at.year < 2050 {
        tlv(UTC_TIME, format!("{:02}{clock}", at.year % 100).as_bytes())
    } else {
        tlv(
            asn1::GENERALIZED_TIME,
            format!("{:04}{clock}", at.year).as_bytes(),
        )
    })
}

/// A `UTCTime` or `GeneralizedTime` in UTC, as seconds since the epoch.
///
/// # Errors
///
/// Where the tag is neither, or the text is not a time.
pub fn read_time(tag: u8, contents: &[u8]) -> Result<i64> {
    let text = core::str::from_utf8(contents).unwrap_or_default();
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 13 => {
            let two: i64 = text[..2].parse().unwrap_or(-1);
            (if two < 50 { 2000 + two } else { 1900 + two }, &text[2..])
        }
        asn1::GENERALIZED_TIME if text.len() == 15 => (text[..4].parse().unwrap_or(-1), &text[4..]),
        _ => {
            return Err(ProvisionError::new(format!(
                "not a certificate time: {text:?}"
            )));
        }
    };
    let part = |at: usize| rest.get(at..at + 2).and_then(|two| two.parse::<u32>().ok());
    let read = || {
        CivilTime::new(year, part(0)?, part(2)?, part(4)?, part(6)?, part(8)?)
            .filter(|_| rest.ends_with('Z'))
    };
    read()
        .map(|at| at.unix())
        .ok_or_else(|| ProvisionError::new(format!("not a certificate time: {text:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_is_utc_time_before_2050_and_generalized_from_it() {
        for unix in [0, 1_791_849_600, 2_524_608_000, 4_102_444_800] {
            let written = time(unix).expect("written");
            let (tag, contents, _) = asn1::read(&written).expect("read");
            assert_eq!(read_time(tag, contents).expect("time"), unix);
        }
        assert_eq!(
            time(2_524_608_000).expect("2050")[0],
            asn1::GENERALIZED_TIME
        );
        assert!(time(-1).is_err());
        assert!(read_time(UTC_TIME, b"nonsense").is_err());
    }

    #[test]
    fn alternative_names_are_read_back_and_a_foreign_key_is_refused() {
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        assert_eq!(
            read_alternative_names(&alternative_names(&names)).expect("read"),
            names
        );
        let foreign = sequence(&[&sequence(&[&oid(&[1, 2, 840, 113_549, 1, 1, 1])])]);
        assert!(point_of(&foreign).is_err());
    }

    #[test]
    fn an_ip_address_is_written_as_an_ip_address_and_never_as_a_dns_name() {
        let names = [
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "h.example".to_string(),
        ];
        let written = alternative_names(&names);
        let (contents, _) = asn1::expect(&written, SEQUENCE).expect("a sequence");
        let entries = asn1::read_all(contents).expect("names");
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(
            entries,
            [
                (asn1::context(7, false), &[127, 0, 0, 1][..]),
                (asn1::context(7, false), &loopback[..]),
                (asn1::context(2, false), &b"h.example"[..]),
            ]
        );
        assert_eq!(
            read_alternative_names(&written).expect("read"),
            ["h.example"]
        );
    }

    #[test]
    fn a_name_is_read_back_as_its_attributes() {
        let read = read_name(&name("alice@example.org")).expect("read");
        assert_eq!(
            read,
            [(COMMON_NAME.to_vec(), "alice@example.org".to_string())]
        );
        assert!(read_name(&[0x02, 0x01, 0x00]).is_err());
    }
}
