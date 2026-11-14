//! The pieces of X.509 (RFC 5280) and PKCS #10 (RFC 2986) a certificate and
//! a request are both made of, written once: an object identifier, a name, a
//! time, a public key, an extension. Each is read back by the estate's one
//! certificate reader, `xmip-core-library-tls`'s `certificate`, which also
//! holds the object identifiers both sides name (`certificate::oid`).

use asn1::{
    BIT_STRING, BOOLEAN, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, SET, UTC_TIME, UTF8_STRING,
    object_identifier, tlv,
};
use codec::civil::CivilTime;
use tls::certificate::oid::{COMMON_NAME, EC_PUBLIC_KEY, ECDSA_SHA256, P256};

use crate::{ProvisionError, Result};

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

/// The identifier of the key `info` holds, as a subject key identifier
/// names a key and an authority key identifier names its issuer's: the
/// leftmost 160 bits of SHA-256 over the key's bits (RFC 7093 section 2,
/// method 1), where SHA-1 was RFC 5280's.
///
/// # Errors
///
/// Where `info` is not a P-256 key.
pub fn key_identifier(info: &[u8]) -> Result<Vec<u8>> {
    let point = tls::certificate::point_of(info)?;
    Ok(codec::digest::sha256(&point)[..20].to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tls::certificate;

    #[test]
    fn a_time_is_utc_time_before_2050_and_generalized_from_it() {
        for unix in [0, 1_791_849_600, 2_524_608_000, 4_102_444_800] {
            let written = time(unix).expect("written");
            let (tag, contents, _) = asn1::read(&written).expect("read");
            assert_eq!(certificate::time(tag, contents).expect("time"), unix);
        }
        assert_eq!(
            time(2_524_608_000).expect("2050")[0],
            asn1::GENERALIZED_TIME
        );
        assert!(time(-1).is_err());
    }

    #[test]
    fn alternative_names_are_read_back_and_a_foreign_key_is_refused() {
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        assert_eq!(
            certificate::dns_names(&alternative_names(&names)).expect("read"),
            names
        );
        let foreign = sequence(&[&sequence(&[&oid(&[1, 2, 840, 113_549, 1, 1, 1])])]);
        assert!(key_identifier(&foreign).is_err());
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
            certificate::dns_names(&written).expect("read"),
            ["h.example"]
        );
    }

    #[test]
    fn a_name_is_read_back_as_its_attributes() {
        let read = certificate::text_attributes(&name("alice@example.org")).expect("read");
        assert_eq!(
            read,
            [(COMMON_NAME.to_vec(), "alice@example.org".to_string())]
        );
        assert!(certificate::text_attributes(&[0x02, 0x01, 0x00]).is_err());
    }
}
