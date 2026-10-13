//! When a certificate is valid, read from the certificate itself: what
//! renewal is timed by, whatever lifetime its issuer chose.

use asn1::SEQUENCE;

use crate::Result;
use crate::der::read_time;

/// A certificate's `notBefore` and `notAfter`, seconds since the epoch.
///
/// # Errors
///
/// Where `der` is not a certificate or its times are not times.
pub fn validity(der: &[u8]) -> Result<(i64, i64)> {
    let (certificate, _) = asn1::expect(der, SEQUENCE)?;
    let (tbs, _) = asn1::expect(certificate, SEQUENCE)?;
    let mut rest = tbs;
    // The version is explicit and optional; the serial, the signature
    // algorithm and the issuer come before the validity.
    if let (tag, _, after) = asn1::read(rest)?
        && tag == asn1::context(0, true)
    {
        rest = after;
    }
    for _ in 0..3 {
        rest = asn1::read(rest)?.2;
    }
    let (times, _) = asn1::expect(rest, SEQUENCE)?;
    let (first_tag, first, after) = asn1::read(times)?;
    let (second_tag, second, _) = asn1::read(after)?;
    Ok((read_time(first_tag, first)?, read_time(second_tag, second)?))
}
