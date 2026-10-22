//! When a certificate is valid, read from the certificate itself, and when
//! it is renewed: what renewal is timed by, whatever lifetime its issuer
//! chose.

use crate::Result;
use crate::parsed::Parsed;

/// A certificate's `notBefore` and `notAfter`, seconds since the epoch.
///
/// # Errors
///
/// Where `der` is not a certificate or its times are not times.
pub fn validity(der: &[u8]) -> Result<(i64, i64)> {
    let read = Parsed::read(der)?;
    Ok((read.not_before, read.not_after))
}

/// When a certificate valid from `not_before` to `not_after` is renewed:
/// two thirds of the way through its life, whatever that life is — the
/// moment a provisioner obtains again, an air-gapped node's health says a
/// request is due, and the cluster's authority suggests over ACME Renewal
/// Information (RFC 9773). Let's Encrypt advises the same fraction for a
/// client without ARI (<https://letsencrypt.org/2025/12/02/from-90-to-45/>).
#[must_use]
pub const fn renewal_moment(not_before: i64, not_after: i64) -> i64 {
    not_before + (not_after - not_before) / 3 * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_renewed_two_thirds_through_its_life() {
        assert_eq!(renewal_moment(0, 90), 60);
        assert_eq!(
            renewal_moment(1_000, 1_000 + 90 * 86_400),
            1_000 + 60 * 86_400
        );
    }
}
