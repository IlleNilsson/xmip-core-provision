//! When a certificate is renewed, said the one way for every reader: a
//! node's health, the register an operator inspects, and ACME Renewal
//! Information (RFC 9773), which the cluster's authority serves so a
//! client on the premises — Xmip's own or a third party's — asks it when
//! to renew rather than guessing.

use codec::base64::encode_url_unpadded;

use crate::parsed::Parsed;
use crate::{ProvisionError, Result};

/// A certificate's standing at a moment: when it ends, when it is renewed,
/// and which of the two has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standing {
    /// From when it is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
    /// When it is renewed (`renewal_moment`).
    pub renew_at: i64,
    /// Whether that moment has come.
    pub due: bool,
    /// Whether it has ended.
    pub expired: bool,
}

impl Standing {
    /// The standing at `now` of the chain `text`, PEM, by its leaf.
    ///
    /// # Errors
    ///
    /// Where the text holds no certificate.
    pub fn of(text: &str, now: i64) -> Result<Self> {
        Ok(Self::at(&Parsed::first(text)?, now))
    }

    /// The standing at `now` of a certificate read.
    #[must_use]
    pub const fn at(read: &Parsed, now: i64) -> Self {
        Self::between(read.not_before, read.not_after, now)
    }

    /// The standing at `now` of a certificate valid from `not_before` to
    /// `not_after`.
    #[must_use]
    pub const fn between(not_before: i64, not_after: i64, now: i64) -> Self {
        let renew_at = crate::renewal_moment(not_before, not_after);
        Self {
            not_before,
            not_after,
            renew_at,
            due: now >= renew_at,
            expired: now >= not_after,
        }
    }

    /// Its word, as a health reads: `current`, `renewal due`, `expired`.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        if self.expired {
            "expired"
        } else if self.due {
            "renewal due"
        } else {
            "current"
        }
    }
}

/// The window RFC 9773 section 4.2 suggests a certificate valid from
/// `not_before` to `not_after` is renewed in: from two thirds of its life,
/// the moment every Xmip reader renews at, to three quarters, so a client
/// that picks a moment inside it still has a quarter of the life to spare.
#[must_use]
pub const fn window(not_before: i64, not_after: i64) -> (i64, i64) {
    let life = not_after - not_before;
    (
        crate::renewal_moment(not_before, not_after),
        not_before + life / 4 * 3,
    )
}

/// A certificate's renewal information identifier (RFC 9773 section 4.1):
/// its authority key identifier's `keyIdentifier` and its serial number's
/// bytes, each base64url without padding, joined by a dot.
///
/// # Errors
///
/// Where it carries no authority key identifier.
pub fn identifier(read: &Parsed) -> Result<String> {
    let authority = read
        .authority_key_identifier()?
        .ok_or_else(|| ProvisionError::new("the certificate names no authority key identifier"))?;
    Ok(format!(
        "{}.{}",
        encode_url_unpadded(&authority),
        encode_url_unpadded(&read.serial)
    ))
}

/// The two halves an identifier names: the authority's key identifier and
/// the serial's bytes.
///
/// # Errors
///
/// Where it is not two base64url halves joined by a dot.
pub fn halves(identifier: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let (authority, serial) = identifier.split_once('.').ok_or_else(|| {
        ProvisionError::new(format!(
            "{identifier:?} is no renewal information identifier"
        ))
    })?;
    Ok((
        codec::base64::decode_url(authority)?,
        codec::base64::decode_url(serial)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_opens_at_two_thirds_and_closes_at_three_quarters() {
        assert_eq!(window(0, 90 * 86_400), (60 * 86_400, 67 * 86_400 + 43_200));
        assert!(halves("no dot").is_err());
        assert_eq!(halves("AQI.Aw").expect("halves"), (vec![1, 2], vec![3]));
    }
}
