//! A host's own certificate under an authority kept in a folder: what a web
//! host serving HTTPS on this machine presents to a browser (ADR-0009,
//! amendment 2026-10-21) — the Playground's tester acting in the web GUI
//! with an operator certificate the same authority signed.
//!
//! The authority is kept, or made where none is kept, as the cluster's own
//! is ([`Issuer::kept_or_made`]); the host's certificate is issued anew at
//! each call, for server authentication alone ([`Purpose::Receive`]: what a
//! browser checks a server for), its subject and only alternative name the
//! name the browser reaches it by — an IP address written as one, which is
//! what a browser checks `https://127.0.0.1` against.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::issuer::CERTIFICATE;
use crate::{Issuer, KeyPair, ProvisionError, Purpose, Result};

/// How long an authority made here is valid: a year. The assistant's draft
/// of 2026-10-21, for the owner to strike.
pub const AUTHORITY_LIFETIME: Duration = Duration::from_hours(365 * 24);

/// How long a host's certificate is valid: thirty days, issued anew each
/// time the host starts. The assistant's draft of 2026-10-21, for the owner
/// to strike.
pub const HOST_LIFETIME: Duration = Duration::from_hours(30 * 24);

/// The file a host's certificate chain is written to, leaf first.
pub const CERTIFICATE_FILE: &str = "host.pem";

/// The file its private key is written to beside it.
pub const KEY_FILE: &str = "host.key";

/// Where [`issue_into`] wrote a host's certificate, its key, and the anchor
/// a client of the host trusts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issued {
    /// The chain, [`CERTIFICATE_FILE`], leaf first.
    pub certificate: PathBuf,
    /// The key, [`KEY_FILE`], a private file.
    pub key: PathBuf,
    /// The authority's certificate, `authority.pem` where it is kept.
    pub anchor: PathBuf,
}

/// The authority kept in `authority` — made and kept there, called `name`,
/// where none is — and a fresh key and certificate for the host `host`
/// under it, valid from `now`, written into `folder` as [`KEY_FILE`] and
/// [`CERTIFICATE_FILE`], each a private file in place of what was there.
///
/// # Errors
///
/// Where the authority cannot be read or made, `host` is empty, or a file
/// cannot be written; each in words.
pub fn issue_into(
    authority: &Path,
    name: &str,
    host: &str,
    folder: &Path,
    now: i64,
) -> Result<Issued> {
    if host.trim().is_empty() {
        return Err(ProvisionError::new(
            "a host's certificate names the host a browser reaches it by",
        ));
    }
    let authorized = Issuer::kept_or_made(authority, name, now, seconds(AUTHORITY_LIFETIME))?;
    let written = Issued {
        certificate: folder.join(CERTIFICATE_FILE),
        key: folder.join(KEY_FILE),
        anchor: authority.join(CERTIFICATE),
    };
    let names = [host.to_string()];
    let fresh = Fresh {
        subject: host,
        names: &names,
        purpose: Purpose::Receive,
        lifetime: HOST_LIFETIME,
    };
    fresh.issued_into(&authorized, now, &written)?;
    Ok(written)
}

/// `lifetime` in whole seconds, as a certificate's validity counts it.
pub(crate) fn seconds(lifetime: Duration) -> i64 {
    i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX / 2)
}

/// A fresh key and the certificate an authority issues for it: what a host
/// and a node are given alike.
pub(crate) struct Fresh<'a> {
    pub subject: &'a str,
    pub names: &'a [String],
    pub purpose: Purpose,
    pub lifetime: Duration,
}

impl Fresh<'_> {
    /// A fresh key, and its certificate under `authorized` from `now`,
    /// written as `written` names them, each a private file in place of
    /// what was there.
    pub(crate) fn issued_into(
        &self,
        authorized: &Issuer,
        now: i64,
        written: &Issued,
    ) -> Result<()> {
        let fresh = KeyPair::generate()?;
        let chain = authorized.issue(
            &fresh.public_key_info(),
            self.subject,
            self.names,
            self.purpose,
            now,
            now.saturating_add(seconds(self.lifetime)),
        )?;
        let failed = |path: &Path, failure: std::io::Error| {
            ProvisionError::new(format!("writing {}: {failure}", path.display()))
        };
        secret::private_file::replace(&written.key, fresh.pem().as_bytes())
            .map_err(|failure| failed(&written.key, failure))?;
        secret::private_file::replace(&written.certificate, chain.as_bytes())
            .map_err(|failure| failed(&written.certificate, failure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem;

    #[test]
    fn a_host_is_issued_under_the_authority_kept_and_one_is_made_where_none_is() {
        let base = std::env::temp_dir().join(format!("xmip-provision-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = base.join("authority");
        let first = issue_into(
            &authority,
            "test authority",
            "127.0.0.1",
            &base,
            1_800_000_000,
        )
        .expect("one");
        let anchor = std::fs::read_to_string(&first.anchor).expect("the anchor");
        let again = issue_into(
            &authority,
            "test authority",
            "127.0.0.1",
            &base,
            1_800_000_000,
        )
        .expect("two");
        assert_eq!(
            std::fs::read_to_string(&again.anchor).expect("kept"),
            anchor
        );

        let chain = std::fs::read_to_string(&again.certificate).expect("the chain");
        assert!(chain.ends_with(&anchor), "the leaf, then the authority");
        let leaf = pem::decode("CERTIFICATE", &chain).expect("pem").remove(0);
        assert!(crate::serves(&leaf, Purpose::Receive).expect("read"));
        assert!(!crate::serves(&leaf, Purpose::Operator).expect("read"));
        let ip = [0x87, 0x04, 127, 0, 0, 1];
        assert!(
            leaf.windows(ip.len()).any(|at| at == ip),
            "an iPAddress name"
        );
        let key = std::fs::read_to_string(&again.key).expect("the key");
        let public = KeyPair::from_pem(&key).expect("a key").public_key_info();
        assert!(leaf.windows(public.len()).any(|at| at == public.as_slice()));

        let refused = issue_into(&authority, "x", " ", &base, 0).expect_err("no host");
        assert!(refused.message.contains("host"), "{refused}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
