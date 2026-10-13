//! What a source gave: a chain, its key and what a peer's chain must reach,
//! each PEM, as `xmip-core-library-tls` takes them, and when it is due for
//! renewal.

use std::path::Path;

use zeroize::Zeroizing;

use crate::{ProvisionError, Result, pem, validity};

/// The files a provisioned certificate is kept in, in its purpose's place.
const CHAIN: &str = "chain.pem";
const KEY: &str = "key.pem";
const ANCHORS: &str = "anchors.pem";

/// A certificate obtained: its chain, leaf first, its private key, and the
/// anchors a peer's certificate must reach where the source knows them —
/// the cluster's authority, a self-signed node's own certificate.
#[derive(Clone)]
pub struct Provisioned {
    /// The chain, PEM, leaf first.
    pub chain: String,
    /// The leaf's private key, PEM.
    pub key: Zeroizing<String>,
    /// The anchors, PEM, where the source has them; a public authority's
    /// are the operating system's trust store.
    pub anchors: Option<String>,
    /// From when the leaf is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
}

impl core::fmt::Debug for Provisioned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Provisioned")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("anchors", &self.anchors.is_some())
            .finish_non_exhaustive()
    }
}

impl Provisioned {
    /// What `chain`, `key` and `anchors` are, its validity read from the
    /// chain's first certificate.
    ///
    /// # Errors
    ///
    /// Where the chain holds no certificate, or its first is unreadable.
    pub fn new(chain: String, key: Zeroizing<String>, anchors: Option<String>) -> Result<Self> {
        let leaf = pem::decode("CERTIFICATE", &chain)?
            .into_iter()
            .next()
            .ok_or_else(|| ProvisionError::new("the chain holds no certificate"))?;
        let (not_before, not_after) = validity(&leaf)?;
        Ok(Self {
            chain,
            key,
            anchors,
            not_before,
            not_after,
        })
    }

    /// When it is renewed: two thirds of the way through the life it was
    /// issued with, whatever that life is.
    #[must_use]
    pub const fn renew_at(&self) -> i64 {
        self.not_before + (self.not_after - self.not_before) / 3 * 2
    }

    /// Whether it is due for renewal at `now`.
    #[must_use]
    pub const fn due(&self, now: i64) -> bool {
        now >= self.renew_at()
    }

    /// Whether it has expired at `now`.
    #[must_use]
    pub const fn expired(&self, now: i64) -> bool {
        now >= self.not_after
    }

    /// Keep it in `place`, a directory created when absent: the chain, the
    /// key and the anchors, each written whole before it replaces the last.
    ///
    /// # Errors
    ///
    /// Where the directory or a file cannot be written, naming it.
    pub fn write(&self, place: &Path) -> Result<()> {
        std::fs::create_dir_all(place).map_err(|failure| {
            ProvisionError::new(format!("creating {}: {failure}", place.display()))
        })?;
        replace(&place.join(CHAIN), self.chain.as_bytes())?;
        replace(&place.join(KEY), self.key.as_bytes())?;
        match &self.anchors {
            Some(anchors) => replace(&place.join(ANCHORS), anchors.as_bytes()),
            None => match std::fs::remove_file(place.join(ANCHORS)) {
                Err(failure) if failure.kind() != std::io::ErrorKind::NotFound => Err(
                    ProvisionError::new(format!("removing the old anchors: {failure}")),
                ),
                _ => Ok(()),
            },
        }
    }

    /// What `place` keeps, or `None` where it keeps nothing yet.
    ///
    /// # Errors
    ///
    /// Where a file is there and cannot be read, or holds no certificate.
    pub fn read(place: &Path) -> Result<Option<Self>> {
        let Some(chain) = optional(&place.join(CHAIN))? else {
            return Ok(None);
        };
        let key = optional(&place.join(KEY))?
            .ok_or_else(|| ProvisionError::new(format!("{} holds no key.pem", place.display())))?;
        let anchors = optional(&place.join(ANCHORS))?;
        Self::new(chain, Zeroizing::new(key), anchors).map(Some)
    }
}

/// `bytes` written beside `path` and then moved over it, so a reader never
/// finds half a file.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let fresh = path.with_extension("new");
    let failed = |failure: std::io::Error| {
        ProvisionError::new(format!("writing {}: {failure}", path.display()))
    };
    std::fs::write(&fresh, bytes).map_err(failed)?;
    std::fs::rename(&fresh, path).map_err(failed)
}

/// A file's text, or `None` where there is no such file.
fn optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(failure) => Err(ProvisionError::new(format!(
            "reading {}: {failure}",
            path.display()
        ))),
    }
}
