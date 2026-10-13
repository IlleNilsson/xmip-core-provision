//! The provisioner's trait: what every source of a certificate implements.

use std::path::Path;

use crate::{Provisioned, Purpose, Result};

/// What a certificate is asked for.
#[derive(Clone, Copy, Debug)]
pub struct Order<'a> {
    /// What it is for.
    pub purpose: Purpose,
    /// The DNS names it is for, the first its subject's common name.
    pub names: &'a [String],
    /// The purpose's place: a directory the source may keep its own state
    /// in between orders — an ACME account's key, an authority's root.
    pub keep: &'a Path,
}

/// A source of certificates: an ACME directory, the cluster's authority, a
/// node signing its own, an operator's files, or a provider's.
pub trait Source: Send + Sync {
    /// The technology's module name, as `[provision.<purpose>] source`
    /// names it.
    fn technology(&self) -> &'static str;

    /// Obtain a certificate for `order`: a fresh key and a chain for it.
    ///
    /// # Errors
    ///
    /// Whatever stopped it, in words: an authority that refused, a
    /// challenge that failed, a file that is not there.
    fn obtain(&self, order: &Order<'_>) -> Result<Provisioned>;
}
