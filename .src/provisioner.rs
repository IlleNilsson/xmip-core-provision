//! A purpose's certificate kept and renewed: read from its place, obtained
//! when there is none, obtained again at two thirds of its life.

use std::path::PathBuf;

use crate::{Order, Provisioned, Purpose, Result, Source};

/// One purpose's certificate, from one source.
pub struct Provisioner {
    source: Box<dyn Source>,
    purpose: Purpose,
    names: Vec<String>,
    place: PathBuf,
    held: Option<Provisioned>,
}

impl Provisioner {
    /// A provisioner for `purpose` and `names` from `source`, keeping what
    /// it obtains in `place`.
    #[must_use]
    pub fn new(
        source: Box<dyn Source>,
        purpose: Purpose,
        names: Vec<String>,
        place: PathBuf,
    ) -> Self {
        Self {
            source,
            purpose,
            names,
            place,
            held: None,
        }
    }

    /// Make the certificate current at `now`: read what the place keeps the
    /// first time, and obtain a new one where there is none or it is due.
    /// Says whether a new one was obtained.
    ///
    /// A renewal that fails leaves the certificate held as it was, still
    /// presented until it expires; the failure is returned to be reported
    /// and asked again.
    ///
    /// # Errors
    ///
    /// Where the place cannot be read or written, or the source fails.
    pub fn refresh(&mut self, now: i64) -> Result<bool> {
        if self.held.is_none() {
            self.held = Provisioned::read(&self.place)?;
        }
        if self.held.as_ref().is_some_and(|held| !held.due(now)) {
            return Ok(false);
        }
        let order = Order {
            purpose: self.purpose,
            names: &self.names,
            keep: &self.place,
        };
        let obtained = self.source.obtain(&order)?;
        obtained.write(&self.place)?;
        self.held = Some(obtained);
        Ok(true)
    }

    /// The certificate held, if any.
    #[must_use]
    pub const fn held(&self) -> Option<&Provisioned> {
        self.held.as_ref()
    }

    /// The purpose it is for.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }
}
