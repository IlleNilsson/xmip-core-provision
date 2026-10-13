//! An operator's own files: the source a purpose has where its table names
//! none, which is how every certificate arrived before this capability.

use std::path::PathBuf;

use xcore::settings::Read;
use zeroize::Zeroizing;

use crate::{Order, ProvisionError, Provisioned, Result, Source};

/// A certificate an operator supplies, read where it lies. Obtaining reads
/// the files again, so a certificate the operator replaced is the one
/// presented after the next renewal.
#[derive(Clone, Debug)]
pub struct Files {
    certificate: PathBuf,
    key: PathBuf,
    anchors: Option<PathBuf>,
}

impl Files {
    /// The files `settings`, read through [`crate::FILES`], name, each
    /// relative to `base` — the configuration file's directory.
    #[must_use]
    pub fn configured(settings: &Read, base: &std::path::Path) -> Self {
        let place = |name: &str| settings.optional_text(name).map(|path| base.join(path));
        Self {
            certificate: place("certificate").unwrap_or_default(),
            key: place("key").unwrap_or_default(),
            anchors: place("anchors"),
        }
    }
}

impl Source for Files {
    fn technology(&self) -> &'static str {
        crate::FILES.technology
    }

    fn obtain(&self, _order: &Order<'_>) -> Result<Provisioned> {
        let read = |path: &PathBuf| {
            std::fs::read_to_string(path).map_err(|failure| {
                ProvisionError::new(format!("reading {}: {failure}", path.display()))
            })
        };
        let anchors = self.anchors.as_ref().map(read).transpose()?;
        Provisioned::new(
            read(&self.certificate)?,
            Zeroizing::new(read(&self.key)?),
            anchors,
        )
    }
}
