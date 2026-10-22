//! The register of an authority kept in a folder: every certificate it
//! signed, which it revoked and why, the revocation list it publishes, and
//! the address it publishes at. Kept beside its key and certificate, so the
//! cluster's authority (`internal-ca`, serving ACME) and every surface that
//! signs through the runtime (a node's certificate issued or signed, a
//! person's) write one register, and an operator inspects, revokes and
//! backs up the one authority (ADR-0034, amendment 2026-10-22).
//!
//! Each certificate signed is its own file, `issued/<serial>.pem`, created
//! and never written over; each revocation its own, `revoked/<serial>`; so
//! two writers — a node's service answering ACME and an operator's surface
//! — never write the same file. The list, `authority.crl`, is made whole
//! from them and switched into place.

use std::path::{Path, PathBuf};

use secret::private_file;

use crate::crl::{self, Reason, Revoked};
use crate::parsed::Parsed;
use crate::{ProvisionError, Purpose, Result, pem, renewal};

/// The folder each signed certificate is kept in.
const ISSUED: &str = "issued";
/// The folder each revocation is kept in.
const REVOKED: &str = "revoked";
/// The file the address it publishes at is kept in.
pub const PUBLISHED: &str = "published";
/// The file its current revocation list is kept in, DER.
pub const LIST: &str = "authority.crl";

/// How long a list it makes is valid: a week, so a verifier on the
/// premises holding the last list fetched still decides while the
/// authority's node is down for a day or two.
pub const LIST_LIFETIME: i64 = 7 * 86_400;

/// How old a list may be before it is made again when asked: a day.
const LIST_FRESH: i64 = 86_400;

/// One certificate the authority signed, as an operator inspects it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Its serial number, hexadecimal, uppercase.
    pub serial: String,
    /// Its subject's common name.
    pub subject: String,
    /// The DNS names it is for.
    pub names: Vec<String>,
    /// What it serves, its purpose's word: `node`, `receive`, `operator`.
    pub purpose: &'static str,
    /// From when it is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
    /// When it is renewed (`renewal_moment`).
    pub renew_at: i64,
    /// Its ACME Renewal Information identifier (RFC 9773 section 4.1).
    pub renewal_id: String,
    /// Its revocation, where it is revoked.
    pub revoked: Option<Revoked>,
}

impl Record {
    /// Its standing at `now`: `revoked`, else as `renewal::Standing` says
    /// it — `current`, `renewal due`, `expired`.
    #[must_use]
    pub const fn standing(&self, now: i64) -> &'static str {
        if self.revoked.is_some() {
            "revoked"
        } else {
            renewal::Standing::between(self.not_before, self.not_after, now).word()
        }
    }
}

/// The register of the authority kept in a folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    place: PathBuf,
}

impl Register {
    /// The register of the authority kept in `place`.
    #[must_use]
    pub fn at(place: &Path) -> Self {
        Self {
            place: place.to_path_buf(),
        }
    }

    /// The folder it is kept in.
    #[must_use]
    pub fn place(&self) -> &Path {
        &self.place
    }

    /// The address the authority publishes its list and certificate at,
    /// where one was set.
    ///
    /// # Errors
    ///
    /// Where the file is there and cannot be read.
    pub fn published(&self) -> Result<Option<String>> {
        match std::fs::read_to_string(self.place.join(PUBLISHED)) {
            Ok(text) => Ok(Some(text.trim().to_string()).filter(|text| !text.is_empty())),
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(failure) => Err(failed(&self.place.join(PUBLISHED), &failure)),
        }
    }

    /// Set the address it publishes at: `http://host:port`, plain HTTP,
    /// which every certificate it signs from now names (RFC 5280 section
    /// 4.2.1.13; a verifier fetches a list before it trusts any TLS).
    ///
    /// # Errors
    ///
    /// Where `address` is not an `http://` address with a host, or the file
    /// cannot be written.
    pub fn publish(&self, address: &str) -> Result<()> {
        let address = address.trim().trim_end_matches('/');
        let host = address.strip_prefix("http://").unwrap_or_default();
        if host.is_empty() || host.contains(['/', ' ', '?', '#']) {
            return Err(ProvisionError::new(format!(
                "the authority publishes at an address http://host:port, plain HTTP, since a \
                 verifier fetches its list before it trusts any TLS; {address:?} is not one"
            )));
        }
        let path = self.place.join(PUBLISHED);
        private_file::replace_readable(&path, format!("{address}\n").as_bytes())
            .map_err(|failure| failed(&path, &failure))
    }

    /// Keep the certificate `leaf`, DER, as signed.
    ///
    /// # Errors
    ///
    /// Where it does not read or cannot be written.
    pub fn record(&self, leaf: &[u8]) -> Result<()> {
        let read = Parsed::read(leaf)?;
        let folder = self.place.join(ISSUED);
        private_file::directory(&folder).map_err(|failure| failed(&folder, &failure))?;
        let path = folder.join(format!("{}.pem", read.serial_hex()));
        private_file::create_readable(&path, pem::encode("CERTIFICATE", leaf).as_bytes())
            .map_err(|failure| failed(&path, &failure))
    }

    /// Every certificate it signed, the newest first.
    ///
    /// # Errors
    ///
    /// Where the register cannot be read.
    pub fn records(&self) -> Result<Vec<Record>> {
        let mut records = Vec::new();
        for path in listed(&self.place.join(ISSUED))? {
            if path.extension().is_some_and(|extension| extension == "pem") {
                records.push(self.read(&path)?);
            }
        }
        records.sort_by_key(|record| core::cmp::Reverse(record.not_before));
        Ok(records)
    }

    /// The certificate whose serial is `serial`, hexadecimal, any case.
    ///
    /// # Errors
    ///
    /// Where it signed none such, or the register cannot be read.
    pub fn find(&self, serial: &str) -> Result<Record> {
        let wanted = serial.trim().trim_start_matches("0x").to_ascii_uppercase();
        let path = self.place.join(ISSUED).join(format!("{wanted}.pem"));
        if wanted.is_empty() || !wanted.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(ProvisionError::new(format!(
                "{serial:?} is not a serial number, hexadecimal as the register lists it"
            )));
        }
        if !path.exists() {
            return Err(ProvisionError::new(format!(
                "the authority at {} signed no certificate {wanted}",
                self.place.display()
            )));
        }
        self.read(&path)
    }

    /// The certificate kept at `path`, with its revocation.
    fn read(&self, path: &Path) -> Result<Record> {
        let text = std::fs::read_to_string(path).map_err(|failure| failed(path, &failure))?;
        let read = Parsed::first(&text)?;
        let serial = read.serial_hex();
        let purpose = [Purpose::Node, Purpose::Receive, Purpose::Operator]
            .into_iter()
            .find(|purpose| crate::serves_read(&read, *purpose).unwrap_or(false))
            .map_or("unknown", Purpose::word);
        Ok(Record {
            subject: read.common_name()?.unwrap_or_default(),
            names: read.names()?,
            purpose,
            not_before: read.not_before,
            not_after: read.not_after,
            renew_at: crate::renewal_moment(read.not_before, read.not_after),
            renewal_id: renewal::identifier(&read).unwrap_or_default(),
            revoked: self.revocation(&serial, &read.serial)?,
            serial,
        })
    }

    /// The revocation of the certificate `serial`, where it is revoked.
    fn revocation(&self, serial: &str, bytes: &[u8]) -> Result<Option<Revoked>> {
        let path = self.place.join(REVOKED).join(serial);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(failure) => return Err(failed(&path, &failure)),
        };
        let value = |key: &str| {
            text.lines()
                .filter_map(|line| line.split_once('='))
                .find(|(name, _)| name.trim() == key)
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_default()
        };
        Ok(Some(Revoked {
            serial: bytes.to_vec(),
            at: value("at").parse().unwrap_or_default(),
            reason: Reason::named(&value("reason")).unwrap_or(Reason::Unspecified),
        }))
    }

    /// Revoke the certificate `serial` for `reason` at `now`, and make the
    /// list again at once, signed by `signer` — the authority's name and
    /// key. A certificate revoked once stays as it was revoked.
    ///
    /// # Errors
    ///
    /// Where it signed no such certificate, it is revoked already, or a
    /// file cannot be written; each in words.
    pub fn revoke(
        &self,
        signer: (&[u8], &crate::KeyPair),
        serial: &str,
        reason: Reason,
        now: i64,
    ) -> Result<Record> {
        let found = self.find(serial)?;
        if let Some(revoked) = &found.revoked {
            return Err(ProvisionError::new(format!(
                "{} was revoked already, at {}, for {}",
                found.serial,
                revoked.at,
                revoked.reason.word()
            )));
        }
        let folder = self.place.join(REVOKED);
        private_file::directory(&folder).map_err(|failure| failed(&folder, &failure))?;
        let path = folder.join(&found.serial);
        let said = format!("at = {now}\nreason = {}\n", reason.word());
        private_file::create_readable(&path, said.as_bytes())
            .map_err(|failure| failed(&path, &failure))?;
        self.make_list(signer, now)?;
        self.find(serial)
    }

    /// The list the authority publishes, DER: the one kept, or one made
    /// again where none is kept or the one kept is a day old.
    ///
    /// # Errors
    ///
    /// Where the register cannot be read or the list written.
    pub fn list(&self, signer: (&[u8], &crate::KeyPair), now: i64) -> Result<Vec<u8>> {
        if let Ok(kept) = std::fs::read(self.place.join(LIST))
            && crl::read(&kept).is_ok_and(|listed| now - listed.this_update < LIST_FRESH)
        {
            return Ok(kept);
        }
        self.make_list(signer, now)
    }

    /// The list made from every revocation, numbered past the last, and
    /// kept whole.
    fn make_list(&self, (name, key): (&[u8], &crate::KeyPair), now: i64) -> Result<Vec<u8>> {
        let revoked: Vec<Revoked> = self
            .records()?
            .into_iter()
            .filter_map(|record| record.revoked)
            .collect();
        let path = self.place.join(LIST);
        let last = std::fs::read(&path)
            .ok()
            .and_then(|kept| crl::read(&kept).ok())
            .map_or(0, |listed| listed.number);
        let number = u64::try_from(now).unwrap_or(0).max(last + 1);
        let der = crl::write(name, key, &revoked, number, (now, now + LIST_LIFETIME))?;
        private_file::replace_readable(&path, &der).map_err(|failure| failed(&path, &failure))?;
        Ok(der)
    }

    /// The whole authority copied into `to`, a folder that is not there or
    /// is empty: its key, its certificate, its register, its list and
    /// whatever its ACME service keeps beside them, each a private file.
    /// What is copied is what restores it: an authority kept in the copy is
    /// the same authority.
    ///
    /// # Errors
    ///
    /// Where `to` holds anything, or a file cannot be read or written.
    pub fn back_up(&self, to: &Path) -> Result<Vec<PathBuf>> {
        if listed(to)?.into_iter().next().is_some() {
            return Err(ProvisionError::new(format!(
                "{} holds files already; a backup is made into an empty folder",
                to.display()
            )));
        }
        if !self.place.join(crate::issuer::KEY).exists() {
            return Err(ProvisionError::new(format!(
                "no authority is kept at {}",
                self.place.display()
            )));
        }
        let mut copied = Vec::new();
        copy(&self.place, to, &mut copied)?;
        Ok(copied)
    }
}

/// Every file and folder in `folder`; none where it is not there.
fn listed(folder: &Path) -> Result<Vec<PathBuf>> {
    match std::fs::read_dir(folder) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|failure| failed(folder, &failure)),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(failure) => Err(failed(folder, &failure)),
    }
}

/// `from` copied into `to`, folder by folder, each file private; what a
/// crash left between writing and switching is passed over.
fn copy(from: &Path, to: &Path, copied: &mut Vec<PathBuf>) -> Result<()> {
    private_file::sweep(from).map_err(|failure| failed(from, &failure))?;
    private_file::directory(to).map_err(|failure| failed(to, &failure))?;
    for path in listed(from)? {
        let target = to.join(path.file_name().unwrap_or_default());
        if path.is_dir() {
            copy(&path, &target, copied)?;
        } else {
            let bytes = zeroize::Zeroizing::new(
                std::fs::read(&path).map_err(|failure| failed(&path, &failure))?,
            );
            private_file::create(&target, &bytes).map_err(|failure| failed(&target, &failure))?;
            copied.push(target);
        }
    }
    Ok(())
}

fn failed(path: &Path, failure: &std::io::Error) -> ProvisionError {
    ProvisionError::new(format!("{}: {failure}", path.display()))
}
