//! A node's certificate carried across an air gap (ADR-0034, amendment
//! 2026-10-22): a node with no route to the cluster's authority writes its
//! request to a file, the file is carried to the machine that keeps the
//! authority and signed there, and the chain is carried back and imported.
//! The owner, 2026-10-22: *There has to be tools, aid, to support 'Let's
//! encrypt', ACME when being offline* — this is the case with no network
//! route at all.
//!
//! Each step checks the file it is given. [`request_into`] checks the names
//! and writes a fresh key that never leaves the node beside a PKCS #10
//! request for it. [`sign`] verifies the request's own signature, holds it
//! to what a node's certificate may be (`Purpose::admit`) and to the names
//! the signer expects, and records what it signed in the authority's
//! register. [`import`] checks the chain's every signature, that the leaf
//! is for the key the request was made with, serves a node, names what was
//! asked and is valid now, and that it reaches the anchors the node holds;
//! only then does the node's certificate change. Renewal is the same three
//! steps, asked when the node's health says a request is due
//! (`renewal::Standing`).

use std::path::{Path, PathBuf};

use secret::private_file;

use crate::node::{ANCHORS_FILE, CERTIFICATE_FILE, KEY_FILE, NODE_LIFETIME, reached_by};
use crate::operator::REQUEST_LABEL;
use crate::parsed::Parsed;
use crate::{Issuer, KeyPair, ProvisionError, Purpose, Result, csr, pem};

/// The request a node writes, carried to the authority.
pub const REQUEST_FILE: &str = "node.csr";

/// The key it is for, which stays on the node until its certificate is
/// imported and becomes `node.key`.
pub const NEXT_KEY_FILE: &str = "node.next.key";

/// The longest DNS name (RFC 1035 section 2.3.4, as text).
const NAME_LONGEST: usize = 253;

/// Where a node's request and its key were written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    /// The request, [`REQUEST_FILE`], `CERTIFICATE REQUEST` PEM.
    pub request: PathBuf,
    /// The key, [`NEXT_KEY_FILE`], a private file.
    pub key: PathBuf,
    /// The names asked for, the node's own first.
    pub names: Vec<String>,
}

/// What the authority signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The chain, PEM, leaf first, then the authority.
    pub chain: String,
    /// Its serial number, hexadecimal, as the register lists it.
    pub serial: String,
    /// The names it is for.
    pub names: Vec<String>,
    /// Until when it is valid.
    pub not_after: i64,
}

/// What a node imported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// The chain, [`CERTIFICATE_FILE`].
    pub certificate: PathBuf,
    /// Its key, [`KEY_FILE`].
    pub key: PathBuf,
    /// The anchors, [`ANCHORS_FILE`].
    pub anchors: PathBuf,
    /// Its serial number, hexadecimal.
    pub serial: String,
    /// Until when it is valid.
    pub not_after: i64,
    /// When its renewal is due.
    pub renew_at: i64,
    /// The SHA-256 of the authority's certificate, hexadecimal: what an
    /// operator compares by another way where the anchor was taken from the
    /// chain.
    pub anchor_fingerprint: String,
    /// Whether the anchor was taken from the chain, the node holding none.
    pub anchor_taken: bool,
}

/// A fresh key and a request for the node `node`, reached by its own name
/// and every one of `names`, written into `folder` as [`NEXT_KEY_FILE`] and
/// [`REQUEST_FILE`], private files, neither over a file already there.
///
/// # Errors
///
/// Where a name is not a host's name, a request is waiting there already,
/// or a file cannot be written; each in words, nothing written.
pub fn request_into(node: &str, names: &[String], folder: &Path) -> Result<Requested> {
    let every = reached_by(node, names);
    for name in &every {
        host_name(name)?;
    }
    let written = Requested {
        request: folder.join(REQUEST_FILE),
        key: folder.join(NEXT_KEY_FILE),
        names: every,
    };
    if let Some(there) = [&written.key, &written.request]
        .into_iter()
        .find(|path| path.exists())
    {
        return Err(ProvisionError::new(format!(
            "a request is waiting at {}: import its certificate, or remove {} and {} to ask \
             again",
            there.display(),
            REQUEST_FILE,
            NEXT_KEY_FILE
        )));
    }
    let key = KeyPair::generate()?;
    let der = csr::write(&key, &written.names)?;
    private_file::directory(folder).map_err(|failure| failed(folder, &failure))?;
    private_file::create(&written.key, key.pem().as_bytes())
        .map_err(|failure| failed(&written.key, &failure))?;
    let text = pem::encode(REQUEST_LABEL, &der);
    if let Err(failure) = private_file::create_readable(&written.request, text.as_bytes()) {
        let _ = std::fs::remove_file(&written.key);
        return Err(failed(&written.request, &failure));
    }
    Ok(written)
}

/// The node's certificate for the request `text`, signed by the authority
/// kept in `authority` — never made here: a carried request is signed by an
/// authority that exists — valid from `now` for ninety days, and recorded
/// in its register. Where `expected` names any names, the request must ask
/// for exactly those.
///
/// # Errors
///
/// Where the text holds no request, its signature does not verify, it asks
/// for more than a node's certificate carries or for other names than
/// expected, or no authority is kept there; each in words.
pub fn sign(authority: &Path, text: &str, expected: &[String], now: i64) -> Result<Signed> {
    let blocks = pem::decode(REQUEST_LABEL, text)?;
    let der = blocks
        .first()
        .ok_or_else(|| ProvisionError::new(format!("the file holds no {REQUEST_LABEL}")))?;
    let requested = csr::read(der)?;
    Purpose::Node.admit(&requested)?;
    for name in &requested.names {
        host_name(name)?;
    }
    if !expected.is_empty() && !same(&requested.names, expected) {
        return Err(ProvisionError::new(format!(
            "the request asks for {} and the signer expects {}; nothing is signed",
            requested.names.join(", "),
            expected.join(", ")
        )));
    }
    let issuer = Issuer::kept(authority)?;
    let lifetime = i64::try_from(NODE_LIFETIME.as_secs()).unwrap_or(i64::MAX / 2);
    let chain = issuer.sign(der, Purpose::Node, now, now.saturating_add(lifetime))?;
    let leaf = Parsed::first(&chain)?;
    Ok(Signed {
        serial: leaf.serial_hex(),
        names: leaf.names()?,
        not_after: leaf.not_after,
        chain,
    })
}

/// The chain `text` imported into the node's `folder`, once every check
/// holds: it is the request's — the leaf for [`NEXT_KEY_FILE`]'s key, for
/// [`REQUEST_FILE`]'s names, serving a node — valid at `now`, each
/// certificate signed by the next and the last an authority that signed
/// itself and is the node's anchor where it holds [`ANCHORS_FILE`]. Then
/// [`CERTIFICATE_FILE`] and [`KEY_FILE`] are written, private files in
/// place of what was there, the anchor too where the node held none, and
/// the request's two files removed. A crash between the writes leaves the
/// request's files in place, and importing the same chain again finishes.
///
/// # Errors
///
/// Where no request is waiting in `folder`, or a check does not hold; each
/// in words, nothing changed.
pub fn import(text: &str, folder: &Path, now: i64) -> Result<Imported> {
    let next_key = folder.join(NEXT_KEY_FILE);
    let key = std::fs::read_to_string(&next_key).map_err(|_| {
        ProvisionError::new(format!(
            "no request is waiting in {}: a certificate is imported into the folder its \
             request was made in",
            folder.display()
        ))
    })?;
    let key = KeyPair::from_pem(&zeroize::Zeroizing::new(key))?;
    let request = read_text(&folder.join(REQUEST_FILE))?;
    let asked = pem::decode(REQUEST_LABEL, &request)?
        .first()
        .map(|der| csr::read(der))
        .transpose()?
        .ok_or_else(|| ProvisionError::new(format!("{REQUEST_FILE} holds no request")))?;

    let chain: Vec<Parsed> = pem::decode("CERTIFICATE", text)?
        .iter()
        .map(|der| Parsed::read(der))
        .collect::<Result<_>>()?;
    let (Some(leaf), Some(root)) = (chain.first(), chain.last()) else {
        return Err(ProvisionError::new("the file holds no CERTIFICATE"));
    };
    if chain.len() < 2 {
        return Err(ProvisionError::new(
            "the file holds the node's certificate alone; the chain carries its authority too",
        ));
    }
    if leaf.public_key_info != key.public_key_info() {
        return Err(ProvisionError::new(
            "the certificate is for another key than the request waiting here",
        ));
    }
    if !crate::serves_read(leaf, Purpose::Node)? {
        return Err(ProvisionError::new(
            "the certificate does not serve a node: server and client authentication both",
        ));
    }
    if !same(&leaf.names()?, &asked.names) {
        return Err(ProvisionError::new(format!(
            "the certificate names {} and the request asked for {}",
            leaf.names()?.join(", "),
            asked.names.join(", ")
        )));
    }
    if now < leaf.not_before || now >= leaf.not_after {
        return Err(ProvisionError::new(format!(
            "the certificate is valid from {} to {}, not now",
            leaf.not_before, leaf.not_after
        )));
    }
    for (one, next) in chain.iter().zip(chain.iter().skip(1)) {
        if !one.signed_by(next)? {
            return Err(ProvisionError::new(
                "a certificate of the chain is not signed by the one after it",
            ));
        }
    }
    if !root.signed_by(root)? {
        return Err(ProvisionError::new(
            "the chain does not end at an authority that signed itself",
        ));
    }
    let root_der = pem::decode("CERTIFICATE", text)?.pop().unwrap_or_default();
    let anchors = folder.join(ANCHORS_FILE);
    let anchor_taken = !anchors.exists();
    if !anchor_taken {
        let held = pem::decode("CERTIFICATE", &read_text(&anchors)?)?;
        if !held.contains(&root_der) {
            return Err(ProvisionError::new(format!(
                "the chain does not reach the anchors this node holds, {}",
                anchors.display()
            )));
        }
    }

    let imported = Imported {
        certificate: folder.join(CERTIFICATE_FILE),
        key: folder.join(KEY_FILE),
        anchors,
        serial: leaf.serial_hex(),
        not_after: leaf.not_after,
        renew_at: crate::renewal_moment(leaf.not_before, leaf.not_after),
        anchor_fingerprint: crate::fingerprint(&root_der),
        anchor_taken,
    };
    let write = |path: &Path, bytes: &[u8]| {
        private_file::replace(path, bytes).map_err(|failure| failed(path, &failure))
    };
    write(&imported.certificate, text.as_bytes())?;
    write(&imported.key, key.pem().as_bytes())?;
    if anchor_taken {
        write(
            &imported.anchors,
            pem::encode("CERTIFICATE", &root_der).as_bytes(),
        )?;
    }
    for done in [folder.join(REQUEST_FILE), next_key] {
        std::fs::remove_file(&done).map_err(|failure| failed(&done, &failure))?;
    }
    Ok(imported)
}

/// Whether `name` may be a host's name in a node's certificate: one to
/// 253 characters, letters, digits, hyphens and dots, or an IP address.
fn host_name(name: &str) -> Result<()> {
    let plain = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
    if name.parse::<std::net::IpAddr>().is_ok()
        || (!name.is_empty() && name.len() <= NAME_LONGEST && plain && !name.starts_with('.'))
    {
        Ok(())
    } else {
        Err(ProvisionError::new(format!(
            "{name:?} is not a host's name: letters, digits, hyphens and dots, or an address"
        )))
    }
}

/// Whether two lists of names hold the same names, case and order aside.
fn same(one: &[String], other: &[String]) -> bool {
    let sorted = |names: &[String]| {
        let mut lowered: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        lowered.sort();
        lowered.dedup();
        lowered
    };
    sorted(one) == sorted(other)
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|failure| failed(path, &failure))
}

fn failed(path: &Path, failure: &std::io::Error) -> ProvisionError {
    ProvisionError::new(format!("{}: {failure}", path.display()))
}
