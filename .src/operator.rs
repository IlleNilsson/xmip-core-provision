//! A person's certificate (ADR-0034, amendment 2026-10-15): the surface
//! makes its own key and a request naming the person, and the cluster's
//! authority signs it once the request is approved out of band — by whoever
//! may reach the authority's key and runs the signing.
//!
//! Both halves are here, once: [`request`] for a surface that holds its key
//! as a PEM file, written by [`request_into`] as a private file, never
//! handed to the surface; [`information`] and [`assemble`] for one whose key never
//! leaves its keeper (a phone's keystore signs the information and the two
//! make the request), and [`sign`] for the authority's side, held to
//! [`Purpose::Operator`]'s rules and to `[provision.operator]`.

use std::path::Path;

use xcore::settings::Read;
use zeroize::Zeroizing;

use crate::{Issuer, KeyPair, Purpose, Result, csr, der, pem};

/// The PEM label a request is written under (RFC 7468).
pub const REQUEST_LABEL: &str = "CERTIFICATE REQUEST";

/// A key made and a request for it.
pub struct Request {
    /// The private key, `PRIVATE KEY` PEM: the surface keeps it.
    pub key: Zeroizing<String>,
    /// The request, `CERTIFICATE REQUEST` PEM: what goes to the authority.
    pub request: String,
}

impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// What an operator's request for `person` signs, over the P-256 key
/// `public_key` is: the person as its one common name, and client
/// authentication as the one usage asked.
///
/// A keeper hands its public key in the form its platform gives:
/// `SubjectPublicKeyInfo` DER — the Android Keystore's, Windows CNG's — or
/// the bare uncompressed point, `0x04`, then `x` and `y` — the iOS
/// keychain's (X9.63). Both are read here, so no surface writes DER.
///
/// # Errors
///
/// Where `person` is not a person's name (`Purpose::person`), or
/// `public_key` is neither form of a P-256 key.
pub fn information(person: &str, public_key: &[u8]) -> Result<Vec<u8>> {
    let subject = Purpose::person(person)?;
    let point = match public_key {
        [0x04, ..] if public_key.len() == 65 => public_key.to_vec(),
        _ => der::point_of(public_key)?,
    };
    Ok(csr::information(
        subject,
        &der::public_key_info(&point),
        &[],
        &Purpose::Operator.extended_key_usages(),
    ))
}

/// The request, `CERTIFICATE REQUEST` PEM, that `information` and the
/// keeper's `signature` over it make: ECDSA with SHA-256, DER, as X.509
/// carries one. The signature is verified under the key the information
/// holds before the request is handed back, so a keeper that signed another
/// form, or with another key, is told so here rather than by the authority.
///
/// # Errors
///
/// Where the two do not make a request whose signature verifies.
pub fn assemble(information: &[u8], signature: &[u8]) -> Result<String> {
    let der = csr::assemble(information, signature);
    csr::read(&der).map_err(|refused| {
        crate::ProvisionError::new(format!(
            "the keeper's signature makes no request: {refused}; it is ECDSA with SHA-256, \
             DER, by the key the request names"
        ))
    })?;
    Ok(pem::encode(REQUEST_LABEL, &der))
}

/// A fresh P-256 key and an operator's request for `person` signed by it.
///
/// # Errors
///
/// Where `person` is not a person's name, or the key cannot be made.
pub fn request(person: &str) -> Result<Request> {
    let key = KeyPair::generate()?;
    let information = information(person, &key.public_key_info())?;
    let request = assemble(&information, &key.sign(&information)?)?;
    Ok(Request {
        key: Zeroizing::new(key.pem().to_string()),
        request,
    })
}

/// The file a surface keeps an operator's key in, in the folder it names.
pub const KEY_FILE: &str = "operator.key";

/// The file the request is written to beside it.
pub const REQUEST_FILE: &str = "operator.csr";

/// Where [`request_into`] wrote the key and the request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Requested {
    /// The key, [`KEY_FILE`] in the folder: a private file.
    pub key: std::path::PathBuf,
    /// The request, [`REQUEST_FILE`] beside it.
    pub request: std::path::PathBuf,
}

/// A fresh key and an operator's request for `person` ([`request`]),
/// written into `folder` as [`KEY_FILE`] and [`REQUEST_FILE`], each a
/// private file ([`secret::private_file`]): the key's bytes leave this
/// process for its file alone. Files already there are never overwritten,
/// and where the request cannot be written the key is removed again, so a
/// refusal writes nothing.
///
/// # Errors
///
/// Where `person` is not a person's name, either file is there already, or
/// a file cannot be written; each in words.
pub fn request_into(person: &str, folder: &Path) -> Result<Requested> {
    let written = Requested {
        key: folder.join(KEY_FILE),
        request: folder.join(REQUEST_FILE),
    };
    if let Some(there) = [&written.key, &written.request]
        .into_iter()
        .find(|path| path.exists())
    {
        return Err(crate::ProvisionError::new(format!(
            "{} is there already; nothing is overwritten.",
            there.display()
        )));
    }
    let made = request(person)?;
    let failed = |path: &Path, failure: std::io::Error| {
        crate::ProvisionError::new(format!("writing {}: {failure}", path.display()))
    };
    secret::private_file::create(&written.key, made.key.as_bytes())
        .map_err(|failure| failed(&written.key, failure))?;
    if let Err(failure) = secret::private_file::create(&written.request, made.request.as_bytes()) {
        let _ = std::fs::remove_file(&written.key);
        return Err(failed(&written.request, failure));
    }
    Ok(written)
}

/// `text` — a chain an authority signed, or the anchors a surface trusts,
/// PEM and not secret — kept whole at `path` in place of what was there:
/// written beside it, synced and renamed over it
/// (`secret::private_file::replace_readable`), so a reader finds the old
/// file or the new one, never half of either. What the text must be is the
/// surface's to check first.
///
/// # Errors
///
/// Where the file cannot be written, naming it.
pub fn keep(path: &Path, text: &str) -> Result<()> {
    secret::private_file::replace_readable(path, text.as_bytes()).map_err(|failure| {
        crate::ProvisionError::new(format!("writing {}: {failure}", path.display()))
    })
}

/// The operator's certificate for the request `text`, PEM, as a chain: the
/// leaf, then the authority. Signed by the authority `[provision.operator]`
/// names in `settings` — `authority`, relative to `base`, the folder its
/// configuration file is in — valid from `now` for its `lifetime`.
///
/// # Errors
///
/// Where the text holds no request, the authority is not kept there, or the
/// request does not verify or asks for more than an operator's certificate
/// carries; each in words.
pub fn sign(settings: &Read, base: &Path, text: &str, now: i64) -> Result<String> {
    let blocks = pem::decode(REQUEST_LABEL, text)?;
    let der = blocks
        .first()
        .ok_or_else(|| crate::ProvisionError::new(format!("the text holds no {REQUEST_LABEL}")))?;
    let issuer = Issuer::kept(&base.join(settings.text("authority")))?;
    let lifetime = i64::try_from(settings.duration("lifetime").as_secs()).unwrap_or(i64::MAX / 2);
    issuer.sign(der, Purpose::Operator, now, now.saturating_add(lifetime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{CERTIFICATE, KEY};
    use crate::{Draft, Usage};
    use xcore::settings::Given;

    #[test]
    fn a_keepers_two_halves_make_a_request_from_either_form_of_its_public_key() {
        // The keeper: a key whose private half this side never reads.
        let keeper = KeyPair::generate().expect("a key");
        for public in [keeper.public_key_info(), keeper.point().to_vec()] {
            let information = information("erin@example.org", &public).expect("information");
            let signature = keeper.sign(&information).expect("signed");
            let text = assemble(&information, &signature).expect("a request");
            let der = pem::decode(REQUEST_LABEL, &text).expect("pem").remove(0);
            let read = csr::read(&der).expect("read");
            assert_eq!(read.public_key_info, keeper.public_key_info());
        }

        let information = information("erin@example.org", keeper.point()).expect("information");
        let fixed = keeper.sign_fixed(&information).expect("signed");
        let refused = assemble(&information, &fixed).expect_err("a fixed-width signature");
        assert!(refused.message.contains("DER"), "{refused}");
        let other = KeyPair::generate().expect("a key");
        let refused = assemble(&information, &other.sign(&information).expect("signed"))
            .expect_err("another key");
        assert!(refused.message.contains("keeper"), "{refused}");
        assert!(information_refused(&[0x04; 64]));
        assert!(information_refused(b"no key"));
    }

    #[test]
    fn a_request_is_written_into_a_folder_its_key_private_and_never_over_a_file() {
        let folder = std::env::temp_dir()
            .join(format!("xmip-provision-request-{}", std::process::id()))
            .join("phone");
        let _ = std::fs::remove_dir_all(folder.parent().expect("base"));
        let written = request_into("frank@example.org", &folder).expect("written");
        assert_eq!(written.key, folder.join(KEY_FILE));
        let key = std::fs::read_to_string(&written.key).expect("key");
        assert!(KeyPair::from_pem(&key).is_ok(), "the key is a PEM key");
        let text = std::fs::read_to_string(&written.request).expect("request");
        let der = pem::decode(REQUEST_LABEL, &text).expect("pem").remove(0);
        let public = KeyPair::from_pem(&key).expect("key").public_key_info();
        assert_eq!(csr::read(&der).expect("read").public_key_info, public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(&written.key).expect("metadata").mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        #[cfg(windows)]
        assert_eq!(
            secret::private_file::described(&written.key).expect("described"),
            secret::private_file::owner_only(false).expect("owner only")
        );

        let refused = request_into("frank@example.org", &folder).expect_err("there");
        assert!(
            refused.message.contains("nothing is overwritten"),
            "{refused}"
        );
        assert_eq!(std::fs::read_to_string(&written.key).expect("key"), key);
        let other = folder.with_file_name("other");
        assert!(request_into("CN=frank", &other).is_err());
        assert!(!other.join(KEY_FILE).exists(), "a refusal writes nothing");
        let _ = std::fs::remove_dir_all(folder.parent().expect("base"));
    }

    fn information_refused(public: &[u8]) -> bool {
        information("erin@example.org", public).is_err()
    }

    #[test]
    fn a_request_is_signed_by_the_authority_the_operator_table_names_for_its_lifetime() {
        let base =
            std::env::temp_dir().join(format!("xmip-provision-operator-{}", std::process::id()));
        let place = base.join("ca");
        std::fs::create_dir_all(&place).expect("made");
        let key = KeyPair::generate().expect("a key");
        let der = Draft {
            subject: "cluster authority",
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_900_000_000,
            usage: Usage::Authority,
        }
        .sign("cluster authority", &key)
        .expect("signed");
        std::fs::write(place.join(CERTIFICATE), pem::encode("CERTIFICATE", &der)).expect("pem");
        std::fs::write(place.join(KEY), key.pem().as_bytes()).expect("key");

        let given = [
            ("authority".to_string(), Given::Text("ca".to_string())),
            ("lifetime".to_string(), Given::Text("1h".to_string())),
        ];
        let table = crate::read("operator", &given, &[]).expect("read");
        let asked = request("dave@example.org").expect("a request");
        let chain = sign(&table.settings, &base, &asked.request, 1_800_000_000).expect("signed");
        let leaf = pem::decode("CERTIFICATE", &chain).expect("pem").remove(0);
        assert_eq!(
            crate::validity(&leaf).expect("validity"),
            (1_800_000_000, 1_800_003_600)
        );

        let refused = sign(&table.settings, &base, "no request", 0).expect_err("no request");
        assert!(refused.message.contains(REQUEST_LABEL), "{refused}");
        let refused = sign(&table.settings, &place, &asked.request, 0).expect_err("elsewhere");
        assert!(
            refused.message.contains("no authority is kept"),
            "{refused}"
        );
        assert!(request("CN=dave").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
