//! An authority's key and certificate, and what it signs: a certificate for
//! a key and a purpose, or for a request its purpose admits. Written once,
//! so the cluster's authority (`internal-ca`) and every surface that signs a
//! person's request (ADR-0034, amendment 2026-10-15) sign the same way.

use std::io::ErrorKind;
use std::path::Path;

use secret::private_file;

use crate::crl::Reason;
use crate::parsed::Parsed;
use crate::register::{Record, Register};
use crate::{Draft, KeyPair, ProvisionError, Purpose, Result, Usage, csr, pem};

/// The file an authority's key is kept in, inside its place.
pub const KEY: &str = "authority.key";
/// The file its certificate is kept in: the anchor its cluster trusts.
pub const CERTIFICATE: &str = "authority.pem";

/// An authority: what it signs with and what it signs as.
pub struct Issuer {
    /// Its certificate's subject, `Name` DER: what it signs as.
    name: Vec<u8>,
    key: KeyPair,
    certificate: String,
    /// Its register, where it is kept in a folder: every certificate it
    /// signs is recorded there.
    register: Option<Register>,
    /// The address it publishes its list and certificate at, which a leaf
    /// it signs names.
    published: Option<String>,
}

impl core::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Issuer(private key not shown)")
    }
}

impl Issuer {
    /// The authority whose certificate is `certificate`, PEM, and whose key
    /// is `key`.
    ///
    /// # Errors
    ///
    /// Where the PEM holds no certificate.
    pub fn new(certificate: String, key: KeyPair) -> Result<Self> {
        let blocks = pem::decode("CERTIFICATE", &certificate)?;
        let first = blocks
            .first()
            .ok_or_else(|| ProvisionError::new("the authority's PEM holds no CERTIFICATE"))?;
        Ok(Self {
            name: Parsed::read(first)?.subject,
            key,
            certificate,
            register: None,
            published: None,
        })
    }

    /// The authority kept in `place`: [`KEY`] and [`CERTIFICATE`]. Nothing
    /// is made where nothing is kept.
    ///
    /// # Errors
    ///
    /// Where either file cannot be read, or they do not hold an authority.
    pub fn kept(place: &Path) -> Result<Self> {
        let read = |file: &str| {
            let path = place.join(file);
            std::fs::read_to_string(&path).map_err(|failure| {
                ProvisionError::new(format!(
                    "no authority is kept at {}: {failure}",
                    path.display()
                ))
            })
        };
        let key = zeroize::Zeroizing::new(read(KEY)?);
        let mut kept = Self::new(read(CERTIFICATE)?, KeyPair::from_pem(&key)?)?;
        let register = Register::at(place);
        kept.published = register.published()?;
        kept.register = Some(register);
        Ok(kept)
    }

    /// A new authority called `name`, a fresh key and its certificate
    /// signed by itself, valid from `now` for `lifetime` seconds.
    ///
    /// # Errors
    ///
    /// Where a key cannot be made or the certificate signed.
    pub fn made(name: &str, now: i64, lifetime: i64) -> Result<Self> {
        let key = KeyPair::generate()?;
        Self::new(self_signed(name, &key, now, lifetime)?, key)
    }

    /// The authority kept in `place`, or a new one called `name` made and
    /// kept there where it keeps none: the cluster's own (`internal-ca`) and
    /// a web host's on this machine (`host`) alike.
    ///
    /// Both files are private files (`secret::private_file`) in a private
    /// directory, and several makers may race for one place: two clusters'
    /// first runs, or a run and a web host starting together. The key is
    /// written first and never over one, so exactly one maker's key is kept
    /// and every other reads it. Then whoever holds that key makes sure the
    /// certificate beside it is for it: one that is, is kept; none is signed
    /// from the key and written never over one, a maker that lost that write
    /// reading the winner's; one for another key, which a crash under the
    /// earlier order left, is replaced. Nobody waits for anybody, since every
    /// maker can sign for the kept key. What every maker returns is read
    /// back from the place, never its own in memory, so all of them hold the
    /// same pair. What a crash left between writing a file and naming it is
    /// swept first (`private_file::sweep`); a write another maker's sweep
    /// took is tried again.
    ///
    /// # Errors
    ///
    /// Where the files cannot be read or written, or do not hold an
    /// authority.
    pub fn kept_or_made(place: &Path, name: &str, now: i64, lifetime: i64) -> Result<Self> {
        private_file::sweep(place).map_err(|failure| {
            ProvisionError::new(format!("sweeping {}: {failure}", place.display()))
        })?;
        private_file::directory(place).map_err(|failure| failed(place, &failure))?;
        let key = key_kept(place)?;
        certificate_kept(place, name, &key, (now, lifetime))?;
        Self::kept(place)
    }

    /// Its certificate, PEM: the anchor what it signs reaches.
    #[must_use]
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// Its key, to be kept.
    #[must_use]
    pub const fn key(&self) -> &KeyPair {
        &self.key
    }

    /// Its register, where it is kept in a folder.
    #[must_use]
    pub const fn register(&self) -> Option<&Register> {
        self.register.as_ref()
    }

    /// The register of an authority kept in a folder, or a refusal saying
    /// it is held in memory alone.
    fn kept_register(&self) -> Result<&Register> {
        self.register
            .as_ref()
            .ok_or_else(|| ProvisionError::new("an authority held in memory keeps no register"))
    }

    /// Revoke the certificate it signed whose serial is `serial` for
    /// `reason` at `now`, its list made again at once
    /// (`Register::revoke`).
    ///
    /// # Errors
    ///
    /// Where it keeps no register, signed no such certificate, or revoked
    /// it already; each in words.
    pub fn revoke(&self, serial: &str, reason: Reason, now: i64) -> Result<Record> {
        self.kept_register()?
            .revoke((&self.name, &self.key), serial, reason, now)
    }

    /// The revocation list it publishes now, DER (`Register::list`).
    ///
    /// # Errors
    ///
    /// Where it keeps no register, or the list cannot be made.
    pub fn revocation_list(&self, now: i64) -> Result<Vec<u8>> {
        self.kept_register()?.list((&self.name, &self.key), now)
    }

    /// A certificate for `public_key_info`, `subject` its common name and
    /// `names` its DNS names, for `purpose`, from `not_before` to
    /// `not_after`, as a chain: the leaf, then the authority.
    ///
    /// # Errors
    ///
    /// Where signing fails.
    pub fn issue(
        &self,
        public_key_info: &[u8],
        subject: &str,
        names: &[String],
        purpose: Purpose,
        not_before: i64,
        not_after: i64,
    ) -> Result<String> {
        let der = Draft {
            subject,
            names,
            public_key_info,
            not_before,
            not_after,
            usage: Usage::Leaf(purpose),
        }
        .sign_published(&self.name, &self.key, self.published.as_deref())?;
        if let Some(register) = &self.register {
            register.record(&der)?;
        }
        Ok(format!(
            "{}{}",
            pem::encode("CERTIFICATE", &der),
            self.certificate
        ))
    }

    /// A certificate for what the request `der` asks, once its signature
    /// verifies and `purpose` admits it (`Purpose::admit`): its subject the
    /// person an operator's request names, else its first DNS name. What
    /// the certificate may do is the purpose's, never the request's.
    ///
    /// # Errors
    ///
    /// Where the request does not read or verify, asks for more than the
    /// purpose allows, or signing fails; each in words.
    pub fn sign(
        &self,
        der: &[u8],
        purpose: Purpose,
        not_before: i64,
        not_after: i64,
    ) -> Result<String> {
        let requested = csr::read(der)?;
        purpose.admit(&requested)?;
        let subject = if purpose.names_hosts() {
            requested.names.first().map(String::as_str)
        } else {
            requested.subject.first().map(|(_, person)| person.as_str())
        }
        .ok_or_else(|| ProvisionError::new("the request names no subject"))?;
        self.issue(
            &requested.public_key_info,
            subject,
            &requested.names,
            purpose,
            not_before,
            not_after,
        )
    }
}

/// How many times a maker writes a file of the place again, where another
/// maker's sweep took the write or another's file landed first.
const TRIES: usize = 5;

/// `failure` at `path`, in words.
fn failed(path: &Path, failure: &std::io::Error) -> ProvisionError {
    ProvisionError::new(format!("{}: {failure}", path.display()))
}

/// The certificate of an authority called `name` whose key is `key`,
/// signed by itself, valid from `now` for `lifetime` seconds; PEM.
fn self_signed(name: &str, key: &KeyPair, now: i64, lifetime: i64) -> Result<String> {
    let der = Draft {
        subject: name,
        names: &[],
        public_key_info: &key.public_key_info(),
        not_before: now,
        not_after: now.saturating_add(lifetime),
        usage: Usage::Authority,
    }
    .sign(name, key)?;
    Ok(pem::encode("CERTIFICATE", &der))
}

/// The key kept in `place`: read where one is, else a fresh one written
/// never over one, and read where another maker's landed first.
fn key_kept(place: &Path) -> Result<KeyPair> {
    let path = place.join(KEY);
    let mut last = None;
    for _ in 0..TRIES {
        match std::fs::read_to_string(&path) {
            Ok(text) => return KeyPair::from_pem(&zeroize::Zeroizing::new(text)),
            Err(failure) if failure.kind() != ErrorKind::NotFound => {
                return Err(failed(&path, &failure));
            }
            Err(_) => {}
        }
        let fresh = KeyPair::generate()?;
        match private_file::create(&path, fresh.pem().as_bytes()) {
            Ok(()) => return Ok(fresh),
            Err(failure) => last = Some(failure),
        }
    }
    Err(last.map_or_else(
        || ProvisionError::new(format!("{}: not kept", path.display())),
        |failure| failed(&path, &failure),
    ))
}

/// The certificate kept in `place` made one for `key`: kept where it is,
/// signed as `name` and written never over one where none is, and written
/// in place of one for another key.
fn certificate_kept(
    place: &Path,
    name: &str,
    key: &KeyPair,
    (now, lifetime): (i64, i64),
) -> Result<()> {
    let path = place.join(CERTIFICATE);
    let public = key.public_key_info();
    let mut last = None;
    for _ in 0..TRIES {
        let other = match std::fs::read_to_string(&path) {
            Ok(text) if for_key(&text, &public) => return Ok(()),
            Ok(_) => true,
            Err(failure) if failure.kind() == ErrorKind::NotFound => false,
            Err(failure) => return Err(failed(&path, &failure)),
        };
        let signed = self_signed(name, key, now, lifetime)?;
        let written = if other {
            private_file::replace(&path, signed.as_bytes())
        } else {
            private_file::create(&path, signed.as_bytes())
        };
        match written {
            Ok(()) => return Ok(()),
            Err(failure) => last = Some(failure),
        }
    }
    Err(last.map_or_else(
        || ProvisionError::new(format!("{}: not kept", path.display())),
        |failure| failed(&path, &failure),
    ))
}

/// Whether the first certificate of `text`, PEM, is for the key whose
/// public key information is `public`; one that does not read is not.
fn for_key(text: &str, public: &[u8]) -> bool {
    pem::decode("CERTIFICATE", text)
        .ok()
        .and_then(|blocks| blocks.into_iter().next())
        .and_then(|der| Parsed::read(&der).ok())
        .is_some_and(|parsed| parsed.public_key_info == public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{
        BASIC_CONSTRAINTS, CLIENT_AUTH, COMMON_NAME, EXTENSION_REQUEST, SERVER_AUTH, SET,
        SUBJECT_ALT_NAME, extension, name, oid, read_name, sequence,
    };
    use crate::operator;
    use asn1::{INTEGER, SEQUENCE, tlv};

    fn authority() -> Issuer {
        let key = KeyPair::generate().expect("a key");
        let der = Draft {
            subject: "test cluster authority",
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_900_000_000,
            usage: Usage::Authority,
        }
        .sign("test cluster authority", &key)
        .expect("signed");
        Issuer::new(pem::encode("CERTIFICATE", &der), key).expect("an issuer")
    }

    fn der_of(text: &str) -> Vec<u8> {
        pem::decode(operator::REQUEST_LABEL, text)
            .expect("pem")
            .remove(0)
    }

    fn leaf(chain: &str) -> Vec<u8> {
        pem::decode("CERTIFICATE", chain).expect("pem").remove(0)
    }

    fn signs(issuer: &Issuer, der: &[u8], purpose: Purpose) -> Result<String> {
        issuer.sign(der, purpose, 1_800_000_000, 1_800_086_400)
    }

    #[test]
    fn an_operator_request_is_signed_for_client_authentication_alone_naming_the_person() {
        let issuer = authority();
        let request = operator::request("alice@example.org").expect("a request");
        let chain = signs(&issuer, &der_of(&request.request), Purpose::Operator).expect("signed");
        let leaf = leaf(&chain);

        assert!(chain.ends_with(issuer.certificate()));
        assert!(crate::serves(&leaf, Purpose::Operator).expect("read"));
        assert!(!crate::serves(&leaf, Purpose::Receive).expect("read"));
        assert!(!crate::serves(&leaf, Purpose::Node).expect("read"));
        assert_eq!(
            read_name(&Parsed::read(&leaf).expect("read").subject).expect("name"),
            [(COMMON_NAME.to_vec(), "alice@example.org".to_string())]
        );
        let alternative = oid(SUBJECT_ALT_NAME);
        assert!(!leaf.windows(alternative.len()).any(|at| at == alternative));
        assert_eq!(crate::validity(&leaf).expect("validity").1, 1_800_086_400);
        assert!(KeyPair::from_pem(&request.key).is_ok());
    }

    #[test]
    fn a_request_asking_more_than_an_operator_may_is_refused_in_words() {
        let issuer = authority();
        let key = KeyPair::generate().expect("a key");
        let pki = key.public_key_info();
        let signed = |information: Vec<u8>| {
            let signature = key.sign(&information).expect("signed");
            csr::assemble(&information, &signature)
        };

        let both = [SERVER_AUTH, CLIENT_AUTH];
        let server = signed(csr::information("bob", &pki, &[], &both));
        let refused = signs(&issuer, &server, Purpose::Operator).expect_err("server");
        assert!(refused.message.contains("extended key usage"), "{refused}");

        let host = signed(csr::information("bob", &pki, &["h.example".into()], &[]));
        let refused = signs(&issuer, &host, Purpose::Operator).expect_err("a host");
        assert!(refused.message.contains("alternative names"), "{refused}");

        let asked = extension(
            BASIC_CONSTRAINTS,
            true,
            &sequence(&[&tlv(asn1::BOOLEAN, &[0xff])]),
        );
        let attribute = sequence(&[&oid(EXTENSION_REQUEST), &tlv(SET, &tlv(SEQUENCE, &asked))]);
        let information = sequence(&[
            &tlv(INTEGER, &[0]),
            &name("bob"),
            &pki,
            &tlv(asn1::context(0, true), &attribute),
        ]);
        let refused = signs(&issuer, &signed(information), Purpose::Operator).expect_err("ca");
        assert!(refused.message.contains("authority"), "{refused}");

        let comma = signed(csr::information("a,b", &pki, &[], &[]));
        let refused = signs(&issuer, &comma, Purpose::Operator).expect_err("a name");
        assert!(refused.message.contains(','), "{refused}");
    }

    #[test]
    fn a_request_whose_signature_does_not_verify_or_is_for_another_purpose_is_refused() {
        let issuer = authority();
        let request = operator::request("carol").expect("a request");
        let mut der = der_of(&request.request);
        let last = der.len() - 1;
        der[last] ^= 0x01;
        let refused = signs(&issuer, &der, Purpose::Operator).expect_err("tampered");
        assert!(refused.message.contains("does not verify"), "{refused}");

        let operator = der_of(&request.request);
        let refused = signs(&issuer, &operator, Purpose::Node).expect_err("no names");
        assert!(refused.message.contains("no DNS name"), "{refused}");
        let node = csr::write(&KeyPair::generate().expect("a key"), &["n.example".into()])
            .expect("written");
        assert!(signs(&issuer, &node, Purpose::Node).is_ok());
        assert!(signs(&issuer, &node, Purpose::Operator).is_err());
    }

    #[test]
    fn an_authority_not_kept_is_refused_and_one_kept_is_read() {
        let place =
            std::env::temp_dir().join(format!("xmip-provision-issuer-{}", std::process::id()));
        let refused = Issuer::kept(&place).expect_err("nothing kept");
        assert!(
            refused.message.contains("no authority is kept"),
            "{refused}"
        );
        let issuer = authority();
        std::fs::create_dir_all(&place).expect("made");
        std::fs::write(place.join(KEY), issuer.key().pem().as_bytes()).expect("key");
        std::fs::write(place.join(CERTIFICATE), issuer.certificate()).expect("certificate");
        let kept = Issuer::kept(&place).expect("kept");
        assert_eq!(kept.certificate(), issuer.certificate());
        let _ = std::fs::remove_dir_all(&place);
    }

    fn place(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("xmip-provision-kept-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path.join("authority")
    }

    /// Whether the certificate kept in `place` is for the key kept beside it.
    fn matching(place: &Path) -> bool {
        let key = std::fs::read_to_string(place.join(KEY)).expect("key");
        let public = KeyPair::from_pem(&key).expect("a key").public_key_info();
        let text = std::fs::read_to_string(place.join(CERTIFICATE)).expect("certificate");
        let der = pem::decode("CERTIFICATE", &text).expect("pem").remove(0);
        der.windows(public.len())
            .any(|window| window == public.as_slice())
    }

    #[test]
    fn an_authority_is_made_and_kept_privately_and_read_back_as_it_was() {
        let place = place("kept");
        let made = Issuer::kept_or_made(&place, "cluster", 1_800_000_000, 3600).expect("made");
        let again = Issuer::kept_or_made(&place, "cluster", 1_800_000_000, 3600).expect("read");
        assert_eq!(made.certificate(), again.certificate());
        assert!(matching(&place));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let bits = |path: &Path| std::fs::metadata(path).expect("metadata").mode() & 0o777;
            assert_eq!(bits(&place.join(KEY)), 0o600);
            assert_eq!(bits(&place), 0o700);
        }
        #[cfg(windows)]
        {
            let described = |path: &Path| private_file::described(path).expect("described");
            let owner = |directory| private_file::owner_only(directory).expect("owner only");
            assert_eq!(described(&place.join(KEY)), owner(false));
            assert_eq!(described(&place), owner(true));
        }
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn a_crash_between_the_certificate_and_the_key_leaves_a_matching_pair_next_time() {
        let place = place("crash");
        let other = Issuer::made("before the crash", 1_800_000_000, 3600).expect("made");
        private_file::replace(&place.join(CERTIFICATE), other.certificate().as_bytes())
            .expect("the certificate a crash left");
        let made = Issuer::kept_or_made(&place, "cluster", 1_800_000_000, 3600).expect("made");
        assert_ne!(made.certificate(), other.certificate());
        assert!(matching(&place), "the certificate is for the key beside it");
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn a_key_kept_with_no_certificate_is_given_one_for_it() {
        let place = place("lone-key");
        let key = KeyPair::generate().expect("a key");
        private_file::create(&place.join(KEY), key.pem().as_bytes()).expect("the lone key");
        let kept = Issuer::kept_or_made(&place, "cluster", 1_800_000_000, 3600).expect("kept");
        assert_eq!(kept.key().public_key_info(), key.public_key_info());
        assert!(matching(&place), "the certificate is for the key kept");
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn makers_racing_for_one_place_all_hold_the_pair_kept_and_everything_issued_verifies() {
        const MAKERS: usize = 8;
        let place = place("race");
        let barrier = std::sync::Barrier::new(MAKERS);
        let (start, at) = (&barrier, place.as_path());
        let made: Vec<Issuer> = std::thread::scope(|scope| {
            let racing: Vec<_> = (0..MAKERS)
                .map(|_| {
                    scope.spawn(move || {
                        start.wait();
                        Issuer::kept_or_made(at, "cluster", 1_800_000_000, 3600)
                    })
                })
                .collect();
            racing
                .into_iter()
                .map(|maker| maker.join().expect("joined").expect("kept or made"))
                .collect()
        });
        let anchor = std::fs::read_to_string(place.join(CERTIFICATE)).expect("the anchor");
        assert!(matching(&place), "the certificate is for the key beside it");
        let parsed = Parsed::first(&anchor).expect("the anchor reads");
        for issuer in &made {
            assert_eq!(issuer.certificate(), anchor, "each holds the pair on disk");
            let leaf_key = KeyPair::generate().expect("a key");
            let chain = issuer
                .issue(
                    &leaf_key.public_key_info(),
                    "node",
                    &["node".to_string()],
                    Purpose::Node,
                    1_800_000_000,
                    1_800_003_600,
                )
                .expect("issued");
            let issued = Parsed::read(&leaf(&chain)).expect("the leaf reads");
            assert!(issued.signed_by(&parsed).expect("verified"), "it verifies");
        }
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }
}
