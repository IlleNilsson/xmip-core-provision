//! A person's certificate (ADR-0034, amendment 2026-10-15): the surface
//! makes its own key and a request naming the person, and the cluster's
//! authority signs it once the request is approved out of band — by whoever
//! may reach the authority's key and runs the signing.
//!
//! Both halves are here, once: [`request`] for a surface that holds its key
//! as a PEM file, [`information`] and [`assemble`] for one whose key never
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
