//! A person's certificate (ADR-0034, amendment 2026-10-15): the surface
//! makes its own key and a request naming the person, and the cluster's
//! authority signs it once the request is approved out of band — by whoever
//! may reach the authority's key and runs the signing.
//!
//! Both halves are here, once: [`request`] for a surface that holds its key
//! as a PEM file, [`information`] for one whose key never leaves its keeper
//! (a phone's keystore signs the bytes and [`crate::csr::assemble`] makes
//! the request), and [`sign`] for the authority's side, held to
//! [`Purpose::Operator`]'s rules and to `[provision.operator]`.

use std::path::Path;

use xcore::settings::Read;
use zeroize::Zeroizing;

use crate::{Issuer, KeyPair, Purpose, Result, csr, pem};

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

/// What an operator's request for `person` signs, over the key
/// `public_key_info` holds: the person as its one common name, and client
/// authentication as the one usage asked.
///
/// # Errors
///
/// Where `person` is not a person's name (`Purpose::person`).
pub fn information(person: &str, public_key_info: &[u8]) -> Result<Vec<u8>> {
    Ok(csr::information(
        Purpose::person(person)?,
        public_key_info,
        &[],
        &Purpose::Operator.extended_key_usages(),
    ))
}

/// A fresh P-256 key and an operator's request for `person` signed by it.
///
/// # Errors
///
/// Where `person` is not a person's name, or the key cannot be made.
pub fn request(person: &str) -> Result<Request> {
    let key = KeyPair::generate()?;
    let information = information(person, &key.public_key_info())?;
    let der = csr::assemble(&information, &key.sign(&information)?);
    Ok(Request {
        key: Zeroizing::new(key.pem().to_string()),
        request: pem::encode(REQUEST_LABEL, &der),
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
