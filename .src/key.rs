//! A P-256 key pair: what every certificate this capability provisions is
//! for, what an authority signs with and what an ACME account is.
//!
//! P-256 because every TLS peer, every public authority and every ACME
//! server takes it, and RFC 8555 names ES256 among what a server must
//! accept. The key is kept as PKCS #8, overwritten when it is dropped.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, UnparsedPublicKey,
};
use zeroize::Zeroizing;

use crate::{ProvisionError, Result, der, pem};

/// The PEM label PKCS #8 is written under.
const LABEL: &str = "PRIVATE KEY";

/// One P-256 key pair.
pub struct KeyPair {
    pkcs8: Zeroizing<Vec<u8>>,
    /// Signs as X.509 and PKCS #10 write a signature: DER `r` and `s`.
    asn1: EcdsaKeyPair,
    /// Signs as JWS writes one: `r` and `s`, 32 bytes each (RFC 7518).
    fixed: EcdsaKeyPair,
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPair(P-256, private half not shown)")
    }
}

impl KeyPair {
    /// A fresh key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Where the random source fails.
    pub fn generate() -> Result<Self> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .map_err(|_| ProvisionError::new("generating a P-256 key failed"))?;
        Self::from_pkcs8(document.as_ref())
    }

    /// The key PKCS #8 holds.
    ///
    /// # Errors
    ///
    /// Where the bytes are not a P-256 key in PKCS #8.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let refused = |failure: aws_lc_rs::error::KeyRejected| {
            ProvisionError::new(format!("the key is not a P-256 key in PKCS #8: {failure}"))
        };
        Ok(Self {
            pkcs8: Zeroizing::new(bytes.to_vec()),
            asn1: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes)
                .map_err(refused)?,
            fixed: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes)
                .map_err(refused)?,
        })
    }

    /// The key a `PRIVATE KEY` PEM block holds.
    ///
    /// # Errors
    ///
    /// Where the text holds no such block, or its key is not P-256.
    pub fn from_pem(text: &str) -> Result<Self> {
        let blocks = Zeroizing::new(pem::decode(LABEL, text)?);
        let first = blocks
            .first()
            .ok_or_else(|| ProvisionError::new("the PEM held no PRIVATE KEY"))?;
        Self::from_pkcs8(first)
    }

    /// The key as a `PRIVATE KEY` PEM block, which the TLS library reads.
    #[must_use]
    pub fn pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem::encode(LABEL, &self.pkcs8))
    }

    /// The public point, uncompressed: `0x04`, then `x` and `y`.
    #[must_use]
    pub fn point(&self) -> &[u8] {
        self.asn1.public_key().as_ref()
    }

    /// The public key as X.509's `SubjectPublicKeyInfo`, DER.
    #[must_use]
    pub fn public_key_info(&self) -> Vec<u8> {
        der::public_key_info(self.point())
    }

    /// An ECDSA signature over `message` with SHA-256, DER, as X.509 and
    /// PKCS #10 carry it.
    ///
    /// # Errors
    ///
    /// Where the random source fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.asn1
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| ProvisionError::new("signing failed"))
    }

    /// An ECDSA signature over `message` with SHA-256, `r` and `s` fixed
    /// width, as JWS's ES256 carries it.
    ///
    /// # Errors
    ///
    /// Where the random source fails.
    pub fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.fixed
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| ProvisionError::new("signing failed"))
    }
}

/// Whether `signature`, DER, is `point`'s over `message`.
#[must_use]
pub fn verify(point: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(message, signature)
        .is_ok()
}

/// Whether `signature`, `r` and `s` fixed width, is `point`'s over
/// `message`.
#[must_use]
pub fn verify_fixed(point: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(message, signature)
        .is_ok()
}

/// SHA-256 of `bytes`: a JWK thumbprint, a dns-01 record's value.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_signs_both_ways_and_survives_its_pem() {
        let key = KeyPair::generate().expect("a key");
        let again = KeyPair::from_pem(&key.pem()).expect("read back");
        assert_eq!(key.point(), again.point());
        assert_eq!(key.point().len(), 65);

        let signature = again.sign(b"signed").expect("signs");
        assert!(verify(key.point(), b"signed", &signature));
        assert!(!verify(key.point(), b"other", &signature));
        let fixed = again.sign_fixed(b"signed").expect("signs");
        assert_eq!(fixed.len(), 64);
        assert!(verify_fixed(key.point(), b"signed", &fixed));
        assert!(format!("{key:?}").contains("not shown"));
    }

    #[test]
    fn a_pem_without_a_key_is_refused_in_words() {
        let refused = KeyPair::from_pem("nothing").expect_err("no key");
        assert!(refused.message.contains("PRIVATE KEY"), "{refused}");
    }
}
