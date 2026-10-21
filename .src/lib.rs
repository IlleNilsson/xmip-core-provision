#![forbid(unsafe_code)]

//! Certificate provisioning (ADR-0034): where a node's certificate comes
//! from, kept apart from how it is used.
//!
//! Using a certificate — mutual TLS on Receive and Send, between nodes — is
//! `xmip-core-library-tls`, the same everywhere. Obtaining one is plural, and
//! a node's configuration chooses: a [`Source`] obtains a certificate for an
//! [`Order`] — a [`Purpose`] and the names it is for — and a [`Provisioner`]
//! keeps what it obtained and asks again at two thirds of its life. Each
//! source is a technology mounted beside this source (ADR-0049): `acme`
//! against any ACME directory, `internal-ca`, the cluster's own authority,
//! and `self-signed` for a lone offline node; an operator's own files are
//! read here, by [`Files`]. A provider may ship another by implementing
//! [`Source`].
//!
//! **Three purposes.** A Receive Location presents what a Party reaches, and
//! needs server authentication alone; between nodes each end presents a
//! certificate, so a node's needs server and client authentication both
//! (ADR-0063 clause 1). Let's Encrypt has issued server authentication alone
//! since 2026-07-08, so it can serve the first purpose and never the second
//! (ADR-0033, amendment 2026-10-13). A person's surface — the phone first —
//! presents an operator's certificate to a node's operate listener: client
//! authentication alone, its subject the person ([`Purpose::Operator`]). It
//! is never obtained: the surface makes its own key and a request
//! ([`operator`]), and the cluster's authority signs it ([`Issuer`]) once it
//! is approved out of band (ADR-0034, amendment 2026-10-15).
//!
//! **Never a fixed lifetime.** A certificate is renewed at two thirds of the
//! life it was issued with, read from the certificate itself
//! ([`Provisioned::renew_at`]): public lifetimes are shortening (CA/Browser
//! Forum ballot SC-081), and a cluster's authority issues whatever its
//! configuration says.
//!
//! **Written once.** The P-256 key ([`KeyPair`]), the CSR ([`csr`]) and the
//! certificate ([`Draft`]) are written here over `xmip-core-library-asn1` and
//! signed with aws-lc-rs, the crypto the TLS library already builds, so the
//! technologies that request, issue or sign hold none of it (ADR-0044); and
//! so is what an authority signs ([`Issuer`]), which a surface reaches
//! through the runtime's export where a technology may not be linked.
//!
//! **A web host on this machine** ([`host`]). An authority kept in a
//! folder, made there where none is as the cluster's own is
//! ([`Issuer::kept_or_made`]), issues the host a certificate for the name a
//! browser reaches it by — an IP address written as one (RFC 5280
//! `iPAddress`) — and signs the tester's operator request, so the
//! Playground's web GUI is acted in with an operator certificate (ADR-0009,
//! amendment 2026-10-21).
//!
//! **A node put on a machine of its own** ([`node`]). The same kept
//! authority, the cluster's, issues a node a fresh key and a certificate for
//! server and client authentication, for every name it is reached by, into
//! a folder holding its anchors too: what an environment template gives a
//! node machine (ADR-0015, amendment 2026-10-21).

mod certificate;
mod configuration;
pub mod csr;
mod der;
mod error;
mod files;
pub mod host;
pub mod issuer;
mod key;
pub mod node;
pub mod operator;
pub mod pem;
mod provisioned;
mod provisioner;
mod purpose;
mod source;
mod usage;
mod validity;

pub use certificate::{Draft, Usage};
pub use configuration::{
    Configured, FILES, NAMES, OPERATOR, OPERATOR_LIFETIME, SOURCE, names, read,
};
pub use error::ProvisionError;
pub use files::Files;
pub use issuer::Issuer;
pub use key::{KeyPair, sha256, verify, verify_fixed};
pub use provisioned::Provisioned;
pub use provisioner::Provisioner;
pub use purpose::Purpose;
pub use source::{Order, Source};
pub use usage::serves;
pub use validity::validity;

/// The result of provisioning.
pub type Result<T> = core::result::Result<T, ProvisionError>;

/// Seconds since the epoch, now: the clock a provisioner renews by.
#[must_use]
pub fn now() -> i64 {
    codec::civil::unix_seconds(std::time::SystemTime::now())
}
