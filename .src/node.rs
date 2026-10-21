//! A node's certificate from the cluster's own authority, issued on the
//! operator's machine before the node is put on a machine of its own
//! (ADR-0015, amendment 2026-10-21): what an environment template gives a
//! node machine, since `xmip-service` starts no provisioner yet (open
//! problem 27) and a node's certificate comes from Xmip's internal CA,
//! never the platform's.
//!
//! The authority is kept, or made where none is kept, as the cluster's own
//! is ([`Issuer::kept_or_made`]); the node is given a fresh key and a
//! certificate for server and client authentication both ([`Purpose::Node`]:
//! mutual TLS between nodes, ADR-0063 clause 1), its subject the node and
//! its names every name the node is reached by — its own and its cluster's,
//! each as it resolves. The folder it is written into holds what the node's
//! `[operate]` names, so it is shipped whole: [`CERTIFICATE_FILE`],
//! [`KEY_FILE`] and [`ANCHORS_FILE`], the authority's certificate.

use std::path::Path;
use std::time::Duration;

use crate::host::{AUTHORITY_LIFETIME, Fresh, Issued, seconds};
use crate::issuer::CERTIFICATE;
use crate::{Issuer, ProvisionError, Purpose, Result};

/// How long a node's certificate is valid: ninety days. The assistant's
/// draft of 2026-10-21, for the owner to strike.
pub const NODE_LIFETIME: Duration = Duration::from_hours(90 * 24);

/// The file a node's certificate chain is written to, leaf first.
pub const CERTIFICATE_FILE: &str = "node.pem";

/// The file its private key is written to beside it.
pub const KEY_FILE: &str = "node.key";

/// The file the authority's certificate is written to beside them: what
/// the node trusts a caller's certificate to reach.
pub const ANCHORS_FILE: &str = "anchors.pem";

/// The authority kept in `authority` — made and kept there, called `name`,
/// where none is — and a fresh key and certificate for the node `node`
/// under it, for every one of `names` and the node's own, valid from `now`,
/// written into `folder` as [`CERTIFICATE_FILE`], [`KEY_FILE`] and
/// [`ANCHORS_FILE`], each a private file in place of what was there.
///
/// # Errors
///
/// Where the authority cannot be read or made, `node` is empty, or a file
/// cannot be written; each in words.
pub fn issue_into(
    authority: &Path,
    name: &str,
    node: &str,
    names: &[String],
    folder: &Path,
    now: i64,
) -> Result<Issued> {
    if node.trim().is_empty() {
        return Err(ProvisionError::new(
            "a node's certificate names the node it is issued to",
        ));
    }
    let authorized = Issuer::kept_or_made(authority, name, now, seconds(AUTHORITY_LIFETIME))?;
    let mut every = vec![node.to_string()];
    for one in names
        .iter()
        .map(|one| one.trim())
        .filter(|one| !one.is_empty())
    {
        if !every.iter().any(|held| held == one) {
            every.push(one.to_string());
        }
    }
    std::fs::create_dir_all(folder)
        .map_err(|failure| ProvisionError::new(format!("{}: {failure}", folder.display())))?;
    let written = Issued {
        certificate: folder.join(CERTIFICATE_FILE),
        key: folder.join(KEY_FILE),
        anchor: folder.join(ANCHORS_FILE),
    };
    let fresh = Fresh {
        subject: node,
        names: &every,
        purpose: Purpose::Node,
        lifetime: NODE_LIFETIME,
    };
    fresh.issued_into(&authorized, now, &written)?;
    let anchor = std::fs::read(authority.join(CERTIFICATE)).map_err(|failure| {
        ProvisionError::new(format!("reading the authority's certificate: {failure}"))
    })?;
    secret::private_file::replace(&written.anchor, &anchor).map_err(|failure| {
        ProvisionError::new(format!("writing {}: {failure}", written.anchor.display()))
    })?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, pem};

    #[test]
    fn a_node_is_issued_for_its_names_under_the_authority_kept_with_its_anchor() {
        let base = std::env::temp_dir().join(format!("xmip-provision-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = base.join("authority");
        let names = ["node.example".to_string(), "cluster.example".to_string()];
        let folder = base.join("node");
        let issued = issue_into(
            &authority,
            "test authority",
            "node",
            &names,
            &folder,
            1_800_000_000,
        )
        .expect("issued");

        let anchor = std::fs::read_to_string(authority.join(CERTIFICATE)).expect("kept");
        assert_eq!(
            std::fs::read_to_string(&issued.anchor).expect("beside the node's"),
            anchor
        );
        let chain = std::fs::read_to_string(&issued.certificate).expect("the chain");
        assert!(chain.ends_with(&anchor), "the leaf, then the authority");
        let leaf = pem::decode("CERTIFICATE", &chain).expect("pem").remove(0);
        assert!(crate::serves(&leaf, Purpose::Node).expect("read"));
        for name in ["node", "node.example", "cluster.example"] {
            assert!(
                leaf.windows(name.len()).any(|at| at == name.as_bytes()),
                "{name} is named"
            );
        }
        let key = std::fs::read_to_string(&issued.key).expect("the key");
        let public = KeyPair::from_pem(&key).expect("a key").public_key_info();
        assert!(leaf.windows(public.len()).any(|at| at == public.as_slice()));

        let refused = issue_into(&authority, "x", " ", &names, &folder, 0).expect_err("no node");
        assert!(refused.message.contains("node"), "{refused}");
        std::fs::remove_dir_all(&base).expect("removes what it wrote");
    }
}
