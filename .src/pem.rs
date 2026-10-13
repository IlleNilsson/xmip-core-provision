//! PEM (RFC 7468): DER in base64 between a label's two lines. What a
//! certificate chain, a key and a set of anchors are written as, and what
//! `xmip-core-library-tls` reads.

use crate::{ProvisionError, Result};

/// `der` as one PEM block under `label`, lines of 64 characters.
#[must_use]
pub fn encode(label: &str, der: &[u8]) -> String {
    let text = codec::base64::encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Every block under `label` in `text`, in order; blocks under another
/// label are passed over.
///
/// # Errors
///
/// Where a block under `label` does not end, or its body is not base64.
pub fn decode(label: &str, text: &str) -> Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after
            .find(&end)
            .ok_or_else(|| ProvisionError::new(format!("a {label} block that does not end")))?;
        let body: String = after[..stop].split_whitespace().collect();
        found.push(codec::base64::decode(&body)?);
        rest = &after[stop + end.len()..];
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_round_trips_and_other_labels_are_passed_over() {
        let der: Vec<u8> = (0..=200).collect();
        let text = format!(
            "{}{}",
            encode("PRIVATE KEY", b"secret"),
            encode("CERTIFICATE", &der)
        );
        assert!(text.lines().all(|line| line.len() <= 64));
        assert_eq!(decode("CERTIFICATE", &text).expect("reads"), vec![der]);
        assert!(decode("CERTIFICATE", "-----BEGIN CERTIFICATE-----\nAA").is_err());
    }
}
