//! What a certificate is for, and every rule that follows from it, in one
//! place: what it authenticates, what its subject is, and what a request for
//! it may ask.

use crate::csr::Requested;
use crate::der::{
    BASIC_CONSTRAINTS, CLIENT_AUTH, COMMON_NAME, EXT_KEY_USAGE, KEY_USAGE, SERVER_AUTH,
    SUBJECT_ALT_NAME,
};
use crate::{ProvisionError, Result};

/// The longest common name X.520 allows (`ub-common-name`).
const COMMON_NAME_LONGEST: usize = 64;

/// The characters RFC 4514 escapes in a distinguished name: a person's name
/// holds none, so it reads as `CN=<person>` in every rendering of it.
const SPECIAL: &[char] = &[',', '+', '=', '"', '\\', '<', '>', ';', '#'];

/// What a certificate is for, which decides what it may authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// What a Party reaches: a Receive Location's server certificate. Server
    /// authentication alone, which any public authority still issues.
    Receive,
    /// Between nodes: each end presents one in mutual TLS (ADR-0063 clause
    /// 1), so it authenticates a server and a client both.
    Node,
    /// A person's surface — the phone first — reaching a node's operate
    /// listener (ADR-0014, amendment 2026-10-14): client authentication
    /// alone, its subject the person, who is the caller the listener proves
    /// (ADR-0009, note of 2026-10-12). Signed by the cluster's authority
    /// from a request the surface made with its own key (ADR-0034,
    /// amendment 2026-10-15); never obtained by a node.
    Operator,
}

impl Purpose {
    /// Every purpose, in the order a configuration lists them.
    pub const ALL: [Self; 3] = [Self::Receive, Self::Node, Self::Operator];

    /// The purpose's word, as `[provision.<word>]` names it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Node => "node",
            Self::Operator => "operator",
        }
    }

    /// The purpose `word` names, if any.
    #[must_use]
    pub fn named(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|purpose| purpose.word() == word)
    }

    /// Whether a certificate for it authenticates a server.
    #[must_use]
    pub const fn server_authentication(self) -> bool {
        matches!(self, Self::Receive | Self::Node)
    }

    /// Whether a certificate for it must authenticate a client too.
    #[must_use]
    pub const fn client_authentication(self) -> bool {
        matches!(self, Self::Node | Self::Operator)
    }

    /// Whether its certificate names hosts by DNS name; an operator's names
    /// a person instead.
    #[must_use]
    pub const fn names_hosts(self) -> bool {
        !matches!(self, Self::Operator)
    }

    /// The extended key usages its certificate carries, object identifiers.
    #[must_use]
    pub fn extended_key_usages(self) -> Vec<&'static [u32]> {
        let mut usages = Vec::with_capacity(2);
        if self.server_authentication() {
            usages.push(SERVER_AUTH);
        }
        if self.client_authentication() {
            usages.push(CLIENT_AUTH);
        }
        usages
    }

    /// Whether a certificate for it may be signed for `requested`: a host's
    /// names a node purpose needs, a person an operator's names, and no
    /// extension asking for more than the purpose's certificate carries.
    ///
    /// # Errors
    ///
    /// What the request asks that the purpose does not allow, in words.
    pub fn admit(self, requested: &Requested) -> Result<()> {
        if self.names_hosts() {
            if requested.names.is_empty() {
                return Err(ProvisionError::new("the request names no DNS name"));
            }
        } else {
            let [(kind, person)] = requested.subject.as_slice() else {
                return Err(ProvisionError::new(
                    "an operator's request names one common name, the person, and nothing else",
                ));
            };
            if kind != COMMON_NAME {
                return Err(ProvisionError::new(
                    "an operator's request names the person as its common name",
                ));
            }
            Self::person(person)?;
        }
        for (id, value) in &requested.extensions {
            self.admit_extension(id, value)?;
        }
        Ok(())
    }

    /// Whether `person` may be an operator certificate's subject: the
    /// person's name as their directory knows it — a user principal name,
    /// `alice@example.org`, where there is one — from one to 64 characters,
    /// no control character and none RFC 4514 escapes, so the caller a
    /// listener proves is `CN=<person>` in every rendering.
    ///
    /// # Errors
    ///
    /// What is wrong with it, in words.
    pub fn person(person: &str) -> Result<&str> {
        let length = person.chars().count();
        if person.trim() != person || length == 0 {
            return Err(ProvisionError::new(
                "a person's name is not empty and has no space at either end",
            ));
        }
        if length > COMMON_NAME_LONGEST {
            return Err(ProvisionError::new(format!(
                "a person's name is at most {COMMON_NAME_LONGEST} characters; {length} given"
            )));
        }
        if let Some(refused) = person
            .chars()
            .find(|character| character.is_control() || SPECIAL.contains(character))
        {
            return Err(ProvisionError::new(format!(
                "a person's name holds no {refused:?}"
            )));
        }
        Ok(person)
    }

    /// One requested extension, held to what the purpose's certificate
    /// carries.
    fn admit_extension(self, id: &[u32], value: &[u8]) -> Result<()> {
        let refused = |what: &str| {
            Err(ProvisionError::new(format!(
                "a {} request may not ask for {what}",
                self.word()
            )))
        };
        match id {
            _ if id == SUBJECT_ALT_NAME && self.names_hosts() => Ok(()),
            _ if id == SUBJECT_ALT_NAME => refused("alternative names"),
            _ if id == EXT_KEY_USAGE => {
                let allowed = self.extended_key_usages();
                match read_usages(value)? {
                    usages
                        if usages
                            .iter()
                            .all(|usage| allowed.contains(&usage.as_slice())) =>
                    {
                        Ok(())
                    }
                    _ => refused("an extended key usage beyond its own"),
                }
            }
            // digitalSignature alone, the one bit a leaf carries.
            _ if id == KEY_USAGE => {
                let (bits, _) = asn1::expect(value, crate::der::BIT_STRING)?;
                // The first byte counts the unused bits; digitalSignature is
                // the first bit of the second.
                let beyond = bits.iter().skip(1).enumerate().any(|(at, byte)| {
                    if at == 0 {
                        byte & 0x7f != 0
                    } else {
                        *byte != 0
                    }
                });
                if beyond {
                    refused("a key usage beyond a digital signature")
                } else {
                    Ok(())
                }
            }
            // Not an authority: an empty constraint, or cA said false.
            _ if id == BASIC_CONSTRAINTS => {
                let (constraints, _) = asn1::expect(value, asn1::SEQUENCE)?;
                match asn1::read_all(constraints)?.first() {
                    None => Ok(()),
                    Some((tag, flag)) if *tag == asn1::BOOLEAN && flag == &[0] => Ok(()),
                    Some(_) => refused("being an authority"),
                }
            }
            _ => refused(&format!(
                "the extension {}",
                id.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
            )),
        }
    }
}

/// The usages an extended key usage value lists.
fn read_usages(value: &[u8]) -> Result<Vec<Vec<u32>>> {
    let (usages, _) = asn1::expect(value, asn1::SEQUENCE)?;
    asn1::read_all(usages)?
        .into_iter()
        .map(|(_, usage)| asn1::read_object_identifier(usage).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purpose_is_named_by_its_word_and_says_what_it_authenticates() {
        for purpose in Purpose::ALL {
            assert_eq!(Purpose::named(purpose.word()), Some(purpose));
        }
        assert_eq!(Purpose::named("edge"), None);
        assert!(Purpose::Node.client_authentication());
        assert!(!Purpose::Receive.client_authentication());
        assert_eq!(Purpose::Operator.extended_key_usages(), [CLIENT_AUTH]);
        assert!(!Purpose::Operator.server_authentication());
        assert!(!Purpose::Operator.names_hosts());
        assert_eq!(
            Purpose::Node.extended_key_usages(),
            [SERVER_AUTH, CLIENT_AUTH]
        );
    }

    #[test]
    fn a_person_is_a_plain_name_and_a_distinguished_name_is_refused() {
        assert_eq!(
            Purpose::person("alice@example.org").expect("a person"),
            "alice@example.org"
        );
        assert!(Purpose::person("Alice Smith").is_ok());
        for refused in ["", " alice", "alice ", "CN=alice", "a,b", "a\\b", "a\nb"] {
            assert!(Purpose::person(refused).is_err(), "{refused:?}");
        }
        assert!(Purpose::person(&"a".repeat(65)).is_err());
        assert!(Purpose::person(&"a".repeat(64)).is_ok());
    }
}
