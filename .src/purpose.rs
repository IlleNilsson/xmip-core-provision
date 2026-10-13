//! What a certificate is for.

/// What a certificate is for, which decides what it may authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// What a Party reaches: a Receive Location's server certificate. Server
    /// authentication alone, which any public authority still issues.
    Receive,
    /// Between nodes: each end presents one in mutual TLS (ADR-0063 clause
    /// 1), so it authenticates a server and a client both.
    Node,
}

impl Purpose {
    /// Every purpose, in the order a configuration lists them.
    pub const ALL: [Self; 2] = [Self::Receive, Self::Node];

    /// The purpose's word, as `[provision.<word>]` names it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Node => "node",
        }
    }

    /// The purpose `word` names, if any.
    #[must_use]
    pub fn named(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|purpose| purpose.word() == word)
    }

    /// Whether a certificate for it must authenticate a client too.
    #[must_use]
    pub const fn client_authentication(self) -> bool {
        matches!(self, Self::Node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purpose_is_named_by_its_word_and_only_the_node_authenticates_a_client() {
        for purpose in Purpose::ALL {
            assert_eq!(Purpose::named(purpose.word()), Some(purpose));
        }
        assert_eq!(Purpose::named("edge"), None);
        assert!(Purpose::Node.client_authentication());
        assert!(!Purpose::Receive.client_authentication());
    }
}
