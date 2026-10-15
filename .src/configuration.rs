//! A purpose's configuration, `[provision.<purpose>]`, read and refused in
//! words.
//!
//! `source` names the technology by its module name, as `[store] key_store`
//! names a key store, and the rest of the table is that technology's
//! settings, read through its own declaration (ADR-0044, amendment
//! 2026-09-26). A table that names no source is an operator's own files,
//! read through [`FILES`]; `[provision.operator]` is the one that never
//! names a source, read through [`OPERATOR`]. A source the program does not link is refused,
//! naming the ones it does.

use std::time::Duration;

use xcore::settings::{
    Applies, Fixed, Given, Kind, Presence, Read, Refusal, Refused, Setting, Settings,
};

use crate::Purpose;

/// The key a purpose's table names its source by.
pub const SOURCE: &str = "source";

/// The capability's own name, as a refusal of the table itself names it.
const CAPABILITY: &str = "xmip-core-provision";

/// The names a certificate is for: every source that issues one declares
/// it, by this one declaration.
pub const NAMES: Setting = Setting {
    name: "names",
    kind: Kind::Text,
    presence: Presence::Required,
    meaning: "The DNS names the certificate is for, separated by commas, the first its subject.",
    applies: Applies::Both,
};

/// An operator's own files, which is what a table without `source` is.
pub const FILES: &Settings = &Settings {
    technology: CAPABILITY,
    settings: &[
        Setting {
            name: "certificate",
            kind: Kind::Address,
            presence: Presence::Required,
            meaning: "The PEM chain, leaf first, relative to the configuration file.",
            applies: Applies::Both,
        },
        Setting {
            name: "key",
            kind: Kind::Address,
            presence: Presence::Required,
            meaning: "The leaf's PEM private key, relative to the configuration file.",
            applies: Applies::Both,
        },
        Setting {
            name: "anchors",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "The PEM anchors a peer's certificate must reach, relative to the \
                      configuration file.",
            applies: Applies::Both,
        },
    ],
};

/// How long an operator's certificate is valid where `[provision.operator]`
/// says nothing: thirty days. The assistant's draft of 2026-10-15, for the
/// owner to strike; a cluster sets its own, and a node its own beside it.
pub const OPERATOR_LIFETIME: Duration = Duration::from_hours(30 * 24);

/// `[provision.operator]`: on the node whose authority signs a person's
/// request (ADR-0034, amendment 2026-10-15). It names no `source`: an
/// operator's certificate is signed from a request, never obtained.
pub const OPERATOR: &Settings = &Settings {
    technology: CAPABILITY,
    settings: &[
        Setting {
            name: "authority",
            kind: Kind::Address,
            presence: Presence::Required,
            meaning: "The folder the cluster's authority is kept in — its authority.key and \
                      authority.pem — relative to the configuration file.",
            applies: Applies::Both,
        },
        Setting {
            name: "lifetime",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(OPERATOR_LIFETIME)),
            meaning: "How long an operator's certificate the authority signs is valid.",
            applies: Applies::Both,
        },
    ],
};

/// A purpose's table, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configured {
    /// The purpose the table is for.
    pub purpose: Purpose,
    /// The technology chosen; [`FILES`]'s name where the table names none.
    pub technology: &'static str,
    /// Its settings, read through its declaration.
    pub settings: Read,
}

/// Read `[provision.<purpose>]`, its keys as `given`, against the sources
/// the program links, each by its declaration.
///
/// # Errors
///
/// Every refusal at once: a purpose that is none, a source not linked, and
/// whatever the chosen declaration refuses — an unknown key, a value of
/// the wrong kind, a required setting left out — each naming what is wrong.
pub fn read(
    purpose: &str,
    given: &[(String, Given)],
    sources: &[&'static Settings],
) -> Result<Configured, Refused> {
    let mut refusals = Vec::new();
    let named = Purpose::named(purpose);
    if named.is_none() {
        refusals.push(Refusal::Unknown {
            technology: CAPABILITY,
            setting: format!("provision.{purpose}"),
        });
    }
    let chosen = given
        .iter()
        .find(|(key, _)| key == SOURCE)
        .map(|(_, value)| value);
    let declaration = match chosen {
        _ if named == Some(Purpose::Operator) => {
            if chosen.is_some() {
                refusals.push(Refusal::Unknown {
                    technology: CAPABILITY,
                    setting: format!("provision.operator.{SOURCE}"),
                });
            }
            Some(OPERATOR)
        }
        None => Some(FILES),
        Some(Given::Text(name)) => {
            let found = sources
                .iter()
                .copied()
                .find(|source| source.technology == name);
            if found.is_none() {
                refusals.push(not_linked(name, sources));
            }
            found
        }
        Some(other) => {
            refusals.push(Refusal::Kind {
                technology: CAPABILITY,
                setting: SOURCE,
                expected: "text",
                reason: format!("{other:?} is not a module name"),
            });
            None
        }
    };
    let rest: Vec<(String, Given)> = given
        .iter()
        .filter(|(key, _)| key != SOURCE)
        .cloned()
        .collect();
    let settings = declaration.map(|declaration| declaration.read(Applies::Both, &rest));
    match (named, declaration, settings) {
        (Some(purpose), Some(declaration), Some(Ok(settings))) if refusals.is_empty() => {
            match empty_names(declaration, &settings) {
                Some(refusal) => Err(Refused(vec![refusal])),
                None => Ok(Configured {
                    purpose,
                    technology: declaration.technology,
                    settings,
                }),
            }
        }
        (_, _, Some(Err(Refused(more)))) => {
            refusals.extend(more);
            Err(Refused(refusals))
        }
        _ => Err(Refused(refusals)),
    }
}

/// The names a source's `names` setting lists, trimmed, empty ones dropped.
#[must_use]
pub fn names(settings: &Read) -> Vec<String> {
    settings
        .optional_text(NAMES.name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn not_linked(name: &str, sources: &[&'static Settings]) -> Refusal {
    let linked: Vec<&str> = sources.iter().map(|source| source.technology).collect();
    Refusal::Kind {
        technology: CAPABILITY,
        setting: SOURCE,
        expected: "a source this program links",
        reason: format!(
            "{name:?} is not one; it links {}",
            if linked.is_empty() {
                "none".to_string()
            } else {
                linked.join(", ")
            }
        ),
    }
}

/// A `names` that lists nothing, where the declaration takes names.
fn empty_names(declaration: &Settings, settings: &Read) -> Option<Refusal> {
    (declaration.setting(NAMES.name).is_some() && names(settings).is_empty()).then(|| {
        Refusal::Kind {
            technology: declaration.technology,
            setting: NAMES.name,
            expected: NAMES.kind.word(),
            reason: "it lists no DNS name".to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_A: &Settings = &Settings {
        technology: "xmip-core-provision-example",
        settings: &[NAMES],
    };

    fn text(key: &str, value: &str) -> (String, Given) {
        (key.to_string(), Given::Text(value.to_string()))
    }

    #[test]
    fn every_declaration_here_is_sound() {
        assert!(FILES.problems().is_empty(), "{:?}", FILES.problems());
        assert!(OPERATOR.problems().is_empty(), "{:?}", OPERATOR.problems());
        assert!(SOURCE_A.problems().is_empty(), "{:?}", SOURCE_A.problems());
    }

    #[test]
    fn a_named_source_reads_its_own_settings_and_its_names() {
        let given = [
            text(SOURCE, SOURCE_A.technology),
            text("names", "a.example, b.example,"),
        ];
        let read = read("node", &given, &[SOURCE_A]).expect("read");
        assert_eq!(read.purpose, Purpose::Node);
        assert_eq!(read.technology, SOURCE_A.technology);
        assert_eq!(names(&read.settings), ["a.example", "b.example"]);
    }

    #[test]
    fn a_table_without_a_source_is_files_and_what_is_missing_is_named() {
        let refused = read("receive", &[text("certificate", "c.pem")], &[]).expect_err("key");
        assert_eq!(refused.0.len(), 1);
        assert_eq!(refused.0[0].setting(), "key");
        let given = [text("certificate", "c.pem"), text("key", "k.pem")];
        assert_eq!(
            read("receive", &given, &[]).expect("files").technology,
            CAPABILITY
        );
    }

    #[test]
    fn the_operator_table_names_an_authority_and_no_source_and_its_lifetime_defaults() {
        let table = read_operator(&[text("authority", "ca")]);
        assert_eq!(table.purpose, Purpose::Operator);
        assert_eq!(table.settings.duration("lifetime"), OPERATOR_LIFETIME);
        let given = [text("authority", "ca"), text("lifetime", "8h")];
        let table = read_operator(&given);
        assert_eq!(table.settings.duration("lifetime").as_secs(), 8 * 3600);
        let given = [text(SOURCE, SOURCE_A.technology), text("authority", "ca")];
        let refused = read("operator", &given, &[SOURCE_A]).expect_err("a source");
        assert!(refused.0[0].to_string().contains("source"), "{refused:?}");
        let refused = read("operator", &[], &[]).expect_err("no authority");
        assert_eq!(refused.0[0].setting(), "authority");
    }

    fn read_operator(given: &[(String, Given)]) -> Configured {
        read("operator", given, &[]).expect("read")
    }

    #[test]
    fn an_unlinked_source_an_unknown_purpose_and_empty_names_are_refused_in_words() {
        let refused = read("edge", &[text(SOURCE, "elsewhere")], &[SOURCE_A]).expect_err("no");
        let said: Vec<String> = refused.0.iter().map(ToString::to_string).collect();
        assert!(said[0].contains("provision.edge"), "{said:?}");
        assert!(said[1].contains(SOURCE_A.technology), "{said:?}");
        let given = [text(SOURCE, SOURCE_A.technology), text("names", " , ")];
        let refused = read("node", &given, &[SOURCE_A]).expect_err("empty");
        assert!(refused.0[0].to_string().contains("no DNS name"));
        let refused = read("node", &[text(SOURCE, SOURCE_A.technology)], &[SOURCE_A]);
        assert!(
            refused.expect_err("missing").0[0]
                .to_string()
                .contains("missing")
        );
    }
}
