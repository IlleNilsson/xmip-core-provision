//! What a source gave: a chain, its key and what a peer's chain must reach,
//! each PEM, as `xmip-core-library-tls` takes them, and when it is due for
//! renewal.

use std::path::Path;

use secret::private_file;
use zeroize::Zeroizing;

use crate::{ProvisionError, Result, pem, validity};

/// The files a provisioned certificate is kept in, in its generation's
/// folder of its purpose's place.
const CHAIN: &str = "chain.pem";
const KEY: &str = "key.pem";
const ANCHORS: &str = "anchors.pem";

/// The file in a purpose's place naming the generation it keeps now: the
/// one switch a new certificate takes effect by.
const CURRENT: &str = "current";

/// How a generation's folder is named, before its random part.
const GENERATION: &str = "generation-";

/// A certificate obtained: its chain, leaf first, its private key, and the
/// anchors a peer's certificate must reach where the source knows them —
/// the cluster's authority, a self-signed node's own certificate.
#[derive(Clone)]
pub struct Provisioned {
    /// The chain, PEM, leaf first.
    pub chain: String,
    /// The leaf's private key, PEM.
    pub key: Zeroizing<String>,
    /// The anchors, PEM, where the source has them; a public authority's
    /// are the operating system's trust store.
    pub anchors: Option<String>,
    /// From when the leaf is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
}

impl core::fmt::Debug for Provisioned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Provisioned")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("anchors", &self.anchors.is_some())
            .finish_non_exhaustive()
    }
}

impl Provisioned {
    /// What `chain`, `key` and `anchors` are, its validity read from the
    /// chain's first certificate.
    ///
    /// # Errors
    ///
    /// Where the chain holds no certificate, or its first is unreadable.
    pub fn new(chain: String, key: Zeroizing<String>, anchors: Option<String>) -> Result<Self> {
        let leaf = pem::decode("CERTIFICATE", &chain)?
            .into_iter()
            .next()
            .ok_or_else(|| ProvisionError::new("the chain holds no certificate"))?;
        let (not_before, not_after) = validity(&leaf)?;
        Ok(Self {
            chain,
            key,
            anchors,
            not_before,
            not_after,
        })
    }

    /// When it is renewed: two thirds of the way through the life it was
    /// issued with, whatever that life is.
    #[must_use]
    pub const fn renew_at(&self) -> i64 {
        self.not_before + (self.not_after - self.not_before) / 3 * 2
    }

    /// Whether it is due for renewal at `now`.
    #[must_use]
    pub const fn due(&self, now: i64) -> bool {
        now >= self.renew_at()
    }

    /// Whether it has expired at `now`.
    #[must_use]
    pub const fn expired(&self, now: i64) -> bool {
        now >= self.not_after
    }

    /// Keep it in `place`, a private directory created when absent, as one
    /// switch: the chain, the key and the anchors are written into a new
    /// generation's folder, each a private file
    /// ([`secret::private_file`]), and only then does `current` name that
    /// folder, replaced whole. A crash at any step leaves `place` keeping
    /// the identity it kept, its chain and key matching; the folder it left
    /// is removed at the next write, and the one replaced at once.
    ///
    /// # Errors
    ///
    /// Where a directory or a file cannot be written, naming it.
    pub fn write(&self, place: &Path) -> Result<()> {
        let generation = self.stage(place)?;
        commit(place, &generation)
    }

    /// The first step of [`Self::write`]: a new generation's folder in
    /// `place` holding the chain, the key and the anchors, which nothing
    /// reads until [`commit`] names it. Generations no longer named, a
    /// crash's leftovers, are removed first.
    fn stage(&self, place: &Path) -> Result<String> {
        private_file::directory(place).map_err(failed(place))?;
        private_file::sweep(place).map_err(failed(place))?;
        sweep(place, current(place)?.as_deref())?;
        let name = format!(
            "{GENERATION}{}",
            codec::hex::encode(&codec::random::array::<8>())
        );
        let folder = place.join(&name);
        private_file::directory(&folder).map_err(failed(&folder))?;
        let files = [
            (CHAIN, Some(self.chain.as_str())),
            (KEY, Some(self.key.as_str())),
            (ANCHORS, self.anchors.as_deref()),
        ];
        for (file, text) in files {
            if let Some(text) = text {
                let path = folder.join(file);
                private_file::create(&path, text.as_bytes()).map_err(failed(&path))?;
            }
        }
        private_file::synced(&folder).map_err(failed(&folder))?;
        Ok(name)
    }

    /// What `place` keeps — the generation its `current` names — or `None`
    /// where it keeps nothing yet.
    ///
    /// # Errors
    ///
    /// Where a file is there and cannot be read, or holds no certificate.
    pub fn read(place: &Path) -> Result<Option<Self>> {
        let Some(generation) = current(place)? else {
            return Ok(None);
        };
        let folder = place.join(generation);
        let holds = |file: &str| {
            optional(&folder.join(file))?
                .ok_or_else(|| ProvisionError::new(format!("{} holds no {file}", folder.display())))
        };
        let chain = holds(CHAIN)?;
        let key = Zeroizing::new(holds(KEY)?);
        let anchors = optional(&folder.join(ANCHORS))?;
        Self::new(chain, key, anchors).map(Some)
    }
}

/// The switch of [`Provisioned::write`]: [`CURRENT`] names `generation`,
/// replaced whole and synced; the generation it named before is removed.
/// A removal that fails is tried again at the next write.
fn commit(place: &Path, generation: &str) -> Result<()> {
    let before = current(place)?;
    let pointer = place.join(CURRENT);
    private_file::replace(&pointer, generation.as_bytes()).map_err(failed(&pointer))?;
    if let Some(before) = before.filter(|before| before != generation) {
        let _ = std::fs::remove_dir_all(place.join(before));
    }
    Ok(())
}

/// The generation `place`'s [`CURRENT`] names, or `None` where there is no
/// such file.
fn current(place: &Path) -> Result<Option<String>> {
    let pointer = place.join(CURRENT);
    let Some(text) = optional(&pointer)? else {
        return Ok(None);
    };
    let name = text.trim();
    let generation = name
        .strip_prefix(GENERATION)
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()));
    if !generation {
        return Err(ProvisionError::new(format!(
            "{} names no generation: {name:?}",
            pointer.display()
        )));
    }
    Ok(Some(name.to_string()))
}

/// Every generation's folder in `place` but `keep` removed: those a crash
/// left before its switch, and one a removal missed.
fn sweep(place: &Path, keep: Option<&str>) -> Result<()> {
    let entries = std::fs::read_dir(place).map_err(failed(place))?;
    for entry in entries {
        let entry = entry.map_err(failed(place))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(GENERATION) && Some(name.as_ref()) != keep {
            std::fs::remove_dir_all(entry.path()).map_err(failed(&entry.path()))?;
        }
    }
    Ok(())
}

/// What the operating system said about `path`, as a failure naming it.
fn failed(path: &Path) -> impl Fn(std::io::Error) -> ProvisionError + '_ {
    move |failure| ProvisionError::new(format!("writing {}: {failure}", path.display()))
}

/// A file's text, or `None` where there is no such file.
fn optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(failure) => Err(ProvisionError::new(format!(
            "reading {}: {failure}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Draft, KeyPair, Usage};

    fn place(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("xmip-provisioned-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path.join("node")
    }

    fn identity(subject: &str) -> Provisioned {
        let key = KeyPair::generate().expect("a key");
        let der = Draft {
            subject,
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: 1_800_000_000,
            not_after: 1_900_000_000,
            usage: Usage::Authority,
        }
        .sign(subject, &key)
        .expect("signed");
        let chain = pem::encode("CERTIFICATE", &der);
        Provisioned::new(chain.clone(), key.pem(), Some(chain)).expect("provisioned")
    }

    fn matches(read: &Provisioned, written: &Provisioned) -> bool {
        read.chain == written.chain && *read.key == *written.key
    }

    fn generations(place: &Path) -> usize {
        std::fs::read_dir(place)
            .expect("listed")
            .filter(|entry| {
                let name = entry.as_ref().expect("entry").file_name();
                name.to_string_lossy().starts_with(GENERATION)
            })
            .count()
    }

    /// The access `path` has, and the owner-only access it should have.
    fn access(path: &Path, directory: bool) -> (String, String) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(path).expect("metadata").mode() & 0o777;
            let owner = if directory { "700" } else { "600" };
            (format!("{mode:o}"), owner.to_string())
        }
        #[cfg(windows)]
        {
            (
                private_file::described(path).expect("described"),
                private_file::owner_only(directory).expect("owner only"),
            )
        }
    }

    #[test]
    fn an_identity_is_read_back_whole_and_its_key_is_the_owners_alone() {
        let place = place("whole");
        assert!(Provisioned::read(&place).expect("read").is_none());
        let first = identity("first");
        first.write(&place).expect("kept");
        let read = Provisioned::read(&place).expect("read").expect("kept");
        assert!(matches(&read, &first));
        assert_eq!(read.anchors, first.anchors);

        let generation = current(&place).expect("current").expect("named");
        let folder = place.join(&generation);
        let (key, owner) = access(&folder.join(KEY), false);
        assert_eq!(key, owner, "key.pem");
        let (folder_access, owner) = access(&folder, true);
        assert_eq!(folder_access, owner, "the generation's folder");
        let (place_access, owner) = access(&place, true);
        assert_eq!(place_access, owner, "the place");

        let second = Provisioned {
            anchors: None,
            ..identity("second")
        };
        second.write(&place).expect("replaced");
        let read = Provisioned::read(&place).expect("read").expect("kept");
        assert!(matches(&read, &second));
        assert!(read.anchors.is_none(), "no anchors left from the first");
        assert_eq!(generations(&place), 1, "the first generation is removed");
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn a_crash_before_the_switch_leaves_the_old_matching_identity() {
        let place = place("crash");
        let old = identity("old");
        old.write(&place).expect("kept");

        // A crash after the new generation is written, before the switch.
        let new = identity("new");
        new.stage(&place).expect("staged");
        let read = Provisioned::read(&place).expect("read").expect("kept");
        assert!(matches(&read, &old), "the old chain with the old key");

        // A crash halfway through writing one: a chain and no key.
        let half = place.join(format!("{GENERATION}00"));
        private_file::directory(&half).expect("made");
        private_file::create(&half.join(CHAIN), new.chain.as_bytes()).expect("chain");
        let read = Provisioned::read(&place).expect("read").expect("kept");
        assert!(matches(&read, &old), "still the old chain with the old key");
        assert_eq!(generations(&place), 3);

        // The next write sweeps what the crashes left and switches whole.
        let next = identity("next");
        next.write(&place).expect("written");
        let read = Provisioned::read(&place).expect("read").expect("kept");
        assert!(matches(&read, &next));
        assert_eq!(generations(&place), 1);
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn a_current_that_names_no_generation_is_refused() {
        let place = place("pointer");
        private_file::directory(&place).expect("made");
        private_file::replace(&place.join(CURRENT), b"../elsewhere").expect("written");
        let refused = Provisioned::read(&place).expect_err("refused");
        assert!(refused.message.contains("names no generation"), "{refused}");
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }
}
