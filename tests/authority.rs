//! The authority kept in a folder as an operator meets it (ADR-0034,
//! amendment 2026-10-22): what it signs is in its register and names where
//! its list is published; a revocation is listed at once, signed by it; a
//! backup is the same authority; and a node's certificate carried across an
//! air gap is requested, signed and imported, each step refusing in words
//! the file it should not take.

use std::path::{Path, PathBuf};

use xmip_core_provision::carried::{self, NEXT_KEY_FILE, REQUEST_FILE};
use xmip_core_provision::crl::{self, Reason};
use xmip_core_provision::renewal::{self, Standing};
use xmip_core_provision::{Issuer, KeyPair, Parsed, Purpose, node, pem};

const NOW: i64 = 1_800_000_000;

/// A fresh folder of its own, removed on drop.
struct Place(PathBuf);

impl Place {
    fn new(test: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "xmip-provision-{test}-{}-{}",
            std::process::id(),
            codec::hex::encode(&codec::random::array::<4>())
        ));
        Self(path)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn kept(place: &Path) -> Issuer {
    Issuer::kept_or_made(place, "test cluster authority", NOW - 60, 10 * 365 * 86_400)
        .expect("an authority")
}

fn leaf_of(issuer: &Issuer, name: &str) -> String {
    let key = KeyPair::generate().expect("a key");
    issuer
        .issue(
            &key.public_key_info(),
            name,
            &[name.to_string()],
            Purpose::Node,
            NOW,
            NOW + 90 * 86_400,
        )
        .expect("issued")
}

#[test]
fn what_an_authority_signs_is_registered_and_names_where_its_list_is() {
    let place = Place::new("register");
    let issuer = kept(&place.0);
    issuer
        .register()
        .expect("kept in a folder")
        .publish("http://ca.example:8080/")
        .expect("published");
    let issuer = Issuer::kept(&place.0).expect("read again");
    let chain = leaf_of(&issuer, "r1.example");
    let leaf = Parsed::first(&chain).expect("the leaf");
    let text =
        String::from_utf8_lossy(&pem::decode("CERTIFICATE", &chain).expect("pem")[0]).into_owned();
    assert!(
        text.contains("http://ca.example:8080/crl"),
        "a distribution point"
    );
    assert!(
        text.contains("http://ca.example:8080/authority.cer"),
        "the issuer"
    );
    let id = renewal::identifier(&leaf).expect("an identifier");
    let (authority, serial) = renewal::halves(&id).expect("halves");
    assert_eq!(serial, leaf.serial);
    assert_eq!(authority.len(), 20);

    let records = issuer
        .register()
        .expect("register")
        .records()
        .expect("read");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.serial, leaf.serial_hex());
    assert_eq!(
        (record.purpose, record.subject.as_str()),
        ("node", "r1.example")
    );
    assert_eq!(record.renewal_id, id);
    assert_eq!(record.renew_at, NOW + 60 * 86_400);
    assert!(record.revoked.is_none());

    let refused = issuer
        .register()
        .expect("register")
        .publish("https://ca.example")
        .expect_err("not plain HTTP");
    assert!(refused.message.contains("plain HTTP"), "{refused}");
}

#[test]
fn a_revocation_is_listed_at_once_signed_by_the_authority_and_never_twice() {
    let place = Place::new("revoke");
    let issuer = kept(&place.0);
    let chain = leaf_of(&issuer, "r2.example");
    let serial = Parsed::first(&chain).expect("leaf").serial_hex();
    let revoked = issuer
        .revoke(&serial.to_ascii_lowercase(), Reason::KeyCompromise, NOW + 5)
        .expect("revoked");
    assert_eq!(
        revoked.revoked.expect("revoked").reason,
        Reason::KeyCompromise
    );

    let listed = crl::read(&issuer.revocation_list(NOW + 6).expect("listed")).expect("read");
    let authority = Parsed::first(issuer.certificate()).expect("the authority");
    assert!(listed.signed_by(&authority).expect("checked"));
    let named = listed
        .names(&Parsed::first(&chain).expect("leaf").serial)
        .expect("named");
    assert_eq!((named.at, named.reason), (NOW + 5, Reason::KeyCompromise));

    let twice = issuer
        .revoke(&serial, Reason::Superseded, NOW + 7)
        .expect_err("twice");
    assert!(twice.message.contains("revoked already"), "{twice}");
    let none = issuer
        .revoke("ABCDEF", Reason::Superseded, NOW)
        .expect_err("none");
    assert!(none.message.contains("signed no certificate"), "{none}");
    let later = crl::read(&issuer.revocation_list(NOW + 2 * 86_400).expect("again")).expect("read");
    assert!(
        later.number > listed.number,
        "a list made again is numbered past the last"
    );
}

#[test]
fn a_backup_is_the_same_authority_and_is_made_into_an_empty_folder_alone() {
    let (place, copy) = (Place::new("kept"), Place::new("backup"));
    let issuer = kept(&place.0);
    let chain = leaf_of(&issuer, "r3.example");
    let register = issuer.register().expect("register");
    let copied = register.back_up(&copy.0).expect("backed up");
    assert!(copied.iter().any(|path| path.ends_with("authority.key")));

    let restored = Issuer::kept(&copy.0).expect("the copy is an authority");
    assert_eq!(restored.certificate(), issuer.certificate());
    let serial = Parsed::first(&chain).expect("leaf").serial_hex();
    assert!(restored.register().expect("register").find(&serial).is_ok());
    let refused = register.back_up(&copy.0).expect_err("not empty");
    assert!(refused.message.contains("empty folder"), "{refused}");
}

#[test]
fn a_node_certificate_carried_across_an_air_gap_is_requested_signed_and_imported() {
    let (authority, machine) = (Place::new("gap-authority"), Place::new("gap-node"));
    let issuer = kept(&authority.0);
    let names = ["r4.example".to_string(), "c1.example".to_string()];
    let asked = carried::request_into("r4", &names, &machine.0).expect("requested");
    assert_eq!(asked.names, ["r4", "r4.example", "c1.example"]);
    let again = carried::request_into("r4", &names, &machine.0).expect_err("waiting");
    assert!(again.message.contains("a request is waiting"), "{again}");

    let request = std::fs::read_to_string(&asked.request).expect("the request");
    let other = ["r5.example".to_string()];
    let refused = carried::sign(&authority.0, &request, &other, NOW).expect_err("names");
    assert!(refused.message.contains("the signer expects"), "{refused}");
    let mut tampered = pem::decode("CERTIFICATE REQUEST", &request)
        .expect("pem")
        .remove(0);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered = pem::encode("CERTIFICATE REQUEST", &tampered);
    let refused = carried::sign(&authority.0, &tampered, &[], NOW).expect_err("tampered");
    assert!(refused.message.contains("does not verify"), "{refused}");

    let signed = carried::sign(&authority.0, &request, &asked.names, NOW).expect("signed");
    assert_eq!(signed.not_after - NOW, 90 * 86_400);
    let register = issuer.register().expect("register");
    assert!(
        register.find(&signed.serial).is_ok(),
        "the signing is registered"
    );

    let foreign = leaf_of(&issuer, "r4");
    let refused = carried::import(&foreign, &machine.0, NOW).expect_err("another key");
    assert!(refused.message.contains("another key"), "{refused}");
    let refused =
        carried::import(&signed.chain, &machine.0, NOW + 91 * 86_400).expect_err("expired");
    assert!(refused.message.contains("not now"), "{refused}");

    let imported = carried::import(&signed.chain, &machine.0, NOW + 1).expect("imported");
    assert!(imported.anchor_taken, "the node held no anchor yet");
    assert_eq!(imported.serial, signed.serial);
    assert!(!machine.0.join(REQUEST_FILE).exists() && !machine.0.join(NEXT_KEY_FILE).exists());
    let key = std::fs::read_to_string(&imported.key).expect("the key");
    let public = KeyPair::from_pem(&key).expect("a key").public_key_info();
    let held = std::fs::read_to_string(&imported.certificate).expect("the chain");
    assert_eq!(Parsed::first(&held).expect("leaf").public_key_info, public);
    assert_eq!(
        std::fs::read_to_string(&imported.anchors).expect("anchors"),
        issuer.certificate()
    );

    let standing = Standing::of(&held, imported.renew_at).expect("standing");
    assert_eq!((standing.due, standing.word()), (true, "renewal due"));
    assert_eq!(
        Standing::of(&held, NOW + 1).expect("standing").word(),
        "current"
    );

    // A renewal: the node holds its anchor now, and a chain from another
    // authority does not reach it.
    let stranger = Place::new("gap-stranger");
    let _ = kept(&stranger.0);
    let renewal = carried::request_into("r4", &names, &machine.0).expect("renewal");
    let request = std::fs::read_to_string(&renewal.request).expect("request");
    let elsewhere = carried::sign(&stranger.0, &request, &[], NOW).expect("signed");
    let refused = carried::import(&elsewhere.chain, &machine.0, NOW + 1).expect_err("anchor");
    assert!(
        refused.message.contains("does not reach the anchors"),
        "{refused}"
    );
    let renewed = carried::sign(&authority.0, &request, &[], NOW + 2).expect("signed");
    let imported = carried::import(&renewed.chain, &machine.0, NOW + 3).expect("renewed");
    assert!(!imported.anchor_taken);
    let unsigned = carried::sign(&machine.0, &request, &[], NOW).expect_err("no authority");
    assert!(
        unsigned.message.contains("no authority is kept"),
        "{unsigned}"
    );
}

#[test]
fn a_node_issued_on_the_operators_machine_is_registered_too() {
    let (authority, folder) = (Place::new("issued"), Place::new("issued-node"));
    let issued = node::issue_into(&authority.0, "test", "r6", &[], &folder.0, NOW).expect("issued");
    let chain = std::fs::read_to_string(issued.certificate).expect("chain");
    let serial = Parsed::first(&chain).expect("leaf").serial_hex();
    let kept = Issuer::kept(&authority.0).expect("kept");
    assert_eq!(
        kept.register()
            .expect("register")
            .find(&serial)
            .expect("found")
            .subject,
        "r6"
    );
}
