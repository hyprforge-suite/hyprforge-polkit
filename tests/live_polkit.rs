//! What only the real polkitd can answer, asked read-only.
//!
//! `cargo test --test live_polkit -- --ignored`. Ignored by default
//! because it needs a running polkitd on the system bus. It registers
//! nothing — a second agent would displace the one this session already
//! has — it only reads polkitd's own description of its methods.
//!
//! It exists because the first registration this agent ever tried was
//! refused: the object path went out as D-Bus type `o`, polkitd's
//! signature says `s`, and nothing short of polkitd itself could have
//! said so.

#[tokio::test]
#[ignore]
async fn polkitd_takes_registration_in_the_shape_the_agent_sends() {
    let system = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("HYPRFORGE-SKIP: no system bus ({e})");
            return;
        }
    };
    let introspect = zbus::fdo::IntrospectableProxy::builder(&system)
        .destination("org.freedesktop.PolicyKit1")
        .unwrap()
        .path("/org/freedesktop/PolicyKit1/Authority")
        .unwrap()
        .build()
        .await
        .unwrap();
    let xml = match introspect.introspect().await {
        Ok(xml) => xml,
        Err(e) => {
            eprintln!("HYPRFORGE-SKIP: polkitd is not answering ({e})");
            return;
        }
    };
    let node = zbus_xml::Node::try_from(xml.as_str()).unwrap();
    let authority = node.interfaces().iter().find(|i| i.name() == "org.freedesktop.PolicyKit1.Authority").expect("the Authority interface");
    let register = authority.methods().iter().find(|m| m.name() == "RegisterAuthenticationAgent").expect("RegisterAuthenticationAgent");
    let signature: String = register
        .args()
        .iter()
        .filter(|a| a.direction() == Some(zbus_xml::ArgDirection::In))
        .map(|a| a.ty().to_string())
        .collect();
    // subject, locale, object path — the path as a *string*. What
    // `agent::register` sends: ("unix-session", {session-id}), $LANG, OBJECT_PATH.
    assert_eq!(signature, "(sa{sv})ss");
}
