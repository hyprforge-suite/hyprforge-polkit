//! The agent, as polkitd sees it: `org.freedesktop.PolicyKit1.AuthenticationAgent`
//! on the system bus, registered for this login session.
//!
//! polkitd calls `BeginAuthentication` when a process in this session
//! asks for something its rules say needs authentication, and waits for
//! the call to return — success means "authenticated" only because the
//! helper has already told polkitd so ([`crate::helper`]); the reply
//! itself just ends the wait. `CancelAuthentication` is polkitd saying
//! the asking process gave up.
//!
//! Requests are answered one at a time: a second request waits for the
//! first prompt to close rather than stacking two password fields on the
//! screen, where a password meant for one could be typed into the other.

use crate::conversation::{authenticate, Did, Ended};
use crate::helper::Connector;
use crate::identity::{self, Identity};
use crate::prompt::{Message, Request};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, UnboundedSender};
use zbus::zvariant::OwnedValue;

/// Where the agent's object lives on the bus.
pub const OBJECT_PATH: &str = "/dev/hyprforge/PolkitAgent";

/// The errors polkitd understands from an agent.
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
pub enum PolkitError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Failed(String),
    Cancelled(String),
}

/// An open prompt, from the agent's side: something to tell things to.
pub trait PromptHandle: Send + Sync {
    fn tell(&self, message: Message);
}

impl PromptHandle for hyprforge_popup::InboxSender<Message> {
    fn tell(&self, message: Message) {
        // A prompt that has already closed has nothing left to show.
        let _ = self.send(message);
    }
}

/// Opens prompts. The real one draws a popup ([`crate::window`]); tests
/// use one that answers by script.
pub trait Prompts: Send + Sync + 'static {
    fn open(&self, request: Request, did: UnboundedSender<Did>) -> std::io::Result<Box<dyn PromptHandle>>;
}

pub struct Agent {
    connector: Arc<dyn Connector>,
    prompts: Arc<dyn Prompts>,
    /// The user this agent's session belongs to — offered first.
    me: String,
    turn: tokio::sync::Mutex<()>,
    /// The way to stop each request in flight, by its cookie.
    cancels: Mutex<HashMap<String, UnboundedSender<Did>>>,
}

impl Agent {
    pub fn new(connector: Arc<dyn Connector>, prompts: Arc<dyn Prompts>, me: String) -> Agent {
        Agent { connector, prompts, me, turn: tokio::sync::Mutex::new(()), cancels: Mutex::default() }
    }

    /// The body of `BeginAuthentication`, apart from the bus.
    pub async fn begin(
        &self,
        action_id: String,
        message: String,
        cookie: String,
        identities: Vec<Identity>,
        users_of: impl Fn(&[Identity], &str) -> Vec<String>,
    ) -> Result<(), PolkitError> {
        let _turn = self.turn.lock().await;
        let users = users_of(&identities, &self.me);
        let Some(first) = users.first().cloned() else {
            return Err(PolkitError::Failed("nobody this agent can ask is allowed to authenticate this".into()));
        };
        let (did, mut answers) = mpsc::unbounded_channel();
        self.cancels.lock().unwrap().insert(cookie.clone(), did.clone());
        let ended = match self.prompts.open(Request { message, action_id, users }, did) {
            Ok(prompt) => {
                let ended = authenticate(&*self.connector, first, &cookie, |s| prompt.tell(Message::Shown(s)), &mut answers).await;
                prompt.tell(Message::End);
                ended
            }
            Err(e) => Ended::Broken(format!("couldn't open the prompt: {e}")),
        };
        self.cancels.lock().unwrap().remove(&cookie);
        match ended {
            Ended::Authenticated => Ok(()),
            Ended::Cancelled => Err(PolkitError::Cancelled("the request was dismissed".into())),
            Ended::Broken(why) => {
                tracing::warn!("authentication failed: {why}");
                Err(PolkitError::Failed(why))
            }
        }
    }

    /// The body of `CancelAuthentication`.
    pub fn cancel(&self, cookie: &str) {
        if let Some(did) = self.cancels.lock().unwrap().get(cookie) {
            let _ = did.send(Did::Cancel);
        }
    }
}

/// polkit's identities, `a(sa{sv})`, as [`Identity`]s. An identity of
/// a kind this agent does not know is skipped, not refused: polkitd may
/// offer several, and one usable is enough.
pub fn identities(raw: &[(String, HashMap<String, OwnedValue>)]) -> Vec<Identity> {
    raw.iter()
        .filter_map(|(kind, details)| {
            let id = |key: &str| details.get(key).and_then(|v| u32::try_from(v).ok());
            match kind.as_str() {
                "unix-user" => id("uid").map(Identity::User),
                "unix-group" => id("gid").map(Identity::Group),
                _ => None,
            }
        })
        .collect()
}

/// The D-Bus face of an [`Agent`].
pub struct Service(pub Arc<Agent>);

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Service {
    async fn begin_authentication(
        &self,
        action_id: String,
        message: String,
        _icon_name: String,
        _details: HashMap<String, String>,
        cookie: String,
        identities: Vec<(String, HashMap<String, OwnedValue>)>,
    ) -> Result<(), PolkitError> {
        let ids = self::identities(&identities);
        self.0
            .begin(action_id, message, cookie, ids, |ids, me| identity::choices(ids, me, identity::user_name, identity::group_members))
            .await
    }

    async fn cancel_authentication(&self, cookie: String) {
        self.0.cancel(&cookie);
    }
}

/// This login session's id, for registering: `$XDG_SESSION_ID` when the
/// session set it, otherwise logind's answer for this process, otherwise
/// the session logind says this user's display is in.
///
/// The last is the one a systemd user unit needs. The user manager and
/// everything it starts belong to the user but to *no* session — its
/// scope is `user@1000.service`, not `session-3.scope` — so asking for
/// this process's session fails with `NoSessionForPID`, and the unit
/// restarted every two seconds, 916 times, with no agent in between.
/// `User.Display` is the graphical session the user is sitting at, which
/// is also where polkitd itself looks when a subject has no session of
/// its own; it's what `pkexec` from a terminal in that session asks
/// about, so it's the one an agent has to answer for.
pub async fn session_id(system: &zbus::Connection) -> zbus::Result<String> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        if !id.is_empty() {
            return Ok(id);
        }
    }
    logind_session(system).await
}

/// [`session_id`] without `$XDG_SESSION_ID`: what logind says.
async fn logind_session(system: &zbus::Connection) -> zbus::Result<String> {
    let manager = zbus::Proxy::new(system, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager").await?;
    let path: zbus::zvariant::OwnedObjectPath = match manager.call("GetSessionByPID", &(std::process::id())).await {
        Ok(path) => path,
        Err(outside) => {
            let user: zbus::zvariant::OwnedObjectPath = manager.call("GetUserByPID", &(std::process::id())).await?;
            let user = zbus::Proxy::new(system, "org.freedesktop.login1", user, "org.freedesktop.login1.User").await?;
            let (id, display) = user.get_property::<(String, zbus::zvariant::OwnedObjectPath)>("Display").await?;
            // No display session reads as `("", "/")`: the user is only
            // logged in over SSH, say. Then there is nothing to answer for,
            // and the original error says why better than an empty id would.
            if id.is_empty() {
                return Err(outside);
            }
            display
        }
    };
    let session = zbus::Proxy::new(system, "org.freedesktop.login1", path, "org.freedesktop.login1.Session").await?;
    session.get_property::<String>("Id").await
}

/// `RegisterAuthenticationAgent`'s arguments: the subject (this login
/// session), the locale, and the object path — as a plain string, which
/// is polkitd's signature (`(sa{sv})ss`), not D-Bus's object-path type,
/// which it refuses. `tests/live_polkit.rs` asks polkitd for its side.
pub type Registration<'a> = ((&'static str, HashMap<&'static str, zbus::zvariant::Value<'a>>), String, &'static str);

pub fn registration(session: &str) -> Registration<'_> {
    let mut details: HashMap<&str, zbus::zvariant::Value> = HashMap::new();
    details.insert("session-id", session.into());
    let locale = std::env::var("LANG").unwrap_or_else(|_| "C".into());
    (("unix-session", details), locale, OBJECT_PATH)
}

/// Tells polkitd this agent answers for `session`.
pub async fn register(system: &zbus::Connection, session: &str) -> zbus::Result<()> {
    let authority = zbus::Proxy::new(
        system,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await?;
    authority.call::<_, _, ()>("RegisterAuthenticationAgent", &registration(session)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Shown;
    use crate::helper::script::Scripted;
    use hyprforge_secret::Secret;

    /// Answers every question with `password`, the moment it is asked,
    /// and keeps what each prompt was asked to show.
    struct Typist {
        password: &'static str,
        opened: Arc<Mutex<Vec<Request>>>,
    }

    struct Seen(UnboundedSender<Did>, &'static str);

    impl PromptHandle for Seen {
        fn tell(&self, message: Message) {
            if let Message::Shown(Shown::Ask { .. }) = message {
                let _ = self.0.send(Did::Answer(Secret::new(self.1.to_string())));
            }
        }
    }

    impl Prompts for Typist {
        fn open(&self, request: Request, did: UnboundedSender<Did>) -> std::io::Result<Box<dyn PromptHandle>> {
            self.opened.lock().unwrap().push(request);
            Ok(Box::new(Seen(did, self.password)))
        }
    }

    fn agent(password: &'static str) -> (Agent, Arc<Mutex<Vec<Request>>>, Scripted) {
        let opened = Arc::new(Mutex::new(Vec::new()));
        let helper = Scripted::new("right");
        let agent = Agent::new(Arc::new(helper.clone()), Arc::new(Typist { password, opened: opened.clone() }), "alex".into());
        (agent, opened, helper)
    }

    fn just(names: &'static [&'static str]) -> impl Fn(&[Identity], &str) -> Vec<String> {
        move |_, _| names.iter().map(|s| s.to_string()).collect()
    }

    /// Run from outside any session, which is where a systemd user unit
    /// runs — and so does `cargo test` started from a terminal on
    /// Hyprland, whose processes live in the user manager's `app.slice`.
    /// `cargo test -p hyprforge-polkit -- --ignored outside`.
    #[tokio::test]
    #[ignore = "live (systemd-logind): changes nothing"]
    async fn a_process_outside_any_session_answers_for_the_users_display() {
        let Ok(system) = zbus::Connection::system().await else {
            eprintln!("HYPRFORGE-SKIP: no system bus");
            return;
        };
        let manager = zbus::Proxy::new(&system, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager").await.unwrap();
        if manager.call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSessionByPID", &(std::process::id())).await.is_ok() {
            eprintln!("HYPRFORGE-SKIP: this test is inside a login session, so the fallback is not reached");
            return;
        }
        let user: zbus::zvariant::OwnedObjectPath = manager.call("GetUserByPID", &(std::process::id())).await.unwrap();
        let user = zbus::Proxy::new(&system, "org.freedesktop.login1", user, "org.freedesktop.login1.User").await.unwrap();
        let (display, _) = user.get_property::<(String, zbus::zvariant::OwnedObjectPath)>("Display").await.unwrap();
        if display.is_empty() {
            eprintln!("HYPRFORGE-SKIP: this user has no display session to answer for");
            return;
        }
        assert_eq!(logind_session(&system).await.unwrap(), display);
    }

    #[tokio::test]
    async fn a_right_answer_is_success_and_the_prompt_was_told_what_was_asked() {
        let (agent, opened, helper) = agent("right");
        let result = agent.begin("org.example.do".into(), "Do the thing".into(), "c1".into(), vec![Identity::User(1000)], just(&["alex"])).await;
        assert!(result.is_ok(), "{result:?}");
        let opened = opened.lock().unwrap();
        assert_eq!(opened[0].message, "Do the thing");
        assert_eq!(helper.started.lock().unwrap()[0], ("alex".to_string(), "c1".to_string()));
    }

    #[tokio::test]
    async fn with_nobody_to_ask_it_fails_without_opening_anything() {
        let (agent, opened, _) = agent("right");
        let result = agent.begin("a".into(), "m".into(), "c".into(), vec![], just(&[])).await;
        assert!(matches!(result, Err(PolkitError::Failed(_))));
        assert!(opened.lock().unwrap().is_empty());
    }

    /// polkitd's CancelAuthentication reaches the request with that
    /// cookie, and the reply polkit gets is "cancelled".
    #[tokio::test]
    async fn cancelling_by_cookie_ends_that_request() {
        struct Silent(Arc<Mutex<Vec<Request>>>);
        struct Nothing;
        impl PromptHandle for Nothing {
            fn tell(&self, _: Message) {}
        }
        impl Prompts for Silent {
            fn open(&self, request: Request, _: UnboundedSender<Did>) -> std::io::Result<Box<dyn PromptHandle>> {
                self.0.lock().unwrap().push(request);
                Ok(Box::new(Nothing))
            }
        }
        let opened = Arc::new(Mutex::new(Vec::new()));
        let agent = Arc::new(Agent::new(Arc::new(Scripted::new("right")), Arc::new(Silent(opened.clone())), "alex".into()));
        let running = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.begin("a".into(), "m".into(), "cookie-9".into(), vec![], just(&["alex"])).await })
        };
        while opened.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        agent.cancel("someone-else");
        agent.cancel("cookie-9");
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), running).await.unwrap().unwrap();
        assert!(matches!(result, Err(PolkitError::Cancelled(_))), "{result:?}");
    }

    /// The shape polkitd takes — the path a string, not `o`. The first
    /// live registration was refused for exactly that.
    #[test]
    fn registration_goes_out_in_polkitds_shape() {
        use zbus::zvariant::Type;
        assert_eq!(<Registration as Type>::SIGNATURE.to_string(), "((sa{sv})ss)");
    }

    #[test]
    fn polkits_identities_are_read_and_unknown_kinds_skipped() {
        let user: HashMap<String, OwnedValue> = [("uid".to_string(), OwnedValue::from(1000u32))].into();
        let group: HashMap<String, OwnedValue> = [("gid".to_string(), OwnedValue::from(998u32))].into();
        let raw = vec![
            ("unix-user".to_string(), user),
            ("unix-netgroup".to_string(), HashMap::new()),
            ("unix-group".to_string(), group),
        ];
        assert_eq!(identities(&raw), [Identity::User(1000), Identity::Group(998)]);
    }
}
