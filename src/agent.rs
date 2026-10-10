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
/// session set it, otherwise logind's answer for this process.
pub async fn session_id(system: &zbus::Connection) -> zbus::Result<String> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let manager = zbus::Proxy::new(system, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager").await?;
    let path: zbus::zvariant::OwnedObjectPath = manager.call("GetSessionByPID", &(std::process::id())).await?;
    let session = zbus::Proxy::new(system, "org.freedesktop.login1", path, "org.freedesktop.login1.Session").await?;
    session.get_property::<String>("Id").await
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
    let mut details: HashMap<&str, zbus::zvariant::Value> = HashMap::new();
    details.insert("session-id", session.into());
    let subject = ("unix-session", details);
    let locale = std::env::var("LANG").unwrap_or_else(|_| "C".into());
    let path = zbus::zvariant::ObjectPath::try_from(OBJECT_PATH)?;
    authority.call::<_, _, ()>("RegisterAuthenticationAgent", &(subject, locale, path)).await
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
