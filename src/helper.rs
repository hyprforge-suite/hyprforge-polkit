//! Talking to polkit's authentication helper.
//!
//! An agent does not authenticate anyone. polkitd hands it a cookie; the
//! agent hands the cookie and a username to `polkit-agent-helper-1`,
//! which runs the `polkit-1` PAM stack as root and, if it succeeds, tells
//! polkitd itself. The agent's whole part is relaying what PAM asks and
//! what the person answers — see [`crate::line`] for the lines.
//!
//! Two ways to reach the helper, in the order polkit's own agent library
//! tries them (`polkitagentsession.c`, polkit 127):
//!
//! - **The socket.** `/run/polkit/agent-helper.socket`, where systemd
//!   starts a sandboxed helper per connection (`polkit-agent-helper@`,
//!   `--socket-activated`). The agent writes the username, then the
//!   cookie, a line each. The helper learns who is asking from the
//!   socket's peer credentials, so nothing setuid is involved.
//! - **The setuid helper**, run as `polkit-agent-helper-1 <username>`
//!   with the cookie on its stdin ("so it can't be seen by other
//!   processes"), on systems without the socket.
//!
//! [`Connector`] is the seam. Tests never reach either: the PAM stack on
//! the machine this was written on locks the account after three wrong
//! passwords (pam_faillock), so a test that typed a wrong one at the real
//! helper would be locking out the person running it. `script` (test builds only) is the
//! stand-in they use instead.

use crate::line::{Line, Unknown};
use hyprforge_secret::Secret;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub const SOCKET: &str = "/run/polkit/agent-helper.socket";
pub const SETUID_HELPER: &str = "/usr/lib/polkit-1/polkit-agent-helper-1";

type Reader = Box<dyn AsyncRead + Unpin + Send>;
type Writer = Box<dyn AsyncWrite + Unpin + Send>;

/// One conversation with one helper: one PAM transaction, one try.
pub struct Session {
    lines: BufReader<Reader>,
    answers: Writer,
    /// The setuid helper, when that is what was started — kept so it is
    /// reaped, and killed if the session is dropped mid-conversation.
    _child: Option<tokio::process::Child>,
}

impl Session {
    pub fn new(reader: impl AsyncRead + Unpin + Send + 'static, writer: impl AsyncWrite + Unpin + Send + 'static) -> Session {
        Session { lines: BufReader::new(Box::new(reader)), answers: Box::new(writer), _child: None }
    }

    /// The next thing the helper says; `None` once it has hung up.
    pub async fn next(&mut self) -> Option<Result<Line, Unknown>> {
        let mut raw = String::new();
        match self.lines.read_line(&mut raw).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(Line::parse(&raw)),
        }
    }

    /// Answers the question the helper last asked.
    ///
    /// The bytes go from the [`Secret`] straight to the socket; the
    /// newline is written separately so no second copy of the answer is
    /// ever built. A newline *inside* an answer would end it early and
    /// hand the rest to the next question, so it is refused — a
    /// password field never produces one (CLAUDE.md: Enter is a key, not
    /// text), and this is the backstop if something else ever did.
    pub async fn answer(&mut self, answer: &Secret<String>) -> io::Result<()> {
        if answer.expose().contains('\n') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "an answer cannot contain a newline"));
        }
        self.answers.write_all(answer.expose().as_bytes()).await?;
        self.answers.write_all(b"\n").await?;
        self.answers.flush().await
    }
}

pub type Connecting = Pin<Box<dyn Future<Output = io::Result<Session>> + Send>>;

/// Starts a session with a helper, for `user` and polkit's `cookie`.
pub trait Connector: Send + Sync + 'static {
    fn connect(&self, user: String, cookie: String) -> Connecting;
}

/// The real helper: the socket when it exists, the setuid binary when it
/// does not — polkit's own order.
pub struct Polkit {
    pub socket: PathBuf,
    pub setuid_helper: PathBuf,
}

impl Default for Polkit {
    fn default() -> Polkit {
        Polkit { socket: SOCKET.into(), setuid_helper: SETUID_HELPER.into() }
    }
}

impl Connector for Polkit {
    fn connect(&self, user: String, cookie: String) -> Connecting {
        let socket = self.socket.clone();
        let setuid_helper = self.setuid_helper.clone();
        Box::pin(async move {
            if socket.exists() {
                match via_socket(&socket, &user, &cookie).await {
                    Ok(session) => return Ok(session),
                    // As the agent library does: a socket that is there
                    // but refuses is worth one try of the other way.
                    Err(e) => tracing::warn!("couldn't reach the helper at {}: {e} — trying the setuid helper", socket.display()),
                }
            }
            via_setuid(&setuid_helper, &user, &cookie).await
        })
    }
}

async fn via_socket(socket: &Path, user: &str, cookie: &str) -> io::Result<Session> {
    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(format!("{user}\n{cookie}\n").as_bytes()).await?;
    writer.flush().await?;
    Ok(Session::new(reader, writer))
}

async fn via_setuid(helper: &Path, user: &str, cookie: &str) -> io::Result<Session> {
    let mut child = tokio::process::Command::new(helper)
        .arg(user)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| io::Error::other("the helper has no stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| io::Error::other("the helper has no stdout"))?;
    stdin.write_all(format!("{cookie}\n").as_bytes()).await?;
    stdin.flush().await?;
    let mut session = Session::new(stdout, stdin);
    session._child = Some(child);
    Ok(session)
}

/// A stand-in helper for tests: it speaks the helper's protocol over an
/// in-memory pipe and checks answers against `password` — never PAM.
#[cfg(test)]
pub mod script {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// What a scripted helper does with one session.
    #[derive(Debug, Clone)]
    pub struct Script {
        /// Info lines said before the password is asked for — what
        /// pam_fprintd's "Place your finger" looks like.
        pub info_first: Vec<String>,
        pub password: String,
    }

    /// Connects to [`Script`]s, and keeps what each session was started
    /// with so a test can check the agent sent the right user and cookie.
    #[derive(Clone)]
    pub struct Scripted {
        pub script: Script,
        pub started: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Scripted {
        pub fn new(password: &str) -> Scripted {
            Scripted {
                script: Script { info_first: Vec::new(), password: password.into() },
                started: Arc::default(),
            }
        }
    }

    impl Connector for Scripted {
        fn connect(&self, user: String, cookie: String) -> Connecting {
            self.started.lock().unwrap().push((user, cookie));
            let script = self.script.clone();
            Box::pin(async move {
                let (agent, helper) = tokio::io::duplex(4096);
                tokio::spawn(run(script, helper));
                let (reader, writer) = tokio::io::split(agent);
                Ok(Session::new(reader, writer))
            })
        }
    }

    async fn run(script: Script, helper: tokio::io::DuplexStream) {
        let (reader, mut writer) = tokio::io::split(helper);
        let mut lines = BufReader::new(reader).lines();
        for info in &script.info_first {
            let _ = writer.write_all(format!("PAM_TEXT_INFO {info}\n").as_bytes()).await;
        }
        let _ = writer.write_all(b"PAM_PROMPT_ECHO_OFF Password: \n").await;
        let verdict = match lines.next_line().await {
            Ok(Some(answer)) if answer == script.password => "SUCCESS\n",
            Ok(Some(_)) => "PAM_ERROR_MSG Authentication failure\nFAILURE\n",
            _ => return,
        };
        let _ = writer.write_all(verdict.as_bytes()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::script::Scripted;
    use super::*;

    /// The socket protocol, against a listener standing in for systemd's:
    /// username then cookie, a line each, before anything is read back.
    #[tokio::test]
    async fn the_socket_hears_the_username_then_the_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-helper.socket");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            let user = lines.next_line().await.unwrap().unwrap();
            let cookie = lines.next_line().await.unwrap().unwrap();
            writer.write_all(b"SUCCESS\n").await.unwrap();
            (user, cookie)
        });
        let polkit = Polkit { socket: path, setuid_helper: "/nonexistent".into() };
        let mut session = polkit.connect("alex".into(), "cookie-1".into()).await.unwrap();
        assert_eq!(session.next().await, Some(Ok(Line::Success)));
        assert_eq!(server.await.unwrap(), ("alex".to_string(), "cookie-1".to_string()));
    }

    #[tokio::test]
    async fn a_scripted_helper_asks_and_judges_like_the_real_one() {
        let helper = Scripted::new("right");
        let mut session = helper.connect("alex".into(), "c".into()).await.unwrap();
        assert_eq!(session.next().await, Some(Ok(Line::Prompt { text: "Password: ".into(), echo: false })));
        session.answer(&Secret::new("wrong".to_string())).await.unwrap();
        assert_eq!(session.next().await, Some(Ok(Line::Error("Authentication failure".into()))));
        assert_eq!(session.next().await, Some(Ok(Line::Failure)));
        assert_eq!(session.next().await, None, "and hangs up");
    }

    #[tokio::test]
    async fn an_answer_with_a_newline_in_it_is_never_sent() {
        let helper = Scripted::new("right");
        let mut session = helper.connect("alex".into(), "c".into()).await.unwrap();
        let _ = session.next().await;
        let refused = session.answer(&Secret::new("right\nSUCCESS".to_string())).await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
