//! One authentication, from polkit's request to its end: the helper on
//! one side, the prompt on the other, and this in between.
//!
//! The prompt is told what to show ([`Shown`]) and answers with what the
//! person did ([`Did`]). A wrong password ends that helper's PAM
//! transaction, so a failed try starts a new session with the prompt
//! still open, which is what polkit's own agents do — the person sees
//! "that didn't work" and types again, rather than the request failing
//! and the application asking all over.
//!
//! Nothing here reads, keeps or logs an answer: it goes from the prompt's
//! [`Secret`] to the helper and is dropped (and zeroed) after.

use crate::helper::{Connector, Session};
use crate::line::Line;
use hyprforge_secret::Secret;
use tokio::sync::mpsc;

/// What the prompt should show now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// PAM is asking; `echo` false is a password.
    Ask { text: String, echo: bool },
    /// PAM said something that wants no answer — "Place your finger…".
    Info(String),
    /// PAM said something went wrong.
    Error(String),
    /// An answer was sent and the helper is deciding.
    Checking,
    /// The last try failed; a new one has started.
    TryAgain,
}

/// What the person did at the prompt.
#[derive(Debug)]
pub enum Did {
    Answer(Secret<String>),
    /// Authenticate as someone else from the identities polkit offered.
    SwitchTo(String),
    Cancel,
}

/// How an authentication ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The helper said SUCCESS — it has already told polkitd.
    Authenticated,
    /// The person cancelled, or the prompt went away.
    Cancelled,
    /// The helper could not be reached or said something unintelligible.
    /// Reported to polkit as a failure; the message is for the log, and
    /// never contains anything typed.
    Broken(String),
}

/// Runs one authentication for `user` until it ends.
pub async fn authenticate(
    connector: &dyn Connector,
    mut user: String,
    cookie: &str,
    show: impl Fn(Shown),
    did: &mut mpsc::UnboundedReceiver<Did>,
) -> Ended {
    'session: loop {
        let mut session: Session = match connector.connect(user.clone(), cookie.to_owned()).await {
            Ok(session) => session,
            Err(e) => return Ended::Broken(format!("couldn't start polkit's helper: {e}")),
        };
        loop {
            tokio::select! {
                line = session.next() => match line {
                    Some(Ok(Line::Prompt { text, echo })) => show(Shown::Ask { text, echo }),
                    Some(Ok(Line::Info(text))) => show(Shown::Info(text)),
                    Some(Ok(Line::Error(text))) => show(Shown::Error(text)),
                    Some(Ok(Line::Success)) => return Ended::Authenticated,
                    Some(Ok(Line::Failure)) => {
                        show(Shown::TryAgain);
                        continue 'session;
                    }
                    Some(Err(unknown)) => return Ended::Broken(format!("polkit's helper said something unknown: {:?}", unknown.0)),
                    // Hung up without a verdict: the helper died, or was
                    // stopped. Not a wrong password, so not a retry.
                    None => return Ended::Broken("polkit's helper hung up without an answer".into()),
                },
                action = did.recv() => match action {
                    Some(Did::Answer(answer)) => {
                        if let Err(e) = session.answer(&answer).await {
                            return Ended::Broken(format!("couldn't answer polkit's helper: {e}"));
                        }
                        show(Shown::Checking);
                    }
                    Some(Did::SwitchTo(other)) => {
                        // A new transaction for the other identity; the
                        // old one is dropped mid-question, which the
                        // helper takes as a hang-up.
                        user = other;
                        continue 'session;
                    }
                    Some(Did::Cancel) | None => return Ended::Cancelled,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::script::Scripted;
    use std::sync::{Arc, Mutex};

    fn answer(text: &str) -> Did {
        Did::Answer(Secret::new(text.to_string()))
    }

    /// A person at the prompt: records what is shown, and answers each
    /// question — only once it is asked, as a person would — with the
    /// next of `answers`.
    type Seen = Arc<Mutex<Vec<Shown>>>;

    fn person(answers: &[&str]) -> (Seen, mpsc::UnboundedReceiver<Did>, impl Fn(Shown)) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::unbounded_channel();
        let queue = Arc::new(Mutex::new(answers.iter().map(|a| a.to_string()).collect::<std::collections::VecDeque<_>>()));
        let into = seen.clone();
        let show = move |s: Shown| {
            if matches!(s, Shown::Ask { .. }) {
                if let Some(a) = queue.lock().unwrap().pop_front() {
                    let _ = tx.send(Did::Answer(Secret::new(a)));
                }
            }
            into.lock().unwrap().push(s);
        };
        (seen, rx, show)
    }

    #[tokio::test]
    async fn the_right_password_authenticates() {
        let helper = Scripted::new("right");
        let (seen, mut rx, show) = person(&["right"]);
        let ended = authenticate(&helper, "alex".into(), "cookie", show, &mut rx).await;
        assert_eq!(ended, Ended::Authenticated);
        assert_eq!(seen.lock().unwrap()[0], Shown::Ask { text: "Password: ".into(), echo: false });
        assert_eq!(helper.started.lock().unwrap().as_slice(), [("alex".to_string(), "cookie".to_string())]);
    }

    /// A wrong password says so and starts a fresh try with the prompt
    /// still open; the right one then succeeds.
    #[tokio::test]
    async fn a_wrong_password_is_said_and_another_try_follows() {
        let helper = Scripted::new("right");
        let (seen, mut rx, show) = person(&["wrong", "right"]);
        let ended = authenticate(&helper, "alex".into(), "cookie", show, &mut rx).await;
        assert_eq!(ended, Ended::Authenticated);
        let seen = seen.lock().unwrap();
        assert!(seen.contains(&Shown::Error("Authentication failure".into())), "{seen:?}");
        assert!(seen.contains(&Shown::TryAgain), "{seen:?}");
        assert_eq!(helper.started.lock().unwrap().len(), 2, "one helper session per try");
    }

    #[tokio::test]
    async fn cancelling_ends_it_and_so_does_the_prompt_going_away() {
        let helper = Scripted::new("right");
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Did::Cancel).unwrap();
        assert_eq!(authenticate(&helper, "alex".into(), "c", |_| {}, &mut rx).await, Ended::Cancelled);
        let (tx, mut rx) = mpsc::unbounded_channel::<Did>();
        drop(tx);
        assert_eq!(authenticate(&helper, "alex".into(), "c", |_| {}, &mut rx).await, Ended::Cancelled);
    }

    /// What pam_fprintd says before any password is asked for reaches
    /// the prompt as it arrives.
    #[tokio::test]
    async fn info_before_the_question_is_shown() {
        let mut helper = Scripted::new("right");
        helper.script.info_first = vec!["Place your finger on the fingerprint reader".into()];
        let (seen, mut rx, show) = person(&["right"]);
        authenticate(&helper, "alex".into(), "c", show, &mut rx).await;
        assert_eq!(seen.lock().unwrap()[0], Shown::Info("Place your finger on the fingerprint reader".into()));
    }

    #[tokio::test]
    async fn switching_identity_starts_over_as_the_other_one() {
        // Switch at the first question, then answer the next one.
        let helper = Scripted::new("right");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let show = move |s: Shown| {
            if matches!(s, Shown::Ask { .. }) {
                let n = asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = tx.send(if n == 0 { Did::SwitchTo("root".into()) } else { answer("right") });
            }
        };
        assert_eq!(authenticate(&helper, "alex".into(), "c", show, &mut rx).await, Ended::Authenticated);
        let started: Vec<String> = helper.started.lock().unwrap().iter().map(|(u, _)| u.clone()).collect();
        assert_eq!(started, ["alex", "root"]);
    }
}
